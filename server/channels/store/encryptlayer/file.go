// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package encryptlayer

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/mattermost/mattermost/server/v8/platform/shared/filestore"
)

// Encrypted file layout: header, then the plaintext cut into 64 KiB chunks, each sealed on its own so
// that a reader can start in the middle (video, large PDF).
//
//	header   = magic(8) | month key id(7) | salt(16)
//	file key = HKDF-SHA256(month key, salt, "chaeum file|" + channel id from the path)
//	chunk    = AES-256-GCM(file key, nonce = chunk index, aad = header)
//
// Every file has its own key, so the month key that also protects posts never sees a file nonce, and a
// file copied under another channel's path does not open.
const (
	fileMagic   = "CHAEUMF2"
	fileSalt    = 16
	fileHeader  = len(fileMagic) + 7 + fileSalt
	fileChunk   = 64 * 1024
	sealedChunk = fileChunk + 16
	pathKeyID   = "path"
)

// Attachments, their previews and thumbnails. Everything else the file store holds (plugins, profile
// pictures, emoji, imports, exports) is read by code that does not go through this wrapper and is left alone.
var attachmentPath = regexp.MustCompile(`^(\d{8}/|[a-z]+/)?teams/[^/]+/channels/.+/[^/]+$`)

var pathChannel = regexp.MustCompile(`teams/[^/]+/channels/([^/]+)/`)

func channelOf(p string) string {
	if m := pathChannel.FindStringSubmatch(p); m != nil {
		return m[1]
	}
	return ""
}

var active *EncryptLayer

// WrapFileBackend returns a file backend that encrypts attachments when storage encryption is on.
func WrapFileBackend(b filestore.FileBackend) filestore.FileBackend {
	if active == nil || b == nil {
		return b
	}
	fb := &fileBackend{FileBackend: b, l: active}
	startMigration(fb)
	return fb
}

type fileBackend struct {
	filestore.FileBackend
	l *EncryptLayer
}

// diskPath hides the file name: the last path element is replaced by a keyed hash of the whole path.
func (l *EncryptLayer) diskPath(p string) (string, bool, error) {
	if !attachmentPath.MatchString(p) {
		return p, false, nil
	}
	key, err := l.keys.ensure(pathKeyID)
	if err != nil {
		return "", false, err
	}
	dir, _ := path.Split(p)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(p))
	return dir + hex.EncodeToString(m.Sum(nil)[:16]), true, nil
}

// existing returns where a file that is being read lives: under its hidden name, or under its plain
// name when it was stored before encryption was turned on.
func (b *fileBackend) existing(p string) (string, error) {
	dp, ours, err := b.l.diskPath(p)
	if err != nil || !ours {
		return p, err
	}
	if ok, err2 := b.FileBackend.FileExists(dp); err2 != nil || ok {
		return dp, err2
	}
	if ok, _ := b.FileBackend.FileExists(p); ok {
		return p, nil
	}
	return dp, nil
}

type fileKey struct {
	header []byte
	gcm    cipher.AEAD
}

func deriveFileKey(monthKey, header []byte, p string) (*fileKey, error) {
	key, err := hkdf.Key(sha256.New, monthKey, header[len(fileMagic)+7:], "chaeum file|"+channelOf(p), 32)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &fileKey{header: header, gcm: gcm}, nil
}

// newFileKey makes the header and key for a file that will be stored for path p.
func (l *EncryptLayer) newFileKey(p string) (*fileKey, error) {
	id, key, err := l.keys.Current()
	if err != nil {
		return nil, err
	}
	if len(id) != 7 {
		return nil, errors.Errorf("encryptlayer: unexpected key id %q", id)
	}
	h := make([]byte, 0, fileHeader)
	h = append(h, fileMagic...)
	h = append(h, id...)
	h = h[:fileHeader]
	if _, err = rand.Read(h[len(fileMagic)+7:]); err != nil {
		return nil, err
	}
	return deriveFileKey(key, h, p)
}

// readFileKey reads the header at the start of r, a file stored for path p. ok is false when the file
// is not one of ours.
func (l *EncryptLayer) readFileKey(r io.Reader, p string) (fk *fileKey, ok bool, err error) {
	h := make([]byte, fileHeader)
	if _, err = io.ReadFull(r, h); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, false, nil
		}
		return nil, false, err
	}
	if string(h[:len(fileMagic)]) != fileMagic {
		return nil, false, nil
	}
	key, known, err := l.keys.Get(string(h[len(fileMagic) : len(fileMagic)+7]))
	if err != nil {
		return nil, false, err
	}
	if !known {
		return nil, false, nil
	}
	fk, err = deriveFileKey(key, h, p)
	return fk, err == nil, err
}

func (fk *fileKey) nonce(index int64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], uint64(index))
	return n
}

func plainSize(stored int64) int64 {
	n := stored - int64(fileHeader)
	if n <= 0 {
		return 0
	}
	size := n / sealedChunk * fileChunk
	if rem := n % sealedChunk; rem > 16 {
		size += rem - 16
	}
	return size
}

// sealer turns a plaintext stream into sealed chunks, starting at chunk index.
type sealer struct {
	src   io.Reader
	fk    *fileKey
	index int64
	out   bytes.Buffer
	plain int64
	done  bool
}

func (s *sealer) Read(p []byte) (int, error) {
	for s.out.Len() == 0 {
		if s.done {
			return 0, io.EOF
		}
		buf := make([]byte, fileChunk)
		n, err := io.ReadFull(s.src, buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			s.done = true
		} else if err != nil {
			return 0, err
		}
		if n > 0 {
			s.out.Write(s.fk.gcm.Seal(nil, s.fk.nonce(s.index), buf[:n], s.fk.header))
			s.index++
			s.plain += int64(n)
		}
	}
	return s.out.Read(p)
}

func (b *fileBackend) WriteFile(fr io.Reader, p string) (int64, error) {
	dp, ours, err := b.l.diskPath(p)
	if err != nil {
		return 0, err
	}
	if !ours {
		return b.FileBackend.WriteFile(fr, p)
	}
	return b.writeSealed(fr, p, dp)
}

// writeSealed stores fr at dp, sealed for path p.
func (b *fileBackend) writeSealed(fr io.Reader, p, dp string) (int64, error) {
	fk, err := b.l.newFileKey(p)
	if err != nil {
		return 0, err
	}
	s := &sealer{src: fr, fk: fk}
	if _, err = b.FileBackend.WriteFile(io.MultiReader(bytes.NewReader(fk.header), s), dp); err != nil {
		return 0, err
	}
	return s.plain, nil
}

// AppendFile continues the chunk sequence when the stored file ends on a chunk boundary. Otherwise the
// last chunk would have to be sealed again with the same nonce, so the file is written anew instead.
func (b *fileBackend) AppendFile(fr io.Reader, p string) (int64, error) {
	dp, ours, err := b.l.diskPath(p)
	if err != nil {
		return 0, err
	}
	if !ours {
		return b.FileBackend.AppendFile(fr, p)
	}
	if ok, err2 := b.FileBackend.FileExists(dp); err2 != nil {
		return 0, err2
	} else if !ok {
		// Only a file stored before encryption was turned on continues as plaintext.
		if old, _ := b.FileBackend.FileExists(p); old {
			return b.FileBackend.AppendFile(fr, p)
		}
		return b.writeSealed(fr, p, dp)
	}
	r, err := b.FileBackend.Reader(dp)
	if err != nil {
		return 0, err
	}
	fk, sealed, err := b.l.readFileKey(r, p)
	if err != nil || !sealed {
		r.Close()
		if err != nil {
			return 0, err
		}
		return 0, errors.New("encryptlayer: stored file has no readable header, not appending to it")
	}
	stored, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		r.Close()
		return 0, err
	}
	size := plainSize(stored)
	if size%fileChunk == 0 {
		r.Close()
		s := &sealer{src: fr, fk: fk, index: size / fileChunk}
		if _, err = b.FileBackend.AppendFile(s, dp); err != nil {
			return 0, err
		}
		return s.plain, nil
	}
	old := &opener{r: r, fk: fk, size: size, cached: -1}
	defer old.Close()
	counted := &countingReader{r: fr}
	tmp := dp + ".rewrite"
	if _, err = b.writeSealed(io.MultiReader(old, counted), p, tmp); err != nil {
		_ = b.FileBackend.RemoveFile(tmp)
		return 0, err
	}
	if err = b.FileBackend.MoveFile(tmp, dp); err != nil {
		return 0, err
	}
	return counted.n, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// opener reads a sealed file as plaintext, with seeking.
type opener struct {
	r      filestore.ReadCloseSeeker
	fk     *fileKey
	size   int64
	pos    int64
	cached int64
	chunk  []byte
}

func (o *opener) Read(p []byte) (int, error) {
	if o.pos >= o.size {
		return 0, io.EOF
	}
	index := o.pos / fileChunk
	if o.cached != index {
		if _, err := o.r.Seek(int64(fileHeader)+index*sealedChunk, io.SeekStart); err != nil {
			return 0, err
		}
		buf := make([]byte, sealedChunk)
		n, err := io.ReadFull(o.r, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			return 0, err
		}
		plain, err := o.fk.gcm.Open(buf[:0], o.fk.nonce(index), buf[:n], o.fk.header)
		if err != nil {
			return 0, errors.New("encryptlayer: stored file does not authenticate")
		}
		o.chunk, o.cached = plain, index
	}
	off := int(o.pos - index*fileChunk)
	if off >= len(o.chunk) {
		return 0, io.EOF
	}
	n := copy(p, o.chunk[off:])
	o.pos += int64(n)
	return n, nil
}

func (o *opener) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekCurrent:
		offset += o.pos
	case io.SeekEnd:
		offset += o.size
	}
	if offset < 0 {
		return 0, errors.New("encryptlayer: negative seek position")
	}
	o.pos = offset
	return offset, nil
}

func (o *opener) Close() error { return o.r.Close() }

func (b *fileBackend) Reader(p string) (filestore.ReadCloseSeeker, error) {
	dp, err := b.existing(p)
	if err != nil {
		return nil, err
	}
	r, err := b.FileBackend.Reader(dp)
	if err != nil {
		return nil, err
	}
	fk, sealed, err := b.l.readFileKey(r, p)
	if err == nil && sealed {
		var stored int64
		if stored, err = r.Seek(0, io.SeekEnd); err == nil {
			return &opener{r: r, fk: fk, size: plainSize(stored), cached: -1}, nil
		}
	}
	if err == nil {
		_, err = r.Seek(0, io.SeekStart)
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (b *fileBackend) ReadFile(p string) ([]byte, error) {
	r, err := b.Reader(p)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func (b *fileBackend) FileSize(p string) (int64, error) {
	dp, err := b.existing(p)
	if err != nil {
		return 0, err
	}
	stored, err := b.FileBackend.FileSize(dp)
	if err != nil || dp == p {
		return stored, err
	}
	r, err := b.FileBackend.Reader(dp)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	if _, sealed, err2 := b.l.readFileKey(r, p); err2 != nil || !sealed {
		return stored, err2
	}
	return plainSize(stored), nil
}

func (b *fileBackend) FileExists(p string) (bool, error) {
	dp, err := b.existing(p)
	if err != nil {
		return false, err
	}
	return b.FileBackend.FileExists(dp)
}

func (b *fileBackend) FileModTime(p string) (time.Time, error) {
	dp, err := b.existing(p)
	if err != nil {
		return time.Time{}, err
	}
	return b.FileBackend.FileModTime(dp)
}

func (b *fileBackend) RemoveFile(p string) error {
	dp, err := b.existing(p)
	if err != nil {
		return err
	}
	return b.FileBackend.RemoveFile(dp)
}

// The file key is bound to the channel in the path, so a file that changes channel is sealed again.
func (b *fileBackend) transfer(oldPath, newPath string, move bool) error {
	from, err := b.existing(oldPath)
	if err != nil {
		return err
	}
	to, ours, err := b.l.diskPath(newPath)
	if err != nil {
		return err
	}
	if ours {
		// Only a sealed file that stays in its channel can be moved as it is. Anything else (another
		// channel, a file from outside the attachment tree, one stored before encryption) is sealed for
		// its new path.
		asIs := false
		if from != oldPath && channelOf(oldPath) == channelOf(newPath) {
			if r, err2 := b.FileBackend.Reader(from); err2 == nil {
				_, asIs, _ = b.l.readFileKey(r, oldPath)
				r.Close()
			}
		}
		if !asIs {
			r, err2 := b.Reader(oldPath)
			if err2 != nil {
				return err2
			}
			_, err2 = b.writeSealed(r, newPath, to)
			r.Close()
			if err2 != nil || !move {
				return err2
			}
			return b.FileBackend.RemoveFile(from)
		}
	}
	if move {
		return b.FileBackend.MoveFile(from, to)
	}
	return b.FileBackend.CopyFile(from, to)
}

func (b *fileBackend) CopyFile(oldPath, newPath string) error {
	return b.transfer(oldPath, newPath, false)
}

func (b *fileBackend) MoveFile(oldPath, newPath string) error {
	return b.transfer(oldPath, newPath, true)
}

// sealPath and openPath hide the file name inside a path column (FileInfo.Path and friends).
func (l *EncryptLayer) sealPath(kind, scope, p string) (string, error) {
	if !attachmentPath.MatchString(p) {
		return p, nil
	}
	dir, name := path.Split(p)
	if strings.HasPrefix(name, prefix) || strings.Contains(dir, "/"+prefix) {
		return p, nil
	}
	sealed, err := l.seal(kind, "path", scope, name)
	if err != nil {
		return "", err
	}
	return dir + sealed, nil
}

func (l *EncryptLayer) openPath(kind, scope, p string) (string, error) {
	i := strings.Index(p, "/"+prefix)
	if i < 0 {
		return p, nil
	}
	name, err := l.open(kind, "path", scope, p[i+1:])
	if err != nil {
		return "", err
	}
	return p[:i+1] + name, nil
}

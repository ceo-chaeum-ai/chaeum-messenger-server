// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

// Package encryptlayer is a store layer that encrypts message content right before it reaches
// the SQL store and decrypts it right after it is read back. Everything above this layer
// (permissions, mentions, notifications, plugins, caches, search indexing) sees plaintext.
//
// Stored form: enc:v1:<month key id>:<base64(nonce|ciphertext)>. Values without that prefix are
// treated as plaintext, so rows written before encryption was enabled keep working.
package encryptlayer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
)

const (
	prefix          = "enc:v1:"
	attachmentsProp = "attachments"
	// Sealed attachments are stored under their own key: the SQL store rewrites "attachments" from its
	// parsed form on every save (Post.GenerateActionIds), which would drop a ciphertext string.
	sealedAttProp = "chaeum_attachments"
)

var bytePrefix = []byte(prefix)

func aad(kind, field, scope string) []byte {
	return []byte(kind + "|" + field + "|" + scope)
}

func (l *EncryptLayer) seal(kind, field, scope, plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	out, err := l.sealBytes(kind, field, scope, []byte(plain), true)
	return string(out), err
}

// sealBytes returns prefix + key id + ":" + payload. The payload is base64 when text is true.
func (l *EncryptLayer) sealBytes(kind, field, scope string, plain []byte, text bool) ([]byte, error) {
	id, key, err := l.keys.Current()
	if err != nil {
		return nil, errors.Wrap(err, "encryptlayer: no current key")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, plain, aad(kind, field, scope))
	head := prefix + id + ":"
	if text {
		return []byte(head + base64.RawStdEncoding.EncodeToString(ct)), nil
	}
	return append([]byte(head), ct...), nil
}

func (l *EncryptLayer) open(kind, field, scope, s string) (string, error) {
	if !strings.HasPrefix(s, prefix) {
		return s, nil
	}
	out, err := l.openBytes(kind, field, scope, []byte(s), true)
	return string(out), err
}

// openBytes decrypts a stored value. A value that is not ours (no prefix, malformed, unknown key id,
// authentication failure) is returned unchanged: a user can type text that merely looks like our format,
// and that must never make a channel unreadable. Only a known key that cannot be unwrapped is an error.
func (l *EncryptLayer) openBytes(kind, field, scope string, s []byte, text bool) ([]byte, error) {
	if !bytes.HasPrefix(s, bytePrefix) {
		return s, nil
	}
	rest := s[len(bytePrefix):]
	i := bytes.IndexByte(rest, ':')
	if i <= 0 || i > 32 {
		return s, nil
	}
	id, payload := string(rest[:i]), rest[i+1:]
	if text {
		dec := make([]byte, base64.RawStdEncoding.DecodedLen(len(payload)))
		n, err := base64.RawStdEncoding.Decode(dec, payload)
		if err != nil {
			return s, nil
		}
		payload = dec[:n]
	}
	key, known, err := l.keys.Get(id)
	if !known {
		return s, nil
	}
	if err != nil {
		return nil, errors.Wrapf(err, "encryptlayer: key %s unavailable", id)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(payload) < gcm.NonceSize()+gcm.Overhead() {
		return s, nil
	}
	plain, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], aad(kind, field, scope))
	if err != nil {
		noteAuthFailure(kind, field, scope)
		return s, nil
	}
	return plain, nil
}

// A value under a key we issued that does not authenticate was changed in the database, or reached us
// with another channel id than it was stored with. It is still returned as stored; this leaves a trace.
var (
	authFailures    atomic.Int64
	authFailureLast atomic.Int64
	authLog         mlog.LoggerIFace
)

// AuthFailures is the number of stored values that failed authentication since the server started.
func AuthFailures() int64 { return authFailures.Load() }

func noteAuthFailure(kind, field, scope string) {
	n := authFailures.Add(1)
	now := time.Now().Unix()
	last := authFailureLast.Load()
	if authLog != nil && now-last >= 60 && authFailureLast.CompareAndSwap(last, now) {
		authLog.Warn("encryptlayer: stored value does not authenticate", mlog.String("kind", kind), mlog.String("field", field), mlog.String("scope", scope), mlog.Int("total", int(n)))
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// saved remembers the plaintext of every argument that was encrypted in place for a store call,
// so it can be put back afterwards. The SQL store mutates and returns the pointers it is given
// (PreSave fills Id, CreateAt, ...), so the layer works in place instead of on copies.
type saved struct {
	restore []func()
	seen    map[any]struct{}
}

func (sv *saved) add(p any, f func()) {
	sv.restore = append(sv.restore, f)
	sv.seen[p] = struct{}{}
}

func (sv *saved) done() {
	if sv == nil {
		return
	}
	for _, f := range sv.restore {
		f()
	}
	sv.restore = nil
}

// encArgs encrypts the content of every argument in place. Call done() on the result after the store call.
func (l *EncryptLayer) encArgs(args ...any) (*saved, error) {
	sv := &saved{seen: map[any]struct{}{}}
	for _, a := range args {
		if err := l.encAny(sv, a); err != nil {
			sv.done()
			return nil, err
		}
	}
	return sv, nil
}

func (l *EncryptLayer) encAny(sv *saved, a any) error {
	switch v := a.(type) {
	case *model.Post:
		return l.encPost(sv, v)
	case []*model.Post:
		for _, p := range v {
			if err := l.encPost(sv, p); err != nil {
				return err
			}
		}
	case *model.Draft:
		return l.encDraft(sv, v)
	case []*model.Draft:
		for _, d := range v {
			if err := l.encDraft(sv, d); err != nil {
				return err
			}
		}
	case *model.ScheduledPost:
		if v != nil {
			return l.encDraft(sv, &v.Draft)
		}
	case []*model.ScheduledPost:
		for _, p := range v {
			if p != nil {
				if err := l.encDraft(sv, &p.Draft); err != nil {
					return err
				}
			}
		}
	case *model.UploadSession:
		return l.encUpload(sv, v)
	case *model.FileInfo:
		return l.encFile(sv, v)
	case []*model.FileInfo:
		for _, f := range v {
			if err := l.encFile(sv, f); err != nil {
				return err
			}
		}
	case *model.ChannelBookmarkWithFileInfo:
		if v != nil {
			return l.encFile(sv, v.FileInfo)
		}
	}
	return nil
}

func (l *EncryptLayer) sealAttachments(kind, scope string, att any) (any, error) {
	if att == nil {
		return nil, nil
	}
	if s, ok := att.(string); ok && strings.HasPrefix(s, prefix) {
		return att, nil
	}
	raw, err := json.Marshal(att)
	if err != nil {
		return nil, err
	}
	return l.seal(kind, attachmentsProp, scope, string(raw))
}

func (l *EncryptLayer) openAttachments(kind, scope string, att any) (any, bool, error) {
	s, ok := att.(string)
	if !ok || !strings.HasPrefix(s, prefix) {
		return att, false, nil
	}
	plain, err := l.open(kind, attachmentsProp, scope, s)
	if err != nil || plain == s {
		return att, false, err
	}
	var out any
	if err = json.Unmarshal([]byte(plain), &out); err != nil {
		return att, false, nil
	}
	return out, true, nil
}

func (l *EncryptLayer) encPost(sv *saved, p *model.Post) error {
	if p == nil {
		return nil
	}
	if _, dup := sv.seen[p]; dup {
		return nil
	}
	// The SQL store generates action ids for message attachments in PreCommit; it cannot once they are encrypted.
	p.GenerateActionIds()
	msg, tags := p.Message, p.Hashtags
	att, hasAtt := p.GetProps()[attachmentsProp]
	sealed, err := l.seal("post", "message", p.ChannelId, msg)
	if err != nil {
		return err
	}
	var sealedAtt any
	if hasAtt {
		if sealedAtt, err = l.sealAttachments("post", p.ChannelId, att); err != nil {
			return err
		}
	}
	p.Message, p.Hashtags = sealed, ""
	if hasAtt {
		p.DelProp(attachmentsProp)
		p.AddProp(sealedAttProp, sealedAtt)
	}
	sv.add(p, func() {
		p.Message, p.Hashtags = msg, tags
		if hasAtt {
			p.DelProp(sealedAttProp)
			p.AddProp(attachmentsProp, att)
		}
	})
	return nil
}

func draftScope(d *model.Draft) string { return d.UserId + "|" + d.ChannelId }

func (l *EncryptLayer) encDraft(sv *saved, d *model.Draft) error {
	if d == nil {
		return nil
	}
	if _, dup := sv.seen[d]; dup {
		return nil
	}
	msg := d.Message
	att, hasAtt := d.GetProps()[attachmentsProp]
	sealed, err := l.seal("draft", "message", draftScope(d), msg)
	if err != nil {
		return err
	}
	var sealedAtt any
	if hasAtt {
		if sealedAtt, err = l.sealAttachments("draft", draftScope(d), att); err != nil {
			return err
		}
	}
	d.Message = sealed
	if hasAtt {
		delete(d.GetProps(), attachmentsProp)
		d.GetProps()[sealedAttProp] = sealedAtt
	}
	sv.add(d, func() {
		d.Message = msg
		if hasAtt {
			delete(d.GetProps(), sealedAttProp)
			d.GetProps()[attachmentsProp] = att
		}
	})
	return nil
}

func (l *EncryptLayer) encFile(sv *saved, f *model.FileInfo) error {
	if f == nil {
		return nil
	}
	if _, dup := sv.seen[f]; dup {
		return nil
	}
	if f.Id == "" {
		f.Id = model.NewId() // the id binds the ciphertext to this row; PreSave would assign one anyway
	}
	name, content, mini := f.Name, f.Content, f.MiniPreview
	sName, err := l.seal("file", "name", f.Id, name)
	if err != nil {
		return err
	}
	sContent, err := l.seal("file", "content", f.Id, content)
	if err != nil {
		return err
	}
	sMini := mini
	if mini != nil && len(*mini) > 0 && !bytes.HasPrefix(*mini, bytePrefix) {
		b, err2 := l.sealBytes("file", "minipreview", f.Id, *mini, false)
		if err2 != nil {
			return err2
		}
		sMini = &b
	}
	paths := [3]string{f.Path, f.ThumbnailPath, f.PreviewPath}
	var sPaths [3]string
	for i, p := range paths {
		if sPaths[i], err = l.sealPath("file", f.Id, p); err != nil {
			return err
		}
	}
	f.Name, f.Content, f.MiniPreview = sName, sContent, sMini
	f.Path, f.ThumbnailPath, f.PreviewPath = sPaths[0], sPaths[1], sPaths[2]
	sv.add(f, func() {
		f.Name, f.Content, f.MiniPreview = name, content, mini
		f.Path, f.ThumbnailPath, f.PreviewPath = paths[0], paths[1], paths[2]
	})
	return nil
}

func (l *EncryptLayer) encUpload(sv *saved, us *model.UploadSession) error {
	if us == nil {
		return nil
	}
	if _, dup := sv.seen[us]; dup {
		return nil
	}
	name, p := us.Filename, us.Path
	sName, err := l.seal("upload", "filename", us.Id, name)
	if err != nil {
		return err
	}
	sPath, err := l.sealPath("upload", us.Id, p)
	if err != nil {
		return err
	}
	us.Filename, us.Path = sName, sPath
	sv.add(us, func() { us.Filename, us.Path = name, p })
	return nil
}

func (l *EncryptLayer) decUpload(sv *saved, us *model.UploadSession) error {
	if us == nil {
		return nil
	}
	if sv != nil {
		if _, was := sv.seen[us]; was {
			return nil
		}
	}
	name, err := l.open("upload", "filename", us.Id, us.Filename)
	if err != nil {
		return err
	}
	p, err := l.openPath("upload", us.Id, us.Path)
	if err != nil {
		return err
	}
	us.Filename, us.Path = name, p
	return nil
}

// decResults decrypts everything a store call returned, in place. Pointers that were arguments of the
// same call were already restored by done() and are skipped.
func (l *EncryptLayer) decResults(sv *saved, results ...any) error {
	for _, r := range results {
		if err := l.decAny(sv, r); err != nil {
			return err
		}
	}
	return nil
}

func (l *EncryptLayer) decAny(sv *saved, r any) error {
	switch v := r.(type) {
	case *model.UploadSession:
		return l.decUpload(sv, v)
	case []*model.UploadSession:
		for _, us := range v {
			if err := l.decUpload(sv, us); err != nil {
				return err
			}
		}
	case *model.Post:
		return l.decPost(sv, v)
	case []*model.Post:
		for _, p := range v {
			if err := l.decPost(sv, p); err != nil {
				return err
			}
		}
	case *model.PostList:
		if v != nil {
			for _, p := range v.Posts {
				if err := l.decPost(sv, p); err != nil {
					return err
				}
			}
		}
	case *model.PostSearchResults:
		if v != nil {
			return l.decAny(sv, v.PostList)
		}
	case *model.ThreadResponse:
		if v != nil {
			return l.decPost(sv, v.Post)
		}
	case []*model.ThreadResponse:
		for _, t := range v {
			if t != nil {
				if err := l.decPost(sv, t.Post); err != nil {
					return err
				}
			}
		}
	case *model.Threads:
		if v != nil {
			return l.decAny(sv, v.Threads)
		}
	case []*model.PostForIndexing:
		for _, p := range v {
			if p != nil {
				if err := l.decPost(sv, &p.Post); err != nil {
					return err
				}
			}
		}
	case []*model.PostForExport:
		for _, p := range v {
			if p != nil {
				if err := l.decPost(sv, &p.Post); err != nil {
					return err
				}
			}
		}
	case []*model.ReplyForExport:
		for _, p := range v {
			if p != nil {
				if err := l.decPost(sv, &p.Post); err != nil {
					return err
				}
			}
		}
	case []*model.DirectPostForExport:
		for _, p := range v {
			if p != nil {
				if err := l.decPost(sv, &p.Post); err != nil {
					return err
				}
			}
		}
	case *model.Draft:
		return l.decDraft(sv, v)
	case []*model.Draft:
		for _, d := range v {
			if err := l.decDraft(sv, d); err != nil {
				return err
			}
		}
	case *model.ScheduledPost:
		if v != nil {
			return l.decDraft(sv, &v.Draft)
		}
	case []*model.ScheduledPost:
		for _, p := range v {
			if p != nil {
				if err := l.decDraft(sv, &p.Draft); err != nil {
					return err
				}
			}
		}
	case *model.FileInfo:
		return l.decFile(sv, v)
	case []*model.FileInfo:
		for _, f := range v {
			if err := l.decFile(sv, f); err != nil {
				return err
			}
		}
	case *model.FileInfoList:
		if v != nil {
			for _, f := range v.FileInfos {
				if err := l.decFile(sv, f); err != nil {
					return err
				}
			}
		}
	case []*model.FileForIndexing:
		for _, f := range v {
			if f != nil {
				if err := l.decFile(sv, &f.FileInfo); err != nil {
					return err
				}
			}
		}
	case *model.ChannelBookmarkWithFileInfo:
		if v != nil {
			return l.decFile(sv, v.FileInfo)
		}
	case []*model.ChannelBookmarkWithFileInfo:
		for _, b := range v {
			if b != nil {
				if err := l.decFile(sv, b.FileInfo); err != nil {
					return err
				}
			}
		}
	// []*model.CompliancePost (enterprise compliance export) carries no channel id, so its message
	// cannot be authenticated and stays as stored.
	case []*model.MessageExport:
		for _, p := range v {
			if p != nil && p.PostMessage != nil && p.ChannelId != nil {
				m, err := l.open("post", "message", *p.ChannelId, *p.PostMessage)
				if err != nil {
					return err
				}
				p.PostMessage = &m
			}
		}
	}
	return nil
}

func (l *EncryptLayer) decPost(sv *saved, p *model.Post) error {
	if p == nil {
		return nil
	}
	if sv != nil {
		if _, was := sv.seen[p]; was {
			return nil
		}
	}
	wasEnc := strings.HasPrefix(p.Message, prefix)
	msg, err := l.open("post", "message", p.ChannelId, p.Message)
	if err != nil {
		return err
	}
	p.Message = msg
	if att, ok := p.GetProps()[sealedAttProp]; ok {
		out, changed, err2 := l.openAttachments("post", p.ChannelId, att)
		if err2 != nil {
			return err2
		}
		if changed {
			p.DelProp(sealedAttProp)
			p.AddProp(attachmentsProp, out)
		}
	}
	// Hashtags are derived from the message and are not stored for encrypted rows.
	if wasEnc && p.Hashtags == "" && strings.Contains(msg, "#") {
		p.Hashtags, _ = model.ParseHashtags(msg)
	}
	return nil
}

func (l *EncryptLayer) decDraft(sv *saved, d *model.Draft) error {
	if d == nil {
		return nil
	}
	if sv != nil {
		if _, was := sv.seen[d]; was {
			return nil
		}
	}
	msg, err := l.open("draft", "message", draftScope(d), d.Message)
	if err != nil {
		return err
	}
	d.Message = msg
	if att, ok := d.GetProps()[sealedAttProp]; ok {
		out, changed, err2 := l.openAttachments("draft", draftScope(d), att)
		if err2 != nil {
			return err2
		}
		if changed {
			delete(d.GetProps(), sealedAttProp)
			d.GetProps()[attachmentsProp] = out
		}
	}
	return nil
}

func (l *EncryptLayer) decFile(sv *saved, f *model.FileInfo) error {
	if f == nil {
		return nil
	}
	if sv != nil {
		if _, was := sv.seen[f]; was {
			return nil
		}
	}
	name, err := l.open("file", "name", f.Id, f.Name)
	if err != nil {
		return err
	}
	content, err := l.open("file", "content", f.Id, f.Content)
	if err != nil {
		return err
	}
	f.Name, f.Content = name, content
	for _, p := range []*string{&f.Path, &f.ThumbnailPath, &f.PreviewPath} {
		if *p, err = l.openPath("file", f.Id, *p); err != nil {
			return err
		}
	}
	if f.MiniPreview != nil && bytes.HasPrefix(*f.MiniPreview, bytePrefix) {
		b, err2 := l.openBytes("file", "minipreview", f.Id, *f.MiniPreview, false)
		if err2 != nil {
			return err2
		}
		f.MiniPreview = &b
	}
	return nil
}

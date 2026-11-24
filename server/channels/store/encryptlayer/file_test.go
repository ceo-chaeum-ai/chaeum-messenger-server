// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package encryptlayer

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/v8/platform/shared/filestore"
)

func testBackend(t *testing.T) (filestore.FileBackend, filestore.FileBackend, string) {
	dir := t.TempDir()
	raw, err := filestore.NewFileBackend(filestore.FileBackendSettings{DriverName: "local", Directory: dir})
	require.NoError(t, err)
	return &fileBackend{FileBackend: raw, l: testLayer(t)}, raw, dir
}

const testPath = "20261124/teams/noteam/channels/c1/users/u1/f1/보고서.hwpx"

func TestFileRoundTripAndSeek(t *testing.T) {
	b, raw, dir := testBackend(t)
	for _, size := range []int{0, 1, fileChunk - 1, fileChunk, fileChunk + 1, 3*fileChunk + 777} {
		data := make([]byte, size)
		_, _ = rand.Read(data)
		n, err := b.WriteFile(bytes.NewReader(data), testPath)
		require.NoError(t, err)
		require.EqualValues(t, size, n)

		got, err := b.ReadFile(testPath)
		require.NoError(t, err)
		require.True(t, bytes.Equal(data, got), "size %d", size)
		fs, err := b.FileSize(testPath)
		require.NoError(t, err)
		require.EqualValues(t, size, fs)

		if size > 2*fileChunk {
			r, err := b.Reader(testPath)
			require.NoError(t, err)
			_, err = r.Seek(int64(fileChunk-5), io.SeekStart)
			require.NoError(t, err)
			part := make([]byte, 100)
			_, err = io.ReadFull(r, part)
			require.NoError(t, err)
			require.Equal(t, data[fileChunk-5:fileChunk+95], part)
			end, err := r.Seek(-3, io.SeekEnd)
			require.NoError(t, err)
			require.EqualValues(t, size-3, end)
			tail, _ := io.ReadAll(r)
			require.Equal(t, data[size-3:], tail)
			require.NoError(t, r.Close())
		}
	}
	// On disk: no plain name, no plain bytes at the plain path.
	ok, _ := raw.FileExists(testPath)
	require.False(t, ok)
	names, _ := os.ReadDir(filepath.Join(dir, filepath.Dir(testPath)))
	require.Len(t, names, 1)
	require.NotContains(t, names[0].Name(), "보고서")
	ok, err := b.FileExists(testPath)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, b.RemoveFile(testPath))
	ok, _ = b.FileExists(testPath)
	require.False(t, ok)
}

func TestFileAppend(t *testing.T) {
	b, _, _ := testBackend(t)
	var want []byte
	first := true
	for _, size := range []int{fileChunk, 2 * fileChunk, 10, fileChunk + 5, 1} {
		part := make([]byte, size)
		_, _ = rand.Read(part)
		want = append(want, part...)
		var n int64
		var err error
		if first {
			n, err = b.WriteFile(bytes.NewReader(part), testPath)
			first = false
		} else {
			n, err = b.AppendFile(bytes.NewReader(part), testPath)
		}
		require.NoError(t, err)
		require.EqualValues(t, size, n)
		got, err := b.ReadFile(testPath)
		require.NoError(t, err)
		require.True(t, bytes.Equal(want, got), "after part of %d", size)
	}
}

func TestFilePlainPassThrough(t *testing.T) {
	b, raw, _ := testBackend(t)
	// Not an attachment path: stored as it is.
	_, err := b.WriteFile(bytes.NewReader([]byte("plugin bundle")), "plugins/x.tar.gz")
	require.NoError(t, err)
	got, _ := raw.ReadFile("plugins/x.tar.gz")
	require.Equal(t, "plugin bundle", string(got))
	// Attachment stored before encryption was on: still readable.
	_, err = raw.WriteFile(bytes.NewReader([]byte("old attachment")), testPath)
	require.NoError(t, err)
	got, err = b.ReadFile(testPath)
	require.NoError(t, err)
	require.Equal(t, "old attachment", string(got))
	size, err := b.FileSize(testPath)
	require.NoError(t, err)
	require.EqualValues(t, 14, size)
}

func TestPathColumns(t *testing.T) {
	l := testLayer(t)
	f := &model.FileInfo{Id: "f1", Name: "보고서.hwpx", Path: testPath, PreviewPath: "20261124/teams/noteam/channels/c1/users/u1/f1/보고서_preview.jpg"}
	sv, err := l.encArgs(f)
	require.NoError(t, err)
	require.NotContains(t, f.Path, "보고서")
	require.NotContains(t, f.PreviewPath, "보고서")
	require.Empty(t, f.ThumbnailPath)
	stored := *f
	sv.done()
	require.Equal(t, testPath, f.Path)
	require.NoError(t, l.decResults(nil, &stored))
	require.Equal(t, testPath, stored.Path)
	require.Equal(t, f.PreviewPath, stored.PreviewPath)

	us := &model.UploadSession{Id: "s1", Filename: "보고서.hwpx", Path: testPath}
	sv, err = l.encArgs(us)
	require.NoError(t, err)
	require.NotContains(t, us.Filename+us.Path, "보고서")
	su := *us
	sv.done()
	require.NoError(t, l.decResults(nil, &su))
	require.Equal(t, "보고서.hwpx", su.Filename)
	require.Equal(t, testPath, su.Path)
}

func TestAppendToMissingFileIsSealed(t *testing.T) {
	b, raw, dir := testBackend(t)
	n, err := b.AppendFile(bytes.NewReader([]byte("first part")), testPath)
	require.NoError(t, err)
	require.EqualValues(t, 10, n)
	ok, _ := raw.FileExists(testPath)
	require.False(t, ok)
	names, _ := os.ReadDir(filepath.Join(dir, filepath.Dir(testPath)))
	require.Len(t, names, 1)
	stored, _ := os.ReadFile(filepath.Join(dir, filepath.Dir(testPath), names[0].Name()))
	require.Equal(t, fileMagic, string(stored[:len(fileMagic)]))
	require.NotContains(t, string(stored), "first part")
	got, err := b.ReadFile(testPath)
	require.NoError(t, err)
	require.Equal(t, "first part", string(got))
}

func TestFileBoundToChannel(t *testing.T) {
	b, raw, _ := testBackend(t)
	fb := b.(*fileBackend)
	other := "20261124/teams/noteam/channels/c2/users/u1/f1/보고서.hwpx"
	_, err := b.WriteFile(bytes.NewReader([]byte("for channel one")), testPath)
	require.NoError(t, err)

	// The stored bytes placed under another channel's path do not open.
	from, _, _ := fb.l.diskPath(testPath)
	to, _, _ := fb.l.diskPath(other)
	require.NoError(t, raw.CopyFile(from, to))
	_, err = b.ReadFile(other)
	require.Error(t, err)

	// Moved through the wrapper, the file is sealed again for its new channel.
	require.NoError(t, raw.RemoveFile(to))
	require.NoError(t, b.MoveFile(testPath, other))
	got, err := b.ReadFile(other)
	require.NoError(t, err)
	require.Equal(t, "for channel one", string(got))
	ok, _ := b.FileExists(testPath)
	require.False(t, ok)
}

func TestKeyServiceAddress(t *testing.T) {
	for addr, ok := range map[string]bool{
		"https://keys.example.org:8200": true,
		"http://127.0.0.1:8200":         true,
		"http://localhost:8200":         true,
		"http://[::1]:8200":             true,
		"http://bao:8200":               false,
		"http://10.0.0.5:8200":          false,
		"bao:8200":                      false,
	} {
		err := (&BaoWrapper{Addr: addr}).CheckAddr()
		require.Equal(t, ok, err == nil, addr)
	}
}

func TestMoveIntoAttachmentsSeals(t *testing.T) {
	b, raw, _ := testBackend(t)
	fb := b.(*fileBackend)
	// From outside the attachment tree, and from an attachment stored before encryption.
	_, err := raw.WriteFile(bytes.NewReader([]byte("plain outside")), "import/x.bin")
	require.NoError(t, err)
	require.NoError(t, b.MoveFile("import/x.bin", testPath))
	dp, _, _ := fb.l.diskPath(testPath)
	stored, err := raw.ReadFile(dp)
	require.NoError(t, err)
	require.Equal(t, fileMagic, string(stored[:len(fileMagic)]))
	got, err := b.ReadFile(testPath)
	require.NoError(t, err)
	require.Equal(t, "plain outside", string(got))

	// The usual upload path: a sealed .tmp renamed within its channel stays readable.
	tmp := testPath + ".tmp"
	_, err = b.WriteFile(bytes.NewReader([]byte("uploaded")), tmp)
	require.NoError(t, err)
	require.NoError(t, b.MoveFile(tmp, testPath))
	got, err = b.ReadFile(testPath)
	require.NoError(t, err)
	require.Equal(t, "uploaded", string(got))
}

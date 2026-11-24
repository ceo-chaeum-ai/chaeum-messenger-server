// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package encryptlayer

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/public/model"
)

type fakeWrapper struct{}

func (fakeWrapper) NewDataKey() ([]byte, string, error) {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k, base64.StdEncoding.EncodeToString(k), nil
}
func (fakeWrapper) Unwrap(w string) ([]byte, error) { return base64.StdEncoding.DecodeString(w) }

type fakeTable map[string]string

func (t fakeTable) Load(id string) (string, bool, error) { w, ok := t[id]; return w, ok, nil }
func (t fakeTable) Insert(id, w string) error {
	if _, ok := t[id]; !ok {
		t[id] = w
	}
	return nil
}

func testLayer(t *testing.T) *EncryptLayer {
	keys := NewKeyRing(fakeWrapper{}, fakeTable{})
	require.NoError(t, keys.Prepare())
	return &EncryptLayer{keys: keys}
}

func TestPostRoundTrip(t *testing.T) {
	l := testLayer(t)
	p := &model.Post{ChannelId: "ch1", Message: "안녕하세요 #회의 내용", Hashtags: "#회의"}
	p.AddProp("attachments", []*model.SlackAttachment{{Text: "붙임 글"}})

	sv, err := l.encArgs(p)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(p.Message, prefix))
	require.NotContains(t, p.Message, "안녕")
	require.Empty(t, p.Hashtags)
	require.Nil(t, p.GetProp("attachments"))
	att, ok := p.GetProp(sealedAttProp).(string)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(att, prefix))

	// What the database would hand back on a later read.
	stored := &model.Post{ChannelId: "ch1", Message: p.Message}
	stored.AddProp(sealedAttProp, att)

	sv.done()
	require.Equal(t, "안녕하세요 #회의 내용", p.Message)
	require.Equal(t, "#회의", p.Hashtags)
	// The pointer was an argument: decResults must leave it alone.
	require.NoError(t, l.decResults(sv, p))
	require.Equal(t, "안녕하세요 #회의 내용", p.Message)

	require.NoError(t, l.decResults(nil, stored))
	require.Equal(t, "안녕하세요 #회의 내용", stored.Message)
	require.Equal(t, "#회의", stored.Hashtags)
	require.Nil(t, stored.GetProp(sealedAttProp))
	require.Len(t, stored.Attachments(), 1)
	require.Equal(t, "붙임 글", stored.Attachments()[0].Text)
}

// Ciphertext copied into another channel does not authenticate; it is shown as stored, never as plaintext.
func TestWrongChannelStaysSealed(t *testing.T) {
	l := testLayer(t)
	p := &model.Post{ChannelId: "ch1", Message: "비밀"}
	_, err := l.encArgs(p)
	require.NoError(t, err)
	moved := &model.Post{ChannelId: "ch2", Message: p.Message}
	require.NoError(t, l.decResults(nil, moved))
	require.Equal(t, p.Message, moved.Message)
}

func TestPlainAndLookalikeStay(t *testing.T) {
	l := testLayer(t)
	for _, m := range []string{"", "평문 글", prefix + "1999-01:AAAA", prefix + "garbage", prefix} {
		p := &model.Post{ChannelId: "ch1", Message: m}
		require.NoError(t, l.decResults(nil, p), m)
		require.Equal(t, m, p.Message)
	}
}

func TestDraftAndFile(t *testing.T) {
	l := testLayer(t)
	d := &model.Draft{UserId: "u1", ChannelId: "ch1", Message: "초안"}
	f := &model.FileInfo{Id: model.NewId(), Name: "보고서.hwpx", Content: "본문 글"}
	mini := []byte{1, 2, 3}
	f.MiniPreview = &mini
	sv, err := l.encArgs(d, f)
	require.NoError(t, err)
	require.NotContains(t, d.Message, "초안")
	require.NotContains(t, f.Name, "보고서")
	require.NotContains(t, f.Content, "본문")
	sd := &model.Draft{UserId: "u1", ChannelId: "ch1", Message: d.Message}
	sf := &model.FileInfo{Id: f.Id, Name: f.Name, Content: f.Content, MiniPreview: f.MiniPreview}
	sv.done()
	require.Equal(t, "초안", d.Message)
	require.Equal(t, "보고서.hwpx", f.Name)
	require.NoError(t, l.decResults(nil, []*model.Draft{sd}, []*model.FileInfo{sf}))
	require.Equal(t, "초안", sd.Message)
	require.Equal(t, "보고서.hwpx", sf.Name)
	require.Equal(t, "본문 글", sf.Content)
	require.Equal(t, []byte{1, 2, 3}, *sf.MiniPreview)
}

func TestPostListAndOldMonth(t *testing.T) {
	table := fakeTable{}
	l := &EncryptLayer{keys: NewKeyRing(fakeWrapper{}, table)}
	require.NoError(t, l.keys.Prepare())
	p := &model.Post{Id: "p1", ChannelId: "ch1", Message: "옛 글"}
	_, err := l.encArgs(p)
	require.NoError(t, err)

	// A fresh process with the same key table reads it back.
	l2 := &EncryptLayer{keys: NewKeyRing(fakeWrapper{}, table)}
	list := model.NewPostList()
	list.AddPost(p)
	require.NoError(t, l2.decResults(nil, list))
	require.Equal(t, "옛 글", list.Posts["p1"].Message)
}

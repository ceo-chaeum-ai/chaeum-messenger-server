// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

// Package chaeumsearch is the search engine of the messenger with storage encryption. The database
// holds ciphertext, so database search cannot work. Recent posts are searched by a separate worker
// process that keeps an index in memory (package worker); older posts are decrypted and scanned month
// by month on demand. The server decides which channels the user may read; the worker only returns ids.
package chaeumsearch

import (
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	worker "github.com/mattermost/mattermost/server/v8/channels/chaeumsearch/searchproto"
	"github.com/mattermost/mattermost/server/v8/channels/store"
	"github.com/mattermost/mattermost/server/v8/channels/store/encryptlayer"
)

const (
	EnvSocket     = "CHAEUM_SEARCH_SOCKET"
	indexMonths   = 6
	backfillBatch = 2000
	// The mobile app asks for the first page only, so the first page is filled from older months
	// within this budget. Later pages (desktop, web) may take longer because an empty page reads as the end.
	firstPageBudget = 2 * time.Second
	laterPageBudget = 8 * time.Second
	oldCacheTTL     = 5 * time.Minute
	// Scanning older months costs database reads and CPU for every distinct query, so it is bounded.
	maxOldScans  = 4   // scans running at the same time
	maxOldCached = 200 // remembered scans
	maxPerPage   = 200
)

// Enabled reports whether the search worker is configured.
func Enabled() bool { return os.Getenv(EnvSocket) != "" }

type Engine struct {
	sock     string
	getStore func() store.Store
	users    func() store.UserStore // the database's own user store, below the search layer
	log      mlog.LoggerIFace

	mu   sync.Mutex
	conn net.Conn
	dec  *json.Decoder
	enc  *json.Encoder

	backfilling atomic.Bool
	stop        chan struct{}

	oldMu sync.Mutex
	old   map[[32]byte]*oldScan
	scans chan struct{}
}

// oldScan remembers, for one user's channel set and one query, the ids found in months already scanned.
type oldScan struct {
	hits   []worker.Hit
	next   int64 // scan continues with posts created before this
	done   bool
	used   time.Time
	oldest int64
	mu     sync.Mutex
}

func New(getStore func() store.Store, users func() store.UserStore, log mlog.LoggerIFace) *Engine {
	return &Engine{sock: os.Getenv(EnvSocket), getStore: getStore, users: users, log: log, old: map[[32]byte]*oldScan{}, scans: make(chan struct{}, maxOldScans), stop: make(chan struct{})}
}

func (e *Engine) call(req *worker.Request) (*worker.Response, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if e.conn == nil {
			c, err := net.DialTimeout("unix", e.sock, 2*time.Second)
			if err != nil {
				return nil, err
			}
			e.conn, e.dec, e.enc = c, json.NewDecoder(c), json.NewEncoder(c)
		}
		_ = e.conn.SetDeadline(time.Now().Add(30 * time.Second))
		var resp worker.Response
		err := e.enc.Encode(req)
		if err == nil {
			err = e.dec.Decode(&resp)
		}
		if err == nil {
			if resp.Err != "" {
				return nil, &net.OpError{Op: "chaeum-search", Err: os.ErrInvalid}
			}
			return &resp, nil
		}
		e.conn.Close()
		e.conn = nil
		if attempt == 1 {
			return nil, err
		}
	}
}

func (e *Engine) Start() *model.AppError {
	go func() {
		t := time.NewTimer(2 * time.Second)
		for {
			select {
			case <-e.stop:
				return
			case <-t.C:
			}
			if resp, err := e.call(&worker.Request{Op: "status"}); err == nil && !resp.Ready && e.backfilling.CompareAndSwap(false, true) {
				go e.backfill()
			}
			t.Reset(30 * time.Second)
		}
	}()
	return nil
}

func (e *Engine) Stop() *model.AppError {
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
	return nil
}

func postText(p *model.Post) string {
	var b strings.Builder
	b.WriteString(p.Message)
	for _, a := range p.Attachments() {
		for _, s := range []string{a.Pretext, a.Title, a.Text} {
			if s != "" {
				b.WriteString("\n")
				b.WriteString(s)
			}
		}
		for _, f := range a.Fields {
			if f != nil {
				b.WriteString("\n" + f.Title)
				if s, ok := f.Value.(string); ok {
					b.WriteString("\n" + s)
				}
			}
		}
	}
	return b.String()
}

func indexable(p *model.Post) bool {
	return p.DeleteAt == 0 && !strings.HasPrefix(p.Type, model.PostSystemMessagePrefix)
}

func doc(p *model.Post) worker.Doc {
	return worker.Doc{ID: p.Id, Channel: p.ChannelId, User: p.UserId, CreateAt: p.CreateAt, Text: postText(p)}
}

// backfill streams the last months of posts to a worker that has just started.
func (e *Engine) backfill() {
	defer e.backfilling.Store(false)
	since := indexSince()
	if _, err := e.call(&worker.Request{Op: "reset", Since: since}); err != nil {
		return
	}
	started, n := time.Now(), 0
	at, id := since-1, ""
	for {
		posts, err := e.getStore().Post().GetPostsBatchForIndexing(at, id, backfillBatch)
		if err != nil {
			e.log.Warn("chaeumsearch: reading posts for the index failed", mlog.Err(err))
			return
		}
		docs := make([]worker.Doc, 0, len(posts))
		for _, p := range posts {
			if indexable(&p.Post) {
				docs = append(docs, doc(&p.Post))
			}
		}
		if len(docs) > 0 {
			if _, err = e.call(&worker.Request{Op: "index", Docs: docs}); err != nil {
				e.log.Warn("chaeumsearch: search worker went away while filling the index", mlog.Err(err))
				return
			}
			n += len(docs)
		}
		if len(posts) < backfillBatch {
			break
		}
		at, id = posts[len(posts)-1].CreateAt, posts[len(posts)-1].Id
	}
	files, err := e.backfillFiles(since)
	if err != nil {
		e.log.Warn("chaeumsearch: filling the file index failed", mlog.Err(err))
		return
	}
	if _, err := e.call(&worker.Request{Op: "ready"}); err == nil {
		e.log.Info("chaeumsearch: index filled", mlog.Int("posts", n), mlog.Int("files", files), mlog.Duration("took", time.Since(started)))
	}
}

// fileDoc is what the worker knows about an attachment: its name always, its extracted text only
// while the file is as recent as the posts the worker holds.
func fileDoc(f *model.FileInfo, channelID string, since int64) worker.Doc {
	text := f.Name
	if f.Content != "" && f.CreateAt >= since {
		text += "\n" + f.Content
	}
	return worker.Doc{ID: f.Id, Channel: channelID, User: f.CreatorId, CreateAt: f.CreateAt, Text: text, Ext: strings.ToLower(f.Extension)}
}

func indexSince() int64 {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -indexMonths, 0).UnixMilli()
}

func (e *Engine) backfillFiles(since int64) (int, error) {
	if _, err := e.call(&worker.Request{Op: "reset", Files: true}); err != nil {
		return 0, err
	}
	n := 0
	at, id := int64(0), ""
	for {
		files, err := e.getStore().FileInfo().GetFilesBatchForIndexing(at, id, false, backfillBatch)
		if err != nil {
			return n, err
		}
		docs := make([]worker.Doc, 0, len(files))
		for _, f := range files {
			if f.ChannelId != "" {
				info := f.FileInfo
				info.Content = f.Content
				docs = append(docs, fileDoc(&info, f.ChannelId, since))
			}
		}
		if len(docs) > 0 {
			if _, err = e.call(&worker.Request{Op: "index", Files: true, Docs: docs}); err != nil {
				return n, err
			}
			n += len(docs)
		}
		if len(files) < backfillBatch {
			return n, nil
		}
		at, id = files[len(files)-1].CreateAt, files[len(files)-1].Id
	}
}

func (e *Engine) IndexPost(post *model.Post, teamId string) *model.AppError {
	if !indexable(post) {
		return e.DeletePost(post)
	}
	if _, err := e.call(&worker.Request{Op: "index", Docs: []worker.Doc{doc(post)}}); err != nil {
		return appErr("IndexPost", err)
	}
	return nil
}

func (e *Engine) DeletePost(post *model.Post) *model.AppError {
	if _, err := e.call(&worker.Request{Op: "delete", IDs: []string{post.Id}}); err != nil {
		return appErr("DeletePost", err)
	}
	return nil
}

func (e *Engine) DeleteChannelPosts(rctx request.CTX, channelID string) *model.AppError {
	if _, err := e.call(&worker.Request{Op: "delete_channel", Channel: channelID}); err != nil {
		return appErr("DeleteChannelPosts", err)
	}
	return nil
}

func (e *Engine) DeleteUserPosts(rctx request.CTX, userID string) *model.AppError {
	if _, err := e.call(&worker.Request{Op: "delete_user", User: userID}); err != nil {
		return appErr("DeleteUserPosts", err)
	}
	return nil
}

func appErr(where string, err error) *model.AppError {
	return model.NewAppError("chaeumsearch."+where, "app.chaeumsearch.worker.app_error", nil, "", http.StatusInternalServerError).Wrap(err)
}

// splitTerms cuts a terms string on spaces, keeping "quoted phrases" whole.
func splitTerms(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for _, r := range s {
		switch {
		case r == '"':
			flush()
			quoted = !quoted
		case r == ' ' && !quoted:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func remove(list, drop []string) []string {
	if len(drop) == 0 {
		return list
	}
	out := list[:0:0]
	for _, x := range list {
		keep := true
		for _, d := range drop {
			keep = keep && x != d
		}
		if keep {
			out = append(out, x)
		}
	}
	return out
}

func keepOnly(list, only []string) []string {
	if len(only) == 0 {
		return list
	}
	out := list[:0:0]
	for _, x := range list {
		for _, o := range only {
			if x == o {
				out = append(out, x)
				break
			}
		}
	}
	return out
}

func buildQuery(allowed []string, p *model.SearchParams) *worker.Query {
	q := &worker.Query{
		Terms:         splitTerms(p.Terms),
		Or:            p.OrTerms,
		Excluded:      splitTerms(p.ExcludedTerms),
		Channels:      remove(keepOnly(allowed, p.InChannels), p.ExcludedChannels),
		FromUsers:     p.FromUsers,
		ExcludedUsers: p.ExcludedUsers,
	}
	if p.OnDate != "" {
		start, end := p.GetOnDateMillis()
		q.After, q.Before = start, end+1
	} else {
		if p.AfterDate != "" {
			q.After = p.GetAfterDateMillis()
		}
		if p.BeforeDate != "" {
			q.Before = p.GetBeforeDateMillis() + 1
		}
	}
	sort.Strings(q.Channels)
	return q
}

func (e *Engine) SearchPosts(channels model.ChannelList, searchParams []*model.SearchParams, page, perPage int) ([]string, model.PostSearchMatches, *model.AppError) {
	allowed := make([]string, 0, len(channels))
	for _, c := range channels {
		allowed = append(allowed, c.Id)
	}
	if perPage > maxPerPage {
		perPage = maxPerPage
	}
	want := (page + 1) * perPage
	budget := firstPageBudget
	if page > 0 {
		budget = laterPageBudget
	}
	deadline := time.Now().Add(budget)

	seen := map[string]struct{}{}
	matches := model.PostSearchMatches{}
	var hits []worker.Hit
	for _, p := range searchParams {
		q := buildQuery(allowed, p)
		if len(q.Channels) == 0 || (len(q.Terms) == 0 && len(q.FromUsers) == 0 && q.After == 0 && q.Before == 0) {
			continue
		}
		q.Limit = want
		resp, err := e.call(&worker.Request{Op: "search", Query: q})
		if err != nil {
			// The worker is down: search finds nothing, everything else keeps working.
			e.log.Warn("chaeumsearch: search worker is not answering", mlog.Err(err))
			return []string{}, matches, nil
		}
		found := resp.Hits
		if len(found) < want && (q.After == 0 || q.After < resp.Since) {
			found = append(found, e.scanOld(q, resp.Since, want-len(found), deadline, page > 0 && len(found) <= page*perPage)...)
		}
		for _, h := range found {
			if _, dup := seen[h.ID]; !dup {
				seen[h.ID] = struct{}{}
				hits = append(hits, h)
				matches[h.ID] = q.Terms
			}
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].CreateAt > hits[j].CreateAt })
	ids := []string{}
	for i := page * perPage; i < len(hits) && i < want; i++ {
		ids = append(ids, hits[i].ID)
	}
	return ids, matches, nil
}

// scanOld returns up to want matches older than the index, newest first. It walks back one month at a
// time until it has enough, runs out of time, or reaches the oldest post. mustFind keeps it going past
// the deadline's first check so that a later page is not returned empty while older months remain.
func (e *Engine) scanOld(q *worker.Query, indexSince int64, want int, deadline time.Time, mustFind bool) []worker.Hit {
	if indexSince == 0 {
		return nil // the worker has not been told its range yet
	}
	keyed := *q
	keyed.Limit = 0
	raw, _ := json.Marshal(&keyed)
	k := sha256.Sum256(raw)
	e.oldMu.Lock()
	for key, s := range e.old {
		if time.Since(s.used) > oldCacheTTL {
			delete(e.old, key)
		}
	}
	s := e.old[k]
	if s == nil {
		if len(e.old) >= maxOldCached {
			var oldestKey [32]byte
			var oldestUse time.Time
			for key, c := range e.old {
				if oldestUse.IsZero() || c.used.Before(oldestUse) {
					oldestKey, oldestUse = key, c.used
				}
			}
			delete(e.old, oldestKey)
		}
		s = &oldScan{next: indexSince}
		if q.Before != 0 && q.Before < s.next {
			s.next = q.Before
		}
		e.old[k] = s
	}
	s.used = time.Now()
	e.oldMu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.done && len(s.hits) < want {
		select {
		case e.scans <- struct{}{}:
			defer func() { <-e.scans }()
		case <-time.After(time.Until(deadline)):
			return s.hits[:min(len(s.hits), want)] // too many scans are running; answer with what is already known
		}
	}
	if s.oldest == 0 && !s.done {
		oldest, err := encryptlayer.OldestPost()
		if err != nil || oldest == 0 {
			s.done = true
		}
		s.oldest = oldest
		if q.After > s.oldest {
			s.oldest = q.After
		}
	}
	from := map[string]struct{}{}
	for _, u := range q.FromUsers {
		from[u] = struct{}{}
	}
	notFrom := map[string]struct{}{}
	for _, u := range q.ExcludedUsers {
		notFrom[u] = struct{}{}
	}
	matcher := worker.Compile(q)
	for !s.done && len(s.hits) < want {
		if time.Now().After(deadline) && !(mustFind && len(s.hits) == 0 && time.Now().Before(deadline.Add(laterPageBudget))) {
			break
		}
		to := s.next
		t := time.UnixMilli(to - 1).UTC()
		start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).UnixMilli()
		if start < s.oldest {
			start = s.oldest
		}
		err := encryptlayer.ScanPosts(q.Channels, start, to, func(p encryptlayer.ScannedPost) {
			if len(from) > 0 {
				if _, ok := from[p.UserID]; !ok {
					return
				}
			}
			if _, ok := notFrom[p.UserID]; ok {
				return
			}
			if matcher.Match(p.Message) {
				s.hits = append(s.hits, worker.Hit{ID: p.ID, CreateAt: p.CreateAt})
			}
		})
		if err != nil {
			e.log.Warn("chaeumsearch: scanning older posts failed", mlog.Err(err))
			break
		}
		s.next = start
		if start <= s.oldest {
			s.done = true
		}
	}
	if len(s.hits) > want {
		return s.hits[:want]
	}
	return s.hits
}

// The rest of the interface: users, channels and files stay with the database, which holds them in plaintext
// (file names and extracted file text are encrypted and are not searchable yet).

func (e *Engine) GetFullVersion() string                       { return "chaeumsearch-1" }
func (e *Engine) GetVersion() int                              { return 1 }
func (e *Engine) GetPlugins() []string                         { return nil }
func (e *Engine) UpdateConfig(cfg *model.Config)               {}
func (e *Engine) GetName() string                              { return "chaeumsearch" }
func (e *Engine) IsEnabled() bool                              { return true }
func (e *Engine) IsActive() bool                               { return true }
func (e *Engine) IsIndexingEnabled() bool                      { return true }
func (e *Engine) IsSearchEnabled() bool                        { return true }
func (e *Engine) IsAutocompletionEnabled() bool                { return false }
func (e *Engine) IsIndexingSync() bool                         { return false }
func (e *Engine) DeleteChannel(*model.Channel) *model.AppError { return nil }
func (e *Engine) DeleteUser(*model.User) *model.AppError       { return nil }
func (e *Engine) IndexChannel(request.CTX, *model.Channel, []string, []string) *model.AppError {
	return nil
}
func (e *Engine) SyncBulkIndexChannels(request.CTX, []*model.Channel, func(*model.Channel) ([]string, error), []string) *model.AppError {
	return nil
}
func (e *Engine) SearchChannels(string, string, string, bool, bool) ([]string, *model.AppError) {
	return []string{}, nil
}
func (e *Engine) IndexUser(request.CTX, *model.User, []string, []string) *model.AppError { return nil }
func (e *Engine) SearchUsersInChannel(string, string, []string, string, *model.UserSearchOptions) ([]string, []string, *model.AppError) {
	return []string{}, []string{}, nil
}

// SearchUsersInTeam answers from the database: user names are not encrypted. The search layer sends
// user search here whenever an engine has search enabled, so the engine hands it straight back.
func (e *Engine) SearchUsersInTeam(teamId string, restrictedToChannels []string, term string, options *model.UserSearchOptions) ([]string, *model.AppError) {
	users, err := e.users().Search(request.EmptyContext(e.log), teamId, term, options)
	if err != nil {
		return nil, appErr("SearchUsersInTeam", err)
	}
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.Id)
	}
	return ids, nil
}
func (e *Engine) IndexFile(f *model.FileInfo, channelID string) *model.AppError {
	if f.DeleteAt != 0 {
		return e.DeleteFile(f.Id)
	}
	if _, err := e.call(&worker.Request{Op: "index", Files: true, Docs: []worker.Doc{fileDoc(f, channelID, indexSince())}}); err != nil {
		return appErr("IndexFile", err)
	}
	return nil
}

func (e *Engine) DeleteFile(fileID string) *model.AppError {
	if _, err := e.call(&worker.Request{Op: "delete", Files: true, IDs: []string{fileID}}); err != nil {
		return appErr("DeleteFile", err)
	}
	return nil
}

func (e *Engine) DeleteUserFiles(rctx request.CTX, userID string) *model.AppError {
	if _, err := e.call(&worker.Request{Op: "delete_user", Files: true, User: userID}); err != nil {
		return appErr("DeleteUserFiles", err)
	}
	return nil
}

// SearchFiles finds attachments by name (all of them) and by extracted text (recent ones).
func (e *Engine) SearchFiles(channels model.ChannelList, searchParams []*model.SearchParams, page, perPage int) ([]string, *model.AppError) {
	allowed := make([]string, 0, len(channels))
	for _, c := range channels {
		allowed = append(allowed, c.Id)
	}
	if perPage > maxPerPage {
		perPage = maxPerPage
	}
	want := (page + 1) * perPage
	seen := map[string]struct{}{}
	var hits []worker.Hit
	for _, p := range searchParams {
		q := buildQuery(allowed, p)
		for _, x := range p.Extensions {
			q.Exts = append(q.Exts, strings.ToLower(strings.TrimPrefix(x, ".")))
		}
		for _, x := range p.ExcludedExtensions {
			q.ExcludedExts = append(q.ExcludedExts, strings.ToLower(strings.TrimPrefix(x, ".")))
		}
		if len(q.Channels) == 0 || (len(q.Terms) == 0 && len(q.FromUsers) == 0 && q.After == 0 && q.Before == 0 && len(q.Exts) == 0) {
			continue
		}
		q.Limit = want
		resp, err := e.call(&worker.Request{Op: "search", Files: true, Query: q})
		if err != nil {
			e.log.Warn("chaeumsearch: search worker is not answering", mlog.Err(err))
			return []string{}, nil
		}
		for _, h := range resp.Hits {
			if _, dup := seen[h.ID]; !dup {
				seen[h.ID] = struct{}{}
				hits = append(hits, h)
			}
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].CreateAt > hits[j].CreateAt })
	ids := []string{}
	for i := page * perPage; i < len(hits) && i < want; i++ {
		ids = append(ids, hits[i].ID)
	}
	return ids, nil
}

func (e *Engine) DeletePostFiles(request.CTX, string) *model.AppError               { return nil }
func (e *Engine) DeleteFilesBatch(request.CTX, int64, int64) *model.AppError        { return nil }
func (e *Engine) TestConfig(request.CTX, *model.Config) *model.AppError             { return nil }
func (e *Engine) PurgeIndexes(request.CTX) *model.AppError                          { return nil }
func (e *Engine) PurgeIndexList(request.CTX, []string) *model.AppError              { return nil }
func (e *Engine) RefreshIndexes(request.CTX) *model.AppError                        { return nil }
func (e *Engine) DataRetentionDeleteIndexes(request.CTX, time.Time) *model.AppError { return nil }

// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package encryptlayer

import (
	"database/sql"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
)

// EnvMigrate starts a background pass that encrypts what was stored before encryption was turned on.
// The server keeps serving meanwhile: rows and files are readable in either form, so the pass can be
// stopped at any point and started again.
const EnvMigrate = "CHAEUM_ENC_MIGRATE"

// The database's own full-text indexes. They are useless over ciphertext and still hold the words of
// the plaintext they were built from, so they go once everything is encrypted.
var plainTextIndexes = []string{
	"idx_posts_message_txt", "idx_posts_hashtags_txt",
	"idx_fileinfo_name_txt", "idx_fileinfo_content_txt", "idx_fileinfo_name_splitted",
}

var migrateOnce sync.Once

type migrator struct {
	l     *EncryptLayer
	db    *sql.DB
	files *fileBackend
	log   mlog.LoggerIFace
	pause time.Duration
}

func startMigration(files *fileBackend) {
	if os.Getenv(EnvMigrate) == "" || scanDB == nil || authLog == nil {
		return
	}
	migrateOnce.Do(func() {
		m := &migrator{l: files.l, db: scanDB, files: files, log: authLog, pause: 20 * time.Millisecond}
		go m.run()
	})
}

func (m *migrator) run() {
	m.log.Info("encryptlayer: encrypting content stored before encryption was turned on")
	// A post whose UpdateAt changed between the read and the update (a reaction, a reply) is skipped by
	// that update, so the table is walked again until a walk finds nothing left in the clear.
	var posts, failed int
	var err error
	for pass := 1; ; pass++ {
		var found, n int
		if found, n, failed, err = m.posts(); err != nil || failed > 0 || found == 0 {
			break
		}
		posts += n
		if pass == 20 {
			err = errors.New("posts keep changing under the migration")
			break
		}
	}
	if err == nil {
		var n, f int
		for _, table := range []string{"drafts", "scheduledposts"} {
			if n, f, err = m.drafts(table); err != nil {
				break
			}
			posts, failed = posts+n, failed+f
		}
	}
	var rows, files, f int
	if err == nil {
		rows, files, f, err = m.fileInfos()
		failed += f
	}
	if err != nil || failed > 0 {
		m.log.Error("encryptlayer: migration stopped before the end; it continues at the next start", mlog.Int("failed", failed), mlog.Err(err))
		return
	}
	for _, idx := range plainTextIndexes {
		if _, err = m.db.Exec(`DROP INDEX IF EXISTS ` + idx); err != nil {
			m.log.Error("encryptlayer: could not drop a plaintext search index", mlog.String("index", idx), mlog.Err(err))
			return
		}
	}
	m.log.Info("encryptlayer: migration finished; "+EnvMigrate+" can be removed", mlog.Int("messages", posts), mlog.Int("file_rows", rows), mlog.Int("files", files))
}

// posts seals message, attachments and hashtags of every post that still has them in the clear.
// found counts the rows that still needed sealing, done the rows this walk sealed.
func (m *migrator) posts() (found, done, failed int, err error) {
	type row struct {
		id, channel, message string
		updateAt             int64
		att                  sql.NullString
	}
	after := ""
	for {
		rows, err := m.db.Query(`SELECT Id, ChannelId, Message, UpdateAt, Props::jsonb->'attachments' FROM Posts
			WHERE Id > $1 AND ((Message <> '' AND Message NOT LIKE 'enc:v1:%') OR Hashtags <> '' OR jsonb_exists(Props::jsonb, 'attachments'))
			ORDER BY Id LIMIT 500`, after)
		if err != nil {
			return found, done, failed, err
		}
		var batch []row
		for rows.Next() {
			var r row
			if err = rows.Scan(&r.id, &r.channel, &r.message, &r.updateAt, &r.att); err != nil {
				rows.Close()
				return found, done, failed, err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return found, done, failed, err
		}
		if len(batch) == 0 {
			return found, done, failed, nil
		}
		// One transaction per batch: a commit per row costs a disk flush each.
		tx, err := m.db.Begin()
		if err != nil {
			return found, done, failed, err
		}
		found += len(batch)
		changed := 0
		for _, r := range batch {
			after = r.id
			var res sql.Result
			sealed := r.message
			if !strings.HasPrefix(sealed, prefix) {
				if sealed, err = m.l.seal("post", "message", r.channel, r.message); err != nil {
					_ = tx.Rollback()
					return found, done, failed, err
				}
			}
			// A post edited between the read and this update is left for the next pass (the edit itself is stored sealed).
			if r.att.Valid {
				var att string
				if att, err = m.l.seal("post", attachmentsProp, r.channel, r.att.String); err != nil {
					_ = tx.Rollback()
					return found, done, failed, err
				}
				res, err = tx.Exec(`UPDATE Posts SET Message = $1, Hashtags = '', Props = ((Props::jsonb - 'attachments') || jsonb_build_object('`+sealedAttProp+`', $2::text))
					WHERE Id = $3 AND UpdateAt = $4 AND Message = $5`, sealed, att, r.id, r.updateAt, r.message)
			} else {
				res, err = tx.Exec(`UPDATE Posts SET Message = $1, Hashtags = '' WHERE Id = $2 AND UpdateAt = $3 AND Message = $4`, sealed, r.id, r.updateAt, r.message)
			}
			if err != nil {
				// A failed statement ends the transaction; the batch is retried at the next start.
				_ = tx.Rollback()
				return found, done, failed + 1, err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				changed++
			}
		}
		if err = tx.Commit(); err != nil {
			return found, done, failed, err
		}
		done += changed
		if done%50000 < len(batch) {
			m.log.Info("encryptlayer: migrating posts", mlog.Int("done", done))
		}
		time.Sleep(m.pause)
	}
}

// drafts seals the message of drafts and scheduled posts, which share a shape.
func (m *migrator) drafts(table string) (done, failed int, err error) {
	for {
		rows, err := m.db.Query(`SELECT UserId, ChannelId, RootId, Message FROM ` + table + ` WHERE Message <> '' AND Message NOT LIKE 'enc:v1:%' LIMIT 500`)
		if err != nil {
			return done, failed, err
		}
		var batch [][4]string
		for rows.Next() {
			var r [4]string
			if err = rows.Scan(&r[0], &r[1], &r[2], &r[3]); err != nil {
				rows.Close()
				return done, failed, err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err = rows.Err(); err != nil || len(batch) == 0 {
			return done, failed, err
		}
		before := done
		for _, r := range batch {
			sealed, err := m.l.seal("draft", "message", r[0]+"|"+r[1], r[3])
			if err != nil {
				return done, failed, err
			}
			if _, err = m.db.Exec(`UPDATE `+table+` SET Message = $1 WHERE UserId = $2 AND ChannelId = $3 AND RootId = $4 AND Message = $5`, sealed, r[0], r[1], r[2], r[3]); err != nil {
				failed++
				continue
			}
			done++
		}
		if done == before {
			return done, failed, nil // nothing moved in this round; do not spin
		}
		time.Sleep(m.pause)
	}
}

// fileInfos walks every file row: files still stored in the clear are sealed on disk, and rows whose
// name, paths and extracted text are still in the clear are sealed in the database.
func (m *migrator) fileInfos() (rowsDone, filesDone, failed int, err error) {
	after := ""
	for {
		rows, err := m.db.Query(`SELECT Id, Name, Path, ThumbnailPath, PreviewPath, COALESCE(Content, ''), MiniPreview FROM FileInfo WHERE Id > $1 ORDER BY Id LIMIT 200`, after)
		if err != nil {
			return rowsDone, filesDone, failed, err
		}
		var batch []*model.FileInfo
		for rows.Next() {
			f := &model.FileInfo{}
			var mini []byte
			if err = rows.Scan(&f.Id, &f.Name, &f.Path, &f.ThumbnailPath, &f.PreviewPath, &f.Content, &mini); err != nil {
				rows.Close()
				return rowsDone, filesDone, failed, err
			}
			if mini != nil {
				f.MiniPreview = &mini
			}
			batch = append(batch, f)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return rowsDone, filesDone, failed, err
		}
		if len(batch) == 0 {
			return rowsDone, filesDone, failed, nil
		}
		for _, f := range batch {
			after = f.Id
			storedName := f.Name
			plainRow := f.Name != "" && !strings.HasPrefix(f.Name, prefix)
			if err = m.l.decFile(nil, f); err != nil {
				return rowsDone, filesDone, failed, err
			}
			ok := true
			for _, p := range []string{f.Path, f.ThumbnailPath, f.PreviewPath} {
				moved, err2 := m.files.sealStored(p)
				if err2 != nil {
					ok = false
					failed++
					m.log.Warn("encryptlayer: could not migrate a file", mlog.String("file_id", f.Id), mlog.Err(err2))
				} else if moved {
					filesDone++
				}
			}
			if !ok || !plainRow {
				continue
			}
			sv := &saved{seen: map[any]struct{}{}}
			if err = m.l.encFile(sv, f); err != nil {
				return rowsDone, filesDone, failed, err
			}
			var mini []byte
			if f.MiniPreview != nil {
				mini = *f.MiniPreview
			}
			if _, err = m.db.Exec(`UPDATE FileInfo SET Name = $1, Path = $2, ThumbnailPath = $3, PreviewPath = $4, Content = $5, MiniPreview = $6 WHERE Id = $7 AND Name = $8`,
				f.Name, f.Path, f.ThumbnailPath, f.PreviewPath, f.Content, mini, f.Id, storedName); err != nil {
				failed++
				m.log.Warn("encryptlayer: could not migrate a file row", mlog.String("file_id", f.Id), mlog.Err(err))
				continue
			}
			rowsDone++
		}
		time.Sleep(m.pause)
	}
}

// sealStored replaces an attachment stored in the clear at p by its sealed form. Readers find either
// one at every moment: the sealed copy is put in place whole before the plain one is removed.
func (b *fileBackend) sealStored(p string) (bool, error) {
	if p == "" {
		return false, nil
	}
	dp, ours, err := b.l.diskPath(p)
	if err != nil || !ours {
		return false, err
	}
	if ok, err2 := b.FileBackend.FileExists(p); err2 != nil || !ok {
		return false, err2
	}
	r, err := b.FileBackend.Reader(p)
	if err != nil {
		return false, err
	}
	tmp := dp + ".migrate"
	_, err = b.writeSealed(r, p, tmp)
	r.Close()
	if err != nil {
		_ = b.FileBackend.RemoveFile(tmp)
		return false, err
	}
	if err = b.FileBackend.MoveFile(tmp, dp); err != nil {
		return false, err
	}
	// The plain file goes only once the sealed copy is seen to hold all of it.
	plain, err := b.FileBackend.FileSize(p)
	if err != nil {
		return false, err
	}
	stored, err := b.FileBackend.FileSize(dp)
	if err != nil {
		return false, err
	}
	if plainSize(stored) != plain {
		return false, errors.Errorf("encryptlayer: sealed copy holds %d of %d bytes, keeping the plain file", plainSize(stored), plain)
	}
	return true, b.FileBackend.RemoveFile(p)
}

// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package encryptlayer

import (
	"database/sql"

	"github.com/lib/pq"
)

var scanDB *sql.DB

// ScannedPost is a decrypted post handed to a scan callback.
type ScannedPost struct {
	ID, UserID string
	CreateAt   int64
	Message    string
}

// ScanPosts decrypts the posts of the given channels created in [from, to), newest first, and hands
// each to fn. Search uses it for posts older than the search worker's index: nothing is kept.
func ScanPosts(channelIDs []string, from, to int64, fn func(ScannedPost)) error {
	if active == nil || scanDB == nil || len(channelIDs) == 0 {
		return nil
	}
	rows, err := scanDB.Query(`SELECT Id, ChannelId, UserId, CreateAt, Message FROM Posts
		WHERE ChannelId = ANY($1) AND CreateAt >= $2 AND CreateAt < $3 AND DeleteAt = 0 AND Type NOT LIKE 'system_%'
		ORDER BY CreateAt DESC`, pq.Array(channelIDs), from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p ScannedPost
		var channelID string
		if err = rows.Scan(&p.ID, &channelID, &p.UserID, &p.CreateAt, &p.Message); err != nil {
			return err
		}
		if p.Message, err = active.open("post", "message", channelID, p.Message); err != nil {
			return err
		}
		fn(p)
	}
	return rows.Err()
}

// OldestPost returns the creation time of the oldest post, or 0 when there is none.
func OldestPost() (int64, error) {
	if scanDB == nil {
		return 0, nil
	}
	var at sql.NullInt64
	err := scanDB.QueryRow(`SELECT MIN(CreateAt) FROM Posts`).Scan(&at)
	return at.Int64, err
}

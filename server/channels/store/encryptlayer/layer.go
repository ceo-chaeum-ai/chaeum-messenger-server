// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package encryptlayer

import (
	"os"
	"time"

	"github.com/pkg/errors"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/channels/store"
	"github.com/mattermost/mattermost/server/v8/channels/store/sqlstore"
)

// Environment variables that switch the layer on. With CHAEUM_ENC_KEY_ADDR unset the server stores plaintext as before.
const (
	EnvKeyAddr      = "CHAEUM_ENC_KEY_ADDR"
	EnvKeyTokenFile = "CHAEUM_ENC_KEY_TOKEN_FILE"
	EnvKeyName      = "CHAEUM_ENC_KEY_NAME"
	// EnvOff lets a server that has stored encrypted content start without the layer, on purpose.
	EnvOff = "CHAEUM_ENC_OFF"
)

// Columns that hold ciphertext must not have a length limit sized for plaintext.
var widenColumns = []string{
	`ALTER TABLE posts ALTER COLUMN message TYPE TEXT`,
	`ALTER TABLE drafts ALTER COLUMN message TYPE TEXT`,
	`ALTER TABLE scheduledposts ALTER COLUMN message TYPE TEXT`,
	`ALTER TABLE fileinfo ALTER COLUMN name TYPE TEXT`,
	`ALTER TABLE fileinfo ALTER COLUMN path TYPE TEXT`,
	`ALTER TABLE fileinfo ALTER COLUMN thumbnailpath TYPE TEXT`,
	`ALTER TABLE fileinfo ALTER COLUMN previewpath TYPE TEXT`,
	`ALTER TABLE uploadsessions ALTER COLUMN filename TYPE TEXT`,
	`ALTER TABLE uploadsessions ALTER COLUMN path TYPE TEXT`,
}

// Enabled reports whether storage encryption is configured.
func Enabled() bool { return os.Getenv(EnvKeyAddr) != "" }

// CheckOff is called when storage encryption is not configured. If this database already holds month
// keys the setting was most likely lost, and starting would quietly store plaintext from here on.
func CheckOff(sqlStore *sqlstore.SqlStore) error {
	if os.Getenv(EnvOff) != "" {
		return nil
	}
	var n int
	db := sqlStore.GetInternalMasterDB()
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name = 'chaeummonthkeys' AND table_schema = current_schema()`).Scan(&n); err != nil || n == 0 {
		return err
	}
	if err := db.QueryRow(`SELECT count(*) FROM chaeummonthkeys`).Scan(&n); err != nil || n == 0 {
		return err
	}
	return errors.Errorf("encryptlayer: this database holds encrypted content but %s is not set; set it, or set %s=1 to start without encryption on purpose", EnvKeyAddr, EnvOff)
}

// NewFromEnv wraps the SQL store with the encryption layer configured from the environment.
func NewFromEnv(sqlStore *sqlstore.SqlStore, logger mlog.LoggerIFace) (*EncryptLayer, error) {
	wrapper := &BaoWrapper{Addr: os.Getenv(EnvKeyAddr), TokenFile: os.Getenv(EnvKeyTokenFile), KeyName: os.Getenv(EnvKeyName)}
	if wrapper.TokenFile == "" || wrapper.KeyName == "" {
		return nil, errors.Errorf("encryptlayer: %s and %s are required with %s", EnvKeyTokenFile, EnvKeyName, EnvKeyAddr)
	}
	if err := wrapper.CheckAddr(); err != nil {
		return nil, err
	}
	authLog = logger
	db := sqlStore.GetInternalMasterDB()
	table := SQLKeyTable{DB: db}
	if err := table.Init(); err != nil {
		return nil, errors.Wrap(err, "encryptlayer: month key table")
	}
	for _, q := range widenColumns {
		if _, err := db.Exec(q); err != nil {
			return nil, errors.Wrapf(err, "encryptlayer: %s", q)
		}
	}
	keys := NewKeyRing(wrapper, table)
	if err := keys.Prepare(); err != nil {
		return nil, errors.Wrap(err, "encryptlayer: month keys")
	}
	// Ciphertext is longer than the plaintext it replaces; the SQL store's own length checks must allow for it.
	sqlstore.EncryptedContentMaxRunes = model.PostMessageMaxRunesV2 * 8
	layer := New(sqlStore, keys)
	active, scanDB = layer, db
	go func() {
		for range time.Tick(time.Hour) {
			if err := keys.Prepare(); err != nil {
				logger.Warn("encryptlayer: preparing month keys failed", mlog.Err(err))
			}
		}
	}()
	logger.Info("Storage encryption is on", mlog.String("key_service", wrapper.Addr), mlog.String("key_name", wrapper.KeyName))
	return layer, nil
}

// The plaintext limits callers above this layer must respect.
func (s *EncryptLayerPostStore) GetMaxPostSize() int { return model.PostMessageMaxRunesV2 }

func (s *EncryptLayerScheduledPostStore) GetMaxMessageSize() int { return model.PostMessageMaxRunesV2 }

// SetContent stores the text extracted from a file, which arrives as a bare string.
func (s *EncryptLayerFileInfoStore) SetContent(rctx request.CTX, fileID, content string) error {
	sealed, err := s.Root.seal("file", "content", fileID, content)
	if err != nil {
		return err
	}
	return s.FileInfoStore.SetContent(rctx, fileID, sealed)
}

var _ store.Store = (*EncryptLayer)(nil)

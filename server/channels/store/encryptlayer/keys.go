// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package encryptlayer

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// KeyWrapper is the key custody service. The organisation key never leaves it: the server only ever
// holds month keys, and asks the service to create one or to unwrap a stored one.
type KeyWrapper interface {
	// NewDataKey returns a fresh 32-byte key and its wrapped form.
	NewDataKey() (plain []byte, wrapped string, err error)
	// Unwrap returns the plaintext of a wrapped key. Every call is recorded by the custody service.
	Unwrap(wrapped string) ([]byte, error)
}

// KeyTable stores wrapped month keys next to the data they protect.
type KeyTable interface {
	Load(id string) (wrapped string, found bool, err error)
	// Insert stores a wrapped key unless one with that id already exists.
	Insert(id, wrapped string) error
}

const idleKeyLifetime = 30 * time.Minute

type heldKey struct {
	key  []byte
	used time.Time
}

// KeyRing keeps unwrapped month keys in memory. The current and next month stay loaded so that a
// custody service outage only delays restarts and reads of old months; older keys are dropped when idle.
type KeyRing struct {
	wrapper KeyWrapper
	table   KeyTable
	now     func() time.Time

	mu      sync.Mutex
	held    map[string]*heldKey
	unknown map[string]time.Time
}

func NewKeyRing(wrapper KeyWrapper, table KeyTable) *KeyRing {
	return &KeyRing{wrapper: wrapper, table: table, now: time.Now, held: map[string]*heldKey{}, unknown: map[string]time.Time{}}
}

func monthID(t time.Time) string { return t.UTC().Format("2006-01") }

// Current returns the key for this month, creating it on first use.
func (r *KeyRing) Current() (string, []byte, error) {
	id := monthID(r.now())
	key, err := r.ensure(id)
	return id, key, err
}

// Prepare makes sure this month's and next month's keys exist and are loaded, and drops idle old keys.
func (r *KeyRing) Prepare() error {
	now := r.now()
	cur, next := monthID(now), monthID(now.UTC().AddDate(0, 1, -now.UTC().Day()+1))
	for _, id := range []string{cur, next} {
		if _, err := r.ensure(id); err != nil {
			return err
		}
	}
	r.mu.Lock()
	for id, h := range r.held {
		if id != cur && id != next && now.Sub(h.used) > idleKeyLifetime {
			for i := range h.key {
				h.key[i] = 0
			}
			delete(r.held, id)
		}
	}
	r.mu.Unlock()
	return nil
}

// Get returns a month key for reading. known is false when no such key id was ever issued, which
// means the value being read is not ours.
func (r *KeyRing) Get(id string) (key []byte, known bool, err error) {
	r.mu.Lock()
	if h, ok := r.held[id]; ok {
		h.used = r.now()
		r.mu.Unlock()
		return h.key, true, nil
	}
	if t, ok := r.unknown[id]; ok && r.now().Sub(t) < time.Minute {
		r.mu.Unlock()
		return nil, false, nil
	}
	r.mu.Unlock()

	wrapped, found, err := r.table.Load(id)
	if err != nil {
		return nil, true, err
	}
	if !found {
		r.mu.Lock()
		if len(r.unknown) > 1000 {
			r.unknown = map[string]time.Time{}
		}
		r.unknown[id] = r.now()
		r.mu.Unlock()
		return nil, false, nil
	}
	key, err = r.wrapper.Unwrap(wrapped)
	if err != nil {
		return nil, true, err
	}
	if len(key) != 32 {
		return nil, true, errors.Errorf("encryptlayer: month key %s has %d bytes", id, len(key))
	}
	return r.hold(id, key), true, nil
}

func (r *KeyRing) hold(id string, key []byte) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.held[id]; ok {
		h.used = r.now()
		return h.key
	}
	r.held[id] = &heldKey{key: key, used: r.now()}
	delete(r.unknown, id)
	return key
}

func (r *KeyRing) ensure(id string) ([]byte, error) {
	r.mu.Lock()
	if h, ok := r.held[id]; ok {
		h.used = r.now()
		r.mu.Unlock()
		return h.key, nil
	}
	r.mu.Unlock()

	wrapped, found, err := r.table.Load(id)
	if err != nil {
		return nil, err
	}
	if !found {
		_, newWrapped, err2 := r.wrapper.NewDataKey()
		if err2 != nil {
			return nil, err2
		}
		if err2 = r.table.Insert(id, newWrapped); err2 != nil {
			return nil, err2
		}
		// Another node may have inserted first; whatever is in the table is the key.
		if wrapped, found, err = r.table.Load(id); err != nil || !found {
			return nil, errors.Errorf("encryptlayer: month key %s missing after insert: %v", id, err)
		}
	}
	key, err := r.wrapper.Unwrap(wrapped)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.Errorf("encryptlayer: month key %s has %d bytes", id, len(key))
	}
	return r.hold(id, key), nil
}

// SQLKeyTable keeps wrapped month keys in the messenger database.
type SQLKeyTable struct{ DB *sql.DB }

func (t SQLKeyTable) Init() error {
	_, err := t.DB.Exec(`CREATE TABLE IF NOT EXISTS chaeummonthkeys (id VARCHAR(16) PRIMARY KEY, wrapped TEXT NOT NULL, createat BIGINT NOT NULL)`)
	return err
}

func (t SQLKeyTable) Load(id string) (string, bool, error) {
	var wrapped string
	err := t.DB.QueryRow(`SELECT wrapped FROM chaeummonthkeys WHERE id = $1`, id).Scan(&wrapped)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return wrapped, err == nil, err
}

func (t SQLKeyTable) Insert(id, wrapped string) error {
	_, err := t.DB.Exec(`INSERT INTO chaeummonthkeys (id, wrapped, createat) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, id, wrapped, time.Now().UnixMilli())
	return err
}

// BaoWrapper talks to an OpenBao (or Vault-compatible) transit engine.
type BaoWrapper struct {
	Addr      string // e.g. https://keys.example.org:8200
	TokenFile string // file holding the access token; re-read on every call so it can be rotated
	KeyName   string // transit key name of the organisation key
	Client    *http.Client
}

// CheckAddr refuses an address that would send month keys over the network in the clear.
func (b *BaoWrapper) CheckAddr() error {
	u, err := url.Parse(b.Addr)
	if err != nil || u.Hostname() == "" {
		return errors.Errorf("encryptlayer: key service address %q is not a URL", b.Addr)
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return errors.Errorf("encryptlayer: key service address %q must be https unless it is on loopback", b.Addr)
}

func (b *BaoWrapper) call(path string, body any) (map[string]any, error) {
	token, err := os.ReadFile(b.TokenFile)
	if err != nil {
		return nil, errors.Wrap(err, "encryptlayer: read key service token")
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(b.Addr, "/")+"/v1/transit/"+path+"/"+b.KeyName, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	client := b.Client
	if client == nil {
		// Redirects are not followed: the token must not travel to an address the operator did not configure.
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "encryptlayer: key service")
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("encryptlayer: key service answered %d", resp.StatusCode)
	}
	var parsed struct {
		Data map[string]any `json:"data"`
	}
	if err = json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	return parsed.Data, nil
}

func (b *BaoWrapper) NewDataKey() ([]byte, string, error) {
	data, err := b.call("datakey/plaintext", map[string]any{"bits": 256})
	if err != nil {
		return nil, "", err
	}
	plainB64, _ := data["plaintext"].(string)
	wrapped, _ := data["ciphertext"].(string)
	plain, err := base64.StdEncoding.DecodeString(plainB64)
	if err != nil || wrapped == "" {
		return nil, "", errors.New("encryptlayer: key service returned no data key")
	}
	return plain, wrapped, nil
}

func (b *BaoWrapper) Unwrap(wrapped string) ([]byte, error) {
	data, err := b.call("decrypt", map[string]any{"ciphertext": wrapped})
	if err != nil {
		return nil, err
	}
	plainB64, _ := data["plaintext"].(string)
	plain, err := base64.StdEncoding.DecodeString(plainB64)
	if err != nil || len(plain) == 0 {
		return nil, errors.New("encryptlayer: key service returned no plaintext")
	}
	return plain, nil
}

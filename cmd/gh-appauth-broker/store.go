package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS apps (
	name        TEXT PRIMARY KEY,
	app_id      INTEGER NOT NULL,
	private_key TEXT NOT NULL,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
	name          TEXT PRIMARY KEY,
	allowed_cidrs TEXT NOT NULL DEFAULT '[]',
	disabled      INTEGER NOT NULL DEFAULT 0,
	note          TEXT NOT NULL DEFAULT '',
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS client_secrets (
	id           INTEGER PRIMARY KEY,
	client       TEXT NOT NULL REFERENCES clients(name) ON DELETE CASCADE,
	sha256       TEXT NOT NULL UNIQUE,
	label        TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS grants (
	id          INTEGER PRIMARY KEY,
	client      TEXT NOT NULL REFERENCES clients(name) ON DELETE CASCADE,
	app         TEXT NOT NULL REFERENCES apps(name),
	repos       TEXT NOT NULL,
	permissions TEXT NOT NULL DEFAULT '{}',
	position    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
	id             INTEGER PRIMARY KEY,
	cache_key      TEXT NOT NULL,
	client         TEXT NOT NULL,
	app            TEXT NOT NULL,
	repo           TEXT NOT NULL,
	permissions    TEXT NOT NULL,
	token          TEXT NOT NULL,
	token_sha256   TEXT NOT NULL,
	bot_name       TEXT NOT NULL DEFAULT '',
	bot_email      TEXT NOT NULL DEFAULT '',
	issued_at      INTEGER NOT NULL,
	expires_at     INTEGER NOT NULL,
	hits           INTEGER NOT NULL DEFAULT 0,
	revoked_at     INTEGER,
	revoked_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS tokens_cache_key ON tokens(cache_key);
CREATE INDEX IF NOT EXISTS tokens_sha ON tokens(token_sha256);
CREATE TABLE IF NOT EXISTS requests (
	id     INTEGER PRIMARY KEY,
	ts     INTEGER NOT NULL,
	event  TEXT NOT NULL,
	status INTEGER NOT NULL DEFAULT 0,
	client TEXT NOT NULL DEFAULT '',
	ip     TEXT NOT NULL DEFAULT '',
	repo   TEXT NOT NULL DEFAULT '',
	app    TEXT NOT NULL DEFAULT '',
	perms  TEXT NOT NULL DEFAULT '',
	cached INTEGER NOT NULL DEFAULT 0,
	reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
CREATE TABLE IF NOT EXISTS sessions (
	id_sha256  TEXT PRIMARY KEY,
	csrf       TEXT NOT NULL,
	ip         TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
`

type Store struct {
	db   *sql.DB
	path string
}

// OpenStore opens (creating if needed) the broker database. The file holds App
// private keys, so it is created 0600 and a warning is printed if it is
// readable by anyone else.
func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600); err != nil {
		return nil, err
	} else {
		f.Close()
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: WARNING: %s has mode %v; it holds private keys and should be 0600\n", path, fi.Mode().Perm())
	}
	// The path is part of a URI, so characters that would end it are escaped.
	// _txlock=immediate makes transactions take the write lock up front: one
	// that reads first and then writes fails with "database is locked" if
	// another connection wrote in between, and busy_timeout doesn't cover that.
	dsn := "file:" + strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path) +
		"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DiskUsage reports the databases size on disk, including the -wal and -shm files
func (s *Store) DiskUsage() (total, wal int64) {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, err := os.Stat(s.path + suffix)
		if err != nil {
			continue
		}
		total += fi.Size()
		if suffix != "" {
			wal += fi.Size()
		}
	}
	return total, wal
}

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ---- config rows ----

type AppRow struct {
	Name       string
	AppID      int64
	PrivateKey string
	CreatedAt  time.Time
}

type ClientRow struct {
	Name         string
	AllowedCIDRs []string
	Disabled     bool
	Note         string
	CreatedAt    time.Time
}

type SecretRow struct {
	ID         int64
	Client     string
	SHA256     string
	Label      string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

type GrantRow struct {
	ID          int64
	Client      string
	App         string
	Repos       []string
	Permissions map[string]string
	Position    int
}

type ConfigRows struct {
	Apps    []AppRow
	Clients []ClientRow
	Secrets []SecretRow
	Grants  []GrantRow
}

func unix(t int64) time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(t, 0)
}

func (s *Store) LoadConfig() (*ConfigRows, error) {
	c := &ConfigRows{}
	rows, err := s.db.Query(`SELECT name, app_id, private_key, created_at FROM apps ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a AppRow
		var ts int64
		if err := rows.Scan(&a.Name, &a.AppID, &a.PrivateKey, &ts); err != nil {
			rows.Close()
			return nil, err
		}
		a.CreatedAt = unix(ts)
		c.Apps = append(c.Apps, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.db.Query(`SELECT name, allowed_cidrs, disabled, note, created_at FROM clients ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cl ClientRow
		var cidrs string
		var ts int64
		if err := rows.Scan(&cl.Name, &cidrs, &cl.Disabled, &cl.Note, &ts); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal([]byte(cidrs), &cl.AllowedCIDRs); err != nil {
			rows.Close()
			return nil, fmt.Errorf("client %s: allowed_cidrs: %w", cl.Name, err)
		}
		cl.CreatedAt = unix(ts)
		c.Clients = append(c.Clients, cl)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.db.Query(`SELECT id, client, sha256, label, created_at, COALESCE(last_used_at,0) FROM client_secrets ORDER BY client, id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sr SecretRow
		var ts, lu int64
		if err := rows.Scan(&sr.ID, &sr.Client, &sr.SHA256, &sr.Label, &ts, &lu); err != nil {
			rows.Close()
			return nil, err
		}
		sr.CreatedAt, sr.LastUsedAt = unix(ts), unix(lu)
		c.Secrets = append(c.Secrets, sr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.db.Query(`SELECT id, client, app, repos, permissions, position FROM grants ORDER BY client, position, id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var g GrantRow
		var repos, perms string
		if err := rows.Scan(&g.ID, &g.Client, &g.App, &repos, &perms, &g.Position); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal([]byte(repos), &g.Repos); err != nil {
			rows.Close()
			return nil, fmt.Errorf("grant %d: repos: %w", g.ID, err)
		}
		if err := json.Unmarshal([]byte(perms), &g.Permissions); err != nil {
			rows.Close()
			return nil, fmt.Errorf("grant %d: permissions: %w", g.ID, err)
		}
		c.Grants = append(c.Grants, g)
	}
	rows.Close()
	return c, rows.Err()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (s *Store) PutApp(a AppRow) error {
	_, err := s.db.Exec(`INSERT INTO apps(name, app_id, private_key, created_at) VALUES(?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET app_id=excluded.app_id, private_key=excluded.private_key`,
		a.Name, a.AppID, a.PrivateKey, time.Now().Unix())
	return err
}

func (s *Store) DeleteApp(name string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM grants WHERE app=?`, name).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("app %q is used by %d grant(s); remove them first", name, n)
	}
	_, err := s.db.Exec(`DELETE FROM apps WHERE name=?`, name)
	return err
}

func (s *Store) CreateClient(c ClientRow) error {
	if c.AllowedCIDRs == nil {
		c.AllowedCIDRs = []string{}
	}
	_, err := s.db.Exec(`INSERT INTO clients(name, allowed_cidrs, disabled, note, created_at) VALUES(?,?,?,?,?)`,
		c.Name, mustJSON(c.AllowedCIDRs), c.Disabled, c.Note, time.Now().Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("client %q already exists", c.Name)
	}
	return err
}

func (s *Store) UpdateClient(c ClientRow) error {
	if c.AllowedCIDRs == nil {
		c.AllowedCIDRs = []string{}
	}
	res, err := s.db.Exec(`UPDATE clients SET allowed_cidrs=?, disabled=?, note=? WHERE name=?`,
		mustJSON(c.AllowedCIDRs), c.Disabled, c.Note, c.Name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no client %q", c.Name)
	}
	return nil
}

func (s *Store) DeleteClient(name string) error {
	_, err := s.db.Exec(`DELETE FROM clients WHERE name=?`, name)
	return err
}

func (s *Store) AddSecret(client, sha, label string) error {
	_, err := s.db.Exec(`INSERT INTO client_secrets(client, sha256, label, created_at) VALUES(?,?,?,?)`,
		client, sha, label, time.Now().Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("that secret hash is already in use")
	}
	return err
}

func (s *Store) DeleteSecret(client string, id int64) error {
	_, err := s.db.Exec(`DELETE FROM client_secrets WHERE client=? AND id=?`, client, id)
	return err
}

func (s *Store) TouchSecret(id int64, t time.Time) {
	_, _ = s.db.Exec(`UPDATE client_secrets SET last_used_at=? WHERE id=?`, t.Unix(), id)
}

func (s *Store) AddGrant(g GrantRow) error {
	if g.Permissions == nil {
		g.Permissions = map[string]string{}
	}
	_, err := s.db.Exec(`INSERT INTO grants(client, app, repos, permissions, position)
		VALUES(?,?,?,?, COALESCE((SELECT MAX(position)+1 FROM grants WHERE client=?), 0))`,
		g.Client, g.App, mustJSON(g.Repos), mustJSON(g.Permissions), g.Client)
	return err
}

func (s *Store) UpdateGrant(g GrantRow) error {
	if g.Permissions == nil {
		g.Permissions = map[string]string{}
	}
	res, err := s.db.Exec(`UPDATE grants SET app=?, repos=?, permissions=? WHERE id=? AND client=?`,
		g.App, mustJSON(g.Repos), mustJSON(g.Permissions), g.ID, g.Client)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("client %q has no grant %d", g.Client, g.ID)
	}
	return nil
}

func (s *Store) DeleteGrant(client string, id int64) error {
	_, err := s.db.Exec(`DELETE FROM grants WHERE client=? AND id=?`, client, id)
	return err
}

// MoveGrant swaps a grant with its neighbour (dir -1 = up, +1 = down). Order
// matters because the first matching grant wins.
func (s *Store) MoveGrant(client string, id int64, dir int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id FROM grants WHERE client=? ORDER BY position, id`, client)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var x int64
		if err := rows.Scan(&x); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, x)
	}
	rows.Close()
	for i, x := range ids {
		if x == id {
			j := i + dir
			if j < 0 || j >= len(ids) {
				return nil
			}
			ids[i], ids[j] = ids[j], ids[i]
			break
		}
	}
	for i, x := range ids {
		if _, err := tx.Exec(`UPDATE grants SET position=? WHERE id=?`, i, x); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- tokens ----

type TokenRow struct {
	ID            int64
	CacheKey      string
	Client        string
	App           string
	Repo          string
	Permissions   map[string]string
	Token         string
	TokenSHA256   string
	BotName       string
	BotEmail      string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	Hits          int
	RevokedAt     time.Time
	RevokedReason string
}

const tokenCols = `id, cache_key, client, app, repo, permissions, token, token_sha256, bot_name, bot_email, issued_at, expires_at, hits, COALESCE(revoked_at,0), revoked_reason`

func scanToken(sc interface{ Scan(...any) error }) (*TokenRow, error) {
	var t TokenRow
	var perms string
	var ia, ea, ra int64
	if err := sc.Scan(&t.ID, &t.CacheKey, &t.Client, &t.App, &t.Repo, &perms, &t.Token, &t.TokenSHA256,
		&t.BotName, &t.BotEmail, &ia, &ea, &t.Hits, &ra, &t.RevokedReason); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(perms), &t.Permissions)
	t.IssuedAt, t.ExpiresAt, t.RevokedAt = unix(ia), unix(ea), unix(ra)
	return &t, nil
}

// CachedToken returns the live token for key with the latest expiry that
// is still valid after minValid, or nil.
func (s *Store) CachedToken(key string, minValid time.Time) (*TokenRow, error) {
	row := s.db.QueryRow(`SELECT `+tokenCols+` FROM tokens
		WHERE cache_key=? AND revoked_at IS NULL AND expires_at>? ORDER BY expires_at DESC LIMIT 1`, key, minValid.Unix())
	t, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

func (s *Store) HitToken(id int64) {
	_, _ = s.db.Exec(`UPDATE tokens SET hits=hits+1 WHERE id=?`, id)
}

// InsertToken stores a freshly minted token and drops rows that expired more
// than a day ago (the request history keeps the long-term record).
func (s *Store) InsertToken(t *TokenRow, now time.Time) error {
	_, err := s.db.Exec(`INSERT INTO tokens(cache_key, client, app, repo, permissions, token, token_sha256, bot_name, bot_email, issued_at, expires_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		t.CacheKey, t.Client, t.App, t.Repo, mustJSON(t.Permissions), t.Token, t.TokenSHA256, t.BotName, t.BotEmail,
		t.IssuedAt.Unix(), t.ExpiresAt.Unix())
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM tokens WHERE expires_at<?`, now.Add(-24*time.Hour).Unix())
	return err
}

// ActiveTokens lists unexpired, unrevoked tokens, soonest-expiring last.
func (s *Store) ActiveTokens(now time.Time) ([]*TokenRow, error) {
	rows, err := s.db.Query(`SELECT `+tokenCols+` FROM tokens WHERE revoked_at IS NULL AND expires_at>? ORDER BY issued_at DESC`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TokenRow
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) TokenByID(id int64) (*TokenRow, error) {
	t, err := scanToken(s.db.QueryRow(`SELECT `+tokenCols+` FROM tokens WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// TokenBySHA returns client's token with this hash, revoked or not.
func (s *Store) TokenBySHA(client, sha string) (*TokenRow, error) {
	t, err := scanToken(s.db.QueryRow(`SELECT `+tokenCols+` FROM tokens WHERE client=? AND token_sha256=?`, client, sha))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

func (s *Store) MarkRevoked(id int64, reason string, now time.Time) error {
	_, err := s.db.Exec(`UPDATE tokens SET revoked_at=?, revoked_reason=? WHERE id=? AND revoked_at IS NULL`, now.Unix(), reason, id)
	return err
}

// ---- request history ----

type RequestRow struct {
	ID     int64
	TS     time.Time
	Event  string
	Status int
	Client string
	IP     string
	Repo   string
	App    string
	Perms  string
	Cached bool
	Reason string
}

func (s *Store) InsertRequest(r *RequestRow) error {
	_, err := s.db.Exec(`INSERT INTO requests(ts, event, status, client, ip, repo, app, perms, cached, reason) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		r.TS.Unix(), r.Event, r.Status, r.Client, r.IP, r.Repo, r.App, r.Perms, r.Cached, r.Reason)
	return err
}

type RequestFilter struct {
	Client string
	Repo   string
	Event  string
	Before int64 // id, for paging
	Limit  int
}

func (s *Store) Requests(f RequestFilter) ([]*RequestRow, error) {
	q := `SELECT id, ts, event, status, client, ip, repo, app, perms, cached, reason FROM requests WHERE 1=1`
	var args []any
	if f.Client != "" {
		q += ` AND client=?`
		args = append(args, f.Client)
	}
	if f.Repo != "" {
		q += ` AND repo LIKE ?`
		args = append(args, "%"+strings.ToLower(f.Repo)+"%")
	}
	if f.Event != "" {
		q += ` AND event=?`
		args = append(args, f.Event)
	}
	if f.Before > 0 {
		q += ` AND id<?`
		args = append(args, f.Before)
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RequestRow
	for rows.Next() {
		var r RequestRow
		var ts int64
		if err := rows.Scan(&r.ID, &ts, &r.Event, &r.Status, &r.Client, &r.IP, &r.Repo, &r.App, &r.Perms, &r.Cached, &r.Reason); err != nil {
			return nil, err
		}
		r.TS = unix(ts)
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) EventCounts(since time.Time) (map[string]int, error) {
	rows, err := s.db.Query(`SELECT event, COUNT(*) FROM requests WHERE ts>=? GROUP BY event`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var e string
		var n int
		if err := rows.Scan(&e, &n); err != nil {
			return nil, err
		}
		m[e] = n
	}
	return m, rows.Err()
}

func (s *Store) PruneRequests(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM requests WHERE ts<?`, before.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- sessions ----

func (s *Store) CreateSession(idSHA, csrf, ip string, now, exp time.Time) error {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE expires_at<?`, now.Unix())
	_, err := s.db.Exec(`INSERT INTO sessions(id_sha256, csrf, ip, created_at, expires_at) VALUES(?,?,?,?,?)`,
		idSHA, csrf, ip, now.Unix(), exp.Unix())
	return err
}

func (s *Store) Session(idSHA string, now time.Time) (csrf string, ok bool) {
	err := s.db.QueryRow(`SELECT csrf FROM sessions WHERE id_sha256=? AND expires_at>?`, idSHA, now.Unix()).Scan(&csrf)
	return csrf, err == nil
}

func (s *Store) DeleteSession(idSHA string) {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE id_sha256=?`, idSHA)
}

func (s *Store) DeleteAllSessions() {
	_, _ = s.db.Exec(`DELETE FROM sessions`)
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

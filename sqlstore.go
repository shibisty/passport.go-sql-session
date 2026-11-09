// Package sqlstore keeps passport sessions and refresh tokens in a database
// through orm: MySQL, Postgres, SQLite, or any orm driver (MongoDB, Redis
// too). gtr package: passport-session-sql.
//
//	sessions := sqlstore.Sessions(conn, "")    // table passport_sessions
//	a := passport.New().UseSessionStore(sessions)
//	refresher := refresh.New(sqlstore.RefreshTokens(conn, ""), 30*24*time.Hour)
//
// Create the tables in a migration with SessionsTable and RefreshTable:
//
//	db.Schema.Create(ctx, "passport_sessions", sqlstore.SessionsTable)
//
// Only the SHA-256 of a session ID (or refresh token) is stored, so reading
// the table does not let anyone log in. Expired rows are removed when they
// are read; call Sweep from time to time to remove the rest.
package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"orm"
	"orm/schema"
	"passport"
	"passport/memorystore"
	"passport/refresh"
)

// Default table names.
const (
	DefaultSessionsTable = "passport_sessions"
	DefaultRefreshTable  = "passport_refresh_tokens"
)

type sessionRow struct {
	ID        string    `db:"id"`
	Identity  string    `db:"identity"`
	ExpiresAt time.Time `db:"expires_at"`
}

// SessionsTable defines the sessions table: id (the hash), identity (JSON)
// and expires_at.
func SessionsTable(t *schema.Blueprint) {
	t.String("id", 64).Primary()
	t.Text("identity")
	t.Timestamp("expires_at")
	t.IndexCols("expires_at")
}

// SessionStore implements passport.SessionStore.
type SessionStore struct {
	exec  orm.QueryExecutor
	table string
	now   func() time.Time
}

// Sessions makes a SessionStore on table ("" is DefaultSessionsTable).
func Sessions(exec orm.QueryExecutor, table string) *SessionStore {
	if table == "" {
		table = DefaultSessionsTable
	}
	return &SessionStore{exec: exec, table: table, now: time.Now}
}

// WithClock replaces the clock (tests).
func (s *SessionStore) WithClock(now func() time.Time) *SessionStore { s.now = now; return s }

func hash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *SessionStore) Create(ctx context.Context, identity *passport.Identity, ttl time.Duration) (string, error) {
	id, err := memorystore.NewID()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(identity) // Raw is json:"-"
	if err != nil {
		return "", err
	}
	_, err = s.exec.Insert(ctx, &orm.Query{Table: s.table, Key: "id", Values: map[string]any{
		"id": hash(id), "identity": string(data), "expires_at": s.now().UTC().Add(ttl),
	}})
	if err != nil {
		return "", fmt.Errorf("sqlstore: %w", err)
	}
	return id, nil
}

func (s *SessionStore) Get(ctx context.Context, sessionID string) (*passport.Identity, error) {
	var row sessionRow
	err := s.exec.Select(ctx, orm.NewQuery(s.table).Where("id", "=", hash(sessionID)).LimitOffset(1, 0), &row)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, passport.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlstore: %w", err)
	}
	if !s.now().Before(row.ExpiresAt) {
		_ = s.Destroy(ctx, sessionID)
		return nil, passport.ErrSessionNotFound
	}
	var id passport.Identity
	if err := json.Unmarshal([]byte(row.Identity), &id); err != nil {
		return nil, fmt.Errorf("sqlstore: session data: %w", err)
	}
	return &id, nil
}

func (s *SessionStore) Destroy(ctx context.Context, sessionID string) error {
	_, err := s.exec.Delete(ctx, orm.NewQuery(s.table).Where("id", "=", hash(sessionID)))
	return err
}

// Sweep deletes expired sessions and returns how many the driver reports.
func (s *SessionStore) Sweep(ctx context.Context) (int64, error) {
	res, err := s.exec.Delete(ctx, orm.NewQuery(s.table).Where("expires_at", "<", s.now().UTC()))
	return res.RowsAffected, err
}

// ---- refresh tokens ----

type refreshRow struct {
	ID        string    `db:"id"`
	Family    string    `db:"family"`
	Identity  string    `db:"identity"`
	ExpiresAt time.Time `db:"expires_at"`
	Spent     bool      `db:"spent"`
}

// RefreshTable defines the refresh token table.
func RefreshTable(t *schema.Blueprint) {
	t.String("id", 64).Primary()
	t.String("family", 64)
	t.Text("identity")
	t.Timestamp("expires_at")
	t.Boolean("spent").Default(false)
	t.IndexCols("family")
	t.IndexCols("expires_at")
}

// RefreshStore implements refresh.Store. Spend is an UPDATE ... WHERE
// spent = false whose affected-row count decides the race, so the driver
// must report affected rows (every orm driver but ClickHouse does).
type RefreshStore struct {
	exec  orm.QueryExecutor
	table string
	now   func() time.Time
}

// RefreshTokens makes a RefreshStore on table ("" is DefaultRefreshTable).
func RefreshTokens(exec orm.QueryExecutor, table string) *RefreshStore {
	if table == "" {
		table = DefaultRefreshTable
	}
	return &RefreshStore{exec: exec, table: table, now: time.Now}
}

func (s *RefreshStore) Save(ctx context.Context, r refresh.Record) error {
	data, err := json.Marshal(r.Identity)
	if err != nil {
		return err
	}
	if _, err := s.exec.Delete(ctx, orm.NewQuery(s.table).Where("id", "=", r.ID)); err != nil {
		return err
	}
	_, err = s.exec.Insert(ctx, &orm.Query{Table: s.table, Key: "id", Values: map[string]any{
		"id": r.ID, "family": r.Family, "identity": string(data), "expires_at": r.Expires.UTC(), "spent": r.Spent,
	}})
	return err
}

func (s *RefreshStore) Get(ctx context.Context, id string) (*refresh.Record, error) {
	var row refreshRow
	err := s.exec.Select(ctx, orm.NewQuery(s.table).Where("id", "=", id).LimitOffset(1, 0), &row)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, refresh.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rec := &refresh.Record{ID: row.ID, Family: row.Family, Expires: row.ExpiresAt, Spent: row.Spent}
	if err := json.Unmarshal([]byte(row.Identity), &rec.Identity); err != nil {
		return nil, fmt.Errorf("sqlstore: refresh token data: %w", err)
	}
	return rec, nil
}

func (s *RefreshStore) Spend(ctx context.Context, id string) (bool, error) {
	q := orm.NewQuery(s.table).Where("id", "=", id).Where("spent", "=", false)
	q.Values = map[string]any{"spent": true}
	res, err := s.exec.Update(ctx, q)
	return res.RowsAffected == 1, err
}

func (s *RefreshStore) RevokeFamily(ctx context.Context, family string) error {
	_, err := s.exec.Delete(ctx, orm.NewQuery(s.table).Where("family", "=", family))
	return err
}

// Sweep deletes expired refresh tokens.
func (s *RefreshStore) Sweep(ctx context.Context) (int64, error) {
	res, err := s.exec.Delete(ctx, orm.NewQuery(s.table).Where("expires_at", "<", s.now().UTC()))
	return res.RowsAffected, err
}

var (
	_ passport.SessionStore = (*SessionStore)(nil)
	_ refresh.Store         = (*RefreshStore)(nil)
)

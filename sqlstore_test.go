package sqlstore_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"orm"
	"orm/schema"
	"passport"
	sqlstore "passport-session-sql"
	"passport/refresh"
	"passport/sessionstoretest"
)

// mem is an orm.QueryExecutor over maps: =, < conditions joined with AND.
type mem struct {
	mu     sync.Mutex
	tables map[string][]map[string]any
	fail   error
}

func newMem() *mem { return &mem{tables: map[string][]map[string]any{}} }

func (m *mem) Driver() string             { return "mem" }
func (m *mem) Ping(context.Context) error { return nil }
func (m *mem) Close() error               { return nil }

func less(a, b any) bool {
	if at, ok := a.(time.Time); ok {
		return at.Before(b.(time.Time))
	}
	return fmt.Sprint(a) < fmt.Sprint(b)
}

func match(r map[string]any, q *orm.Query) bool {
	for _, c := range q.Wheres {
		v := r[c.Column]
		switch c.Op {
		case "=":
			if !reflect.DeepEqual(v, c.Value) {
				return false
			}
		case "<":
			if !less(v, c.Value) {
				return false
			}
		default:
			panic(c.Op)
		}
	}
	return true
}

func (m *mem) Insert(_ context.Context, q *orm.Query) (orm.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return orm.Result{}, m.fail
	}
	row := map[string]any{}
	for k, v := range q.Values {
		row[k] = v
	}
	m.tables[q.Table] = append(m.tables[q.Table], row)
	return orm.Result{RowsAffected: 1}, nil
}

func (m *mem) Select(_ context.Context, q *orm.Query, dest any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	for _, r := range m.tables[q.Table] {
		if match(r, q) {
			return orm.FillStruct(dest, r)
		}
	}
	return orm.ErrNotFound
}

func (m *mem) Update(_ context.Context, q *orm.Query) (orm.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.tables[q.Table] {
		if match(r, q) {
			for k, v := range q.Values {
				r[k] = v
			}
			n++
		}
	}
	return orm.Result{RowsAffected: int64(n)}, m.fail
}

func (m *mem) Delete(_ context.Context, q *orm.Query) (orm.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keep []map[string]any
	n := 0
	for _, r := range m.tables[q.Table] {
		if match(r, q) {
			n++
		} else {
			keep = append(keep, r)
		}
	}
	m.tables[q.Table] = keep
	return orm.Result{RowsAffected: int64(n)}, m.fail
}

func TestSessions(t *testing.T) {
	m := newMem()
	sessionstoretest.Run(t, sqlstore.Sessions(m, ""), 100*time.Millisecond)
	ctx := context.Background()
	s := sqlstore.Sessions(m, "custom")
	id, _ := s.Create(ctx, &passport.Identity{ProviderUserID: "1"}, time.Hour)
	row := m.tables["custom"][0]
	if row["id"] == id || len(row["id"].(string)) != 43 {
		t.Fatalf("the session id is stored as is: %v", row)
	}
	now := time.Now().Add(2 * time.Hour)
	if n, err := sqlstore.Sessions(m, "custom").WithClock(func() time.Time { return now }).Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("Sweep: %d %v", n, err)
	}
	m.fail = errors.New("db down")
	if _, err := s.Create(ctx, &passport.Identity{}, time.Hour); err == nil {
		t.Fatal("insert error lost")
	}
	if _, err := s.Get(ctx, "x"); err == nil || errors.Is(err, passport.ErrSessionNotFound) {
		t.Fatalf("store error reported as not found: %v", err)
	}
	m.fail = nil
	m.tables["custom"] = []map[string]any{{"id": hashOf("broken"), "identity": "{", "expires_at": time.Now().Add(time.Hour)}}
	if _, err := s.Get(ctx, "broken"); err == nil || errors.Is(err, passport.ErrSessionNotFound) {
		t.Fatalf("corrupted row: %v", err)
	}
}

func hashOf(id string) string { return sqlstore.Hash(id) }

func TestRefresh(t *testing.T) {
	m := newMem()
	store := sqlstore.RefreshTokens(m, "")
	r := refresh.New(store, time.Hour)
	ctx := context.Background()
	iss := issuer{}
	p1, err := r.Issue(ctx, iss, &passport.Identity{ProviderUserID: "7", Name: "Ann"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := r.Rotate(ctx, iss, p1.Refresh, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate(ctx, iss, p1.Refresh, time.Minute); !errors.Is(err, refresh.ErrReused) {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := r.Rotate(ctx, iss, p2.Refresh, time.Minute); !errors.Is(err, refresh.ErrInvalid) {
		t.Fatalf("family survived: %v", err)
	}
	p3, _ := r.Issue(ctx, iss, &passport.Identity{ProviderUserID: "8"}, time.Minute)
	if err := r.Revoke(ctx, p3.Refresh); err != nil || len(m.tables[sqlstore.DefaultRefreshTable]) != 0 {
		t.Fatalf("Revoke: %v %v", err, m.tables)
	}
	// Spend decides a race by affected rows.
	r.Issue(ctx, iss, &passport.Identity{ProviderUserID: "9"}, time.Minute)
	id := m.tables[sqlstore.DefaultRefreshTable][0]["id"].(string)
	if won, _ := store.Spend(ctx, id); !won {
		t.Fatal("first Spend lost")
	}
	if won, _ := store.Spend(ctx, id); won {
		t.Fatal("second Spend won")
	}
	if n, err := store.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("Sweep: %d %v", n, err)
	}
	m.tables[sqlstore.DefaultRefreshTable][0]["identity"] = "{"
	if _, err := store.Get(ctx, id); err == nil {
		t.Fatal("corrupted identity")
	}
	m.fail = errors.New("down")
	if _, err := store.Get(ctx, id); err == nil {
		t.Fatal("store error")
	}
	if err := store.Save(ctx, refresh.Record{ID: "x"}); err == nil {
		t.Fatal("save error")
	}
}

type issuer struct{}

func (issuer) Issue(_ context.Context, id *passport.Identity, _ time.Duration) (string, error) {
	return "access-" + id.ProviderUserID, nil
}

func TestTables(t *testing.T) {
	for name, fn := range map[string]func(*schema.Blueprint){"sessions": sqlstore.SessionsTable, "refresh": sqlstore.RefreshTable} {
		bp := &schema.Blueprint{Table: name}
		fn(bp)
		if len(bp.Columns) < 3 || !bp.Columns[0].IsPrimary {
			t.Errorf("%s: %+v", name, bp.Columns)
		}
	}
}

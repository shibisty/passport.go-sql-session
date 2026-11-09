# passport-session-sql

Sessions and refresh tokens of [`passport`](https://github.com/shibisty/passport.go) in a
database through [`orm`](https://github.com/shibisty/orm.go): MySQL, Postgres, SQLite (and
the other orm drivers). Go package: `sqlstore`.

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/orm.go github:shibisty/passport.go-sql-session
```

`passport` (`^0.1`) and `orm` (`^0.2`) are peer dependencies; add the orm driver of your database.

## Usage

```go
sessions := sqlstore.Sessions(conn, "")      // table passport_sessions
a := passport.New().UseSessionStore(sessions)

refresher := refresh.New(sqlstore.RefreshTokens(conn, ""), 30*24*time.Hour) // passport_refresh_tokens

// In a migration (migration-orm):
db.Schema.Create(ctx, sqlstore.DefaultSessionsTable, sqlstore.SessionsTable)
db.Schema.Create(ctx, sqlstore.DefaultRefreshTable, sqlstore.RefreshTable)

// From time to time (a cron, a ticker):
sessions.Sweep(ctx)
```

- Only the SHA-256 of a session ID or refresh token is stored: reading the table does
  not let anyone log in.
- An expired session is deleted when it is read; `Sweep` deletes the rest.
- `RefreshTokens` decides concurrent rotations with `UPDATE … WHERE spent = false` and the
  affected-row count, which every orm driver reports except ClickHouse.
- Store errors are returned as they are, never as "not logged in".

## Tests

```bash
gtr run test -- -race -cover   # the shared passport/sessionstoretest suite on an in-memory orm executor
```

## License

MIT

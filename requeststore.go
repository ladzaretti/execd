package main

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ladzaretti/migrate"

	_ "modernc.org/sqlite"
)

var (
	//go:embed migrations
	embedFS    embed.FS
	migrations = migrate.EmbeddedMigrations{
		FS:   embedFS,
		Path: "migrations",
	}
)

type requestStore struct {
	db   *sql.DB
	path string
}

func newExecDB(path string) (*requestStore, error) {
	p := path
	if p == "" {
		cacheDir, err := ensureDefaultCacheDir()
		if err != nil {
			return nil, fmt.Errorf("ensure cache dir: %v", err)
		}

		p = filepath.Join(cacheDir, defaultDBFilename)
	}

	rs := &requestStore{path: filepath.Clean(p)}

	if err := rs.open(); err != nil {
		return nil, err
	}

	return rs, nil
}

func (rs *requestStore) open() (retErr error) {
	db, err := sql.Open("sqlite", rs.path)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	defer func() {
		if retErr != nil {
			_ = db.Close()
		}
	}()

	//nolint:noctx //pragma configuration
	if _, err := db.Exec("PRAGMA journal_mode=WAL;PRAGMA synchronous=NORMAL;"); err != nil {
		return err
	}

	m := migrate.New(db, migrate.SQLiteDialect{})
	if _, err = m.Apply(migrations); err != nil {
		return fmt.Errorf("failed to apply migrations: %v", err)
	}

	rs.db = db

	return nil
}

func (rs *requestStore) close() error {
	if rs == nil || rs.db == nil {
		return nil
	}

	return rs.db.Close()
}

func ensureDefaultCacheDir() (dir string, _ error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("default cache path: %v", err)
	}

	cacheDir := filepath.Join(dir, defaultCacheDir)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("create cache dir %q: %v", cacheDir, err)
	}

	return cacheDir, nil
}

const insertQuery = `
	INSERT INTO
		requests (uuid, path, state)
	VALUES
		(?, ?, ?)
`

func (rs *requestStore) insert(ctx context.Context, uuid string, req RequestState) (int, error) {
	return rs.execContext(ctx, insertQuery, uuid, req.Path, req.State)
}

const updateStateQuery = `
	UPDATE requests
	SET
		state = ?
	WHERE
		uuid = ?
`

func (rs *requestStore) updateState(ctx context.Context, uuid string, state execState) (int, error) {
	return rs.execContext(ctx, updateStateQuery, state, uuid)
}

const completeQuery = `
	UPDATE requests
	SET
		state = ?,
		stdout = ?,
		stderr = ?,
		detached = ?,
		pid = NULLIF(?, 0),
		exit_code = ?,
		error = NULLIF(?, ""),
		completed_at = strftime('%Y-%m-%d %H:%M:%f', 'now')
	WHERE
		uuid = ?
`

func (rs *requestStore) complete(ctx context.Context, uuid string, req RequestState) (int, error) {
	return rs.execContext(ctx, completeQuery,
		req.State,
		req.Result.Stdout,
		req.Result.Stderr,
		req.Result.Detached,
		req.Result.PID,
		req.Result.ExitCode,
		req.Result.Error,
		uuid,
	)
}

const selectQuery = `
	SELECT
		uuid,
		path,
		state,
		stdout,
		stderr,
		detached,
		pid,
		exit_code,
		error,
		started_at,
		completed_at
	FROM
		requests
`

func (rs *requestStore) selectByUUID(ctx context.Context, uuid string) (RequestState, error) {
	query := selectQuery + "WHERE uuid = ?"

	row := rs.db.QueryRowContext(ctx, query, uuid)

	req, err := scanRequest(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RequestState{}, fmt.Errorf("request not found: %s", uuid)
		}

		return RequestState{}, fmt.Errorf("query request by uuid: %w", err)
	}

	return req, nil
}

func (rs *requestStore) selectPage(ctx context.Context, cursor string, filters []string, limit int) ([]RequestState, error) {
	query := selectQuery + "WHERE true "
	args := []any{}

	if cursor != "" {
		query += "AND uuid <= ? "

		args = append(args, cursor)
	}

	if len(filters) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(filters)), ",")
		query += "AND state IN (" + placeholders + ") "

		for _, f := range filters {
			args = append(args, f)
		}
	}

	query += "ORDER BY uuid DESC "

	if limit > 0 {
		query += "LIMIT ?"

		args = append(args, limit)
	}

	rows, err := rs.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query requests: %v", err)
	}
	defer func() { _ = rows.Close() }() //nolint:wsl_v5

	requests := make([]RequestState, 0, 16)

	for rows.Next() {
		req, err := scanRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("scan request: %v", err)
		}

		requests = append(requests, req)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %v", err)
	}

	return requests, nil
}

func scanRequest(rows interface{ Scan(dest ...any) error }) (RequestState, error) {
	var (
		uuid        string
		path        string
		state       string
		stdout      sql.NullString
		stderr      sql.NullString
		detached    sql.NullBool
		pid         sql.NullInt64
		exitCode    sql.NullInt64
		errMsg      sql.NullString
		startedAt   sql.NullString
		completedAt sql.NullString
	)

	if err := rows.Scan(
		&uuid,
		&path,
		&state,
		&stdout,
		&stderr,
		&detached,
		&pid,
		&exitCode,
		&errMsg,
		&startedAt,
		&completedAt,
	); err != nil {
		return RequestState{}, err
	}

	req := RequestState{
		UUID:  uuid,
		Path:  path,
		State: execState(state),
		Result: ExecResult{
			Stdout:   stdout.String,
			Stderr:   stderr.String,
			Detached: detached.Bool,
			Error:    errMsg.String,
		},
	}

	if startedAt.Valid && startedAt.String != "" {
		req.StartedAt, _ = time.Parse("2006-01-02 15:04:05.000", startedAt.String)
	}

	if completedAt.Valid && completedAt.String != "" {
		req.CompletedAt, _ = time.Parse("2006-01-02 15:04:05.000", completedAt.String)
	}

	if exitCode.Valid {
		code := int(exitCode.Int64)
		req.Result.ExitCode = &code
	}

	if pid.Valid {
		pid := int(pid.Int64)
		req.Result.PID = &pid
	}

	return req, nil
}

func (rs *requestStore) execContext(ctx context.Context, query string, args ...any) (int, error) {
	res, err := rs.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}

	insertID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	return int(insertID), nil
}

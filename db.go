package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ladzaretti/migrate"

	_ "modernc.org/sqlite"
)

type execDB struct {
	db   *sql.DB
	path string
}

func newExecDB(path string) (*execDB, error) {
	p := path
	if p == "" {
		cacheDir, err := ensureDefaultCacheDir()
		if err != nil {
			return nil, fmt.Errorf("ensure cache dir: %v", err)
		}

		p = filepath.Join(cacheDir, defaultDBFilename)
	}

	db := &execDB{path: filepath.Clean(p)}

	if err := db.open(); err != nil {
		return nil, err
	}

	return db, nil
}

func (e *execDB) open() (retErr error) {
	db, err := sql.Open("sqlite", e.path)
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

	e.db = db

	return nil
}

func (e *execDB) close() error {
	if e == nil || e.db == nil {
		return nil
	}

	return e.db.Close()
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

const newRequestQuery = `
	INSERT INTO
		requests (uuid, path, state)
	VALUES
		(?, ?, ?)
`

func (e *execDB) insertNewRequest(ctx context.Context, uuid string, req RequestState) (int, error) {
	return e.execContext(ctx, newRequestQuery, uuid, req.Path, req.State)
}

const updateStateQuery = `
	UPDATE requests
	SET
		state = ?
	WHERE
		uuid = ?
`

func (e *execDB) updateRequestState(ctx context.Context, uuid string, state execState) (int, error) {
	return e.execContext(ctx, updateStateQuery, state, uuid)
}

const completeRequestQuery = `
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

func (e *execDB) completeRequest(ctx context.Context, uuid string, req RequestState) (int, error) {
	return e.execContext(ctx, completeRequestQuery,
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

func (e *execDB) selectRequestByUUID(ctx context.Context, uuid string) (RequestState, error) {
	query := selectQuery + "WHERE uuid = ?"

	row := e.db.QueryRowContext(ctx, query, uuid)

	req, err := scanRequest(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RequestState{}, fmt.Errorf("request not found: %s", uuid)
		}

		return RequestState{}, fmt.Errorf("query request by uuid: %w", err)
	}

	return req, nil
}

func (e *execDB) selectRequests(ctx context.Context, cursor string, filters []string, limit int) ([]RequestState, error) {
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

	rows, err := e.db.QueryContext(ctx, query, args...)
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

func (e *execDB) execContext(ctx context.Context, query string, args ...any) (int, error) {
	res, err := e.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}

	insertID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	return int(insertID), nil
}

package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

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

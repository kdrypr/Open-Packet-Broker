// Package backup manages configuration backup/restore with version history.
package backup

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Backup types. config = file-based settings (live-restorable); data = the broker
// SQLite database; full = config + data + license (restore needs a restart).
const (
	TypeConfig = "config"
	TypeData   = "data"
	TypeFull   = "full"
)

// Entry represents one stored backup.
type Entry struct {
	ID          int64  `json:"id"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Size        int64  `json:"size"` // zip size in bytes
	AutoBackup  bool   `json:"auto_backup"`
	Created     string `json:"created"`
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store manages backups in SQLite (config stored as BLOBs).
type Store struct {
	db          *sql.DB
	rulesPath   string
	usersDBPath string
	dataDir     string // broker-data dir (for data/full backups); set via SetDataDir
}

// New creates the backup store and runs migrations.
func New(db *sql.DB, rulesPath, usersDBPath string) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS config_backups (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			description TEXT NOT NULL DEFAULT '',
			zip_data    BLOB NOT NULL,
			auto_backup INTEGER NOT NULL DEFAULT 0,
			created     DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	// Add the type column on existing installs (ignore "duplicate column" error).
	db.Exec(`ALTER TABLE config_backups ADD COLUMN type TEXT NOT NULL DEFAULT 'config'`)
	return &Store{db: db, rulesPath: rulesPath, usersDBPath: usersDBPath}, nil
}

// SetDataDir tells the store where the broker-data dir is, enabling data/full
// backups (broker.db + license.key + all config files).
func (s *Store) SetDataDir(dir string) { s.dataDir = dir }

// ── CRUD ──────────────────────────────────────────────────────────────────────

// Create makes a config backup (backward-compatible default).
func (s *Store) Create(description string, auto bool) (int64, error) {
	return s.CreateTyped(description, TypeConfig, auto)
}

// CreateTyped makes a backup of the given type (config | data | full).
func (s *Store) CreateTyped(description, typ string, auto bool) (int64, error) {
	switch typ {
	case TypeConfig, TypeData, TypeFull:
	default:
		typ = TypeConfig
	}
	zipData, err := s.buildZipTyped(typ)
	if err != nil {
		return 0, err
	}
	autoInt := 0
	if auto {
		autoInt = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO config_backups (description, zip_data, auto_backup, type) VALUES (?,?,?,?)`,
		description, zipData, autoInt, typ,
	)
	if err != nil {
		return 0, err
	}

	// Prune old auto-backups (keep last 20)
	if auto {
		s.db.Exec(`DELETE FROM config_backups WHERE auto_backup=1 AND id NOT IN (
			SELECT id FROM config_backups WHERE auto_backup=1 ORDER BY id DESC LIMIT 20
		)`)
	}

	return res.LastInsertId()
}

// AutoBackup creates an automatic backup before rule changes.
func (s *Store) AutoBackup() {
	s.Create("Auto-backup before change", true)
}

// List returns all backups, newest first.
func (s *Store) List() ([]Entry, error) {
	rows, err := s.db.Query(
		`SELECT id, description, LENGTH(zip_data), auto_backup, created, type FROM config_backups ORDER BY id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var auto int
		if err := rows.Scan(&e.ID, &e.Description, &e.Size, &auto, &e.Created, &e.Type); err != nil {
			return nil, err
		}
		e.AutoBackup = auto == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// Download returns the zip data for a backup.
func (s *Store) Download(id int64) ([]byte, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT zip_data FROM config_backups WHERE id=?`, id).Scan(&data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Restore extracts a backup's zip and overwrites current files.
func (s *Store) Restore(id int64) error {
	data, err := s.Download(id)
	if err != nil {
		return err
	}

	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	for _, f := range r.File {
		// Zip slip protection: only allow exact known filenames (no paths)
		cleanName := filepath.Base(f.Name)
		if cleanName != f.Name || strings.Contains(f.Name, "..") {
			continue // path traversal attempt
		}
		var dest string
		switch cleanName {
		case "rules.conf":
			dest = s.rulesPath
		case "dedup.conf", "masking.conf", "rules_state.json", "license.key", "broker.db":
			// data/full restore targets — written into the broker-data dir; the DB
			// only takes effect after a service restart (it is held open live).
			if s.dataDir == "" {
				continue
			}
			dest = filepath.Join(s.dataDir, cleanName)
		default:
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		if err := os.WriteFile(dest, content, 0600); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes a backup.
func (s *Store) Delete(id int64) error {
	res, err := s.db.Exec(`DELETE FROM config_backups WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("backup not found")
	}
	return nil
}

// Import stores an uploaded zip as a backup.
func (s *Store) Import(zipData []byte, description string) (int64, error) {
	// Validate zip
	if _, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData))); err != nil {
		return 0, errors.New("invalid zip file")
	}
	if description == "" {
		description = "Imported " + time.Now().Format("2006-01-02 15:04")
	}
	res, err := s.db.Exec(
		`INSERT INTO config_backups (description, zip_data) VALUES (?,?)`,
		description, zipData,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// buildZipTyped bundles the file set for the requested backup type. Missing files
// are skipped silently (a fresh install may not have all of them yet).
func (s *Store) buildZipTyped(typ string) ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	add := func(path, name string) { _ = addFileToZip(w, path, name) }

	switch typ {
	case TypeData:
		if s.dataDir != "" {
			add(filepath.Join(s.dataDir, "broker.db"), "broker.db")
		} else if s.usersDBPath != "" {
			add(s.usersDBPath, "broker.db")
		}
	case TypeFull:
		add(s.rulesPath, "rules.conf")
		if s.dataDir != "" {
			for _, n := range []string{"dedup.conf", "masking.conf", "rules_state.json", "license.key", "broker.db"} {
				add(filepath.Join(s.dataDir, n), n)
			}
		}
	default: // config — file-based settings, live-restorable
		add(s.rulesPath, "rules.conf")
		if s.dataDir != "" {
			for _, n := range []string{"dedup.conf", "masking.conf", "rules_state.json"} {
				add(filepath.Join(s.dataDir, n), n)
			}
		}
	}

	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func addFileToZip(w *zip.Writer, srcPath, zipName string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	f, err := w.Create(zipName)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

// Package logrotate provides built-in log file rotation.
// Rotates when file exceeds maxSize, keeps maxBackups old files.
package logrotate

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Config for log rotation.
type Config struct {
	MaxSizeMB  int // rotate when file exceeds this size (default 10)
	MaxBackups int // keep this many old files (default 5)
}

// Rotator watches a log file and rotates it when needed.
type Rotator struct {
	path   string
	config Config
	mu     sync.Mutex
	stopCh chan struct{}
}

// New creates and starts a log rotator.
func New(logPath string, cfg Config) *Rotator {
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 10
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}
	r := &Rotator{path: logPath, config: cfg, stopCh: make(chan struct{})}
	go r.loop()
	return r
}

func (r *Rotator) loop() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			r.checkAndRotate()
		case <-r.stopCh:
			return
		}
	}
}

// Stop halts the rotator.
func (r *Rotator) Stop() { close(r.stopCh) }

func (r *Rotator) checkAndRotate() {
	r.mu.Lock()
	defer r.mu.Unlock()

	fi, err := os.Stat(r.path)
	if err != nil {
		return
	}

	maxBytes := int64(r.config.MaxSizeMB) * 1024 * 1024
	if fi.Size() < maxBytes {
		return
	}

	// Rotate by COPY+TRUNCATE, not rename. The application logger holds an
	// open O_APPEND fd to this path; renaming it would orphan that fd onto the
	// backup inode (the writer keeps logging to the renamed file and the fresh
	// log stays empty forever). Copying then truncating in place keeps the
	// same inode, so the writer's fd keeps working and the file is emptied.
	ts := time.Now().Format("20060102_150405")
	backupPath := r.path + "." + ts
	if err := copyFile(r.path, backupPath); err != nil {
		return
	}
	if err := os.Truncate(r.path, 0); err != nil {
		return
	}

	// Prune old backups
	r.pruneBackups()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func (r *Rotator) pruneBackups() {
	dir := filepath.Dir(r.path)
	base := filepath.Base(r.path)
	pattern := base + ".*"

	matches, _ := filepath.Glob(filepath.Join(dir, pattern))
	if len(matches) <= r.config.MaxBackups {
		return
	}

	sort.Strings(matches) // oldest first (timestamp in name)
	toDelete := matches[:len(matches)-r.config.MaxBackups]
	for _, f := range toDelete {
		os.Remove(f)
	}
}

// CurrentSize returns the log file size in a human-readable format.
func (r *Rotator) CurrentSize() string {
	fi, err := os.Stat(r.path)
	if err != nil {
		return "0 B"
	}
	b := fi.Size()
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
}

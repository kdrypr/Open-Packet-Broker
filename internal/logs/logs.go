// Package logs reads and parses the shared packet_broker.log file.
package logs

import (
	"bufio"
	"os"
	"strings"
)

// Entry is a single parsed log line.
type Entry struct {
	Raw     string
	Time    string
	Level   string // INFO | ERROR | WARNING | DEBUG | "" (unparsed)
	Message string
}

// Page holds a slice of entries plus pagination metadata.
type Page struct {
	Entries     []Entry
	TotalLines  int
	CurrentPage int
	TotalPages  int
	PerPage     int
	HasPrev     bool
	HasNext     bool
	PrevPage    int
	NextPage    int
	PageNums    []int
}

// Parse extracts timestamp, level and message from a single log line.
//
// Recognised format (written by main.go's logInfo/logError):
//
//	2009/11/10 23:00:00 [INFO] message
//
// Falls back to splitting off a "YYYY/MM/DD HH:MM:SS" prefix if present,
// or treating the whole line as the message.
func Parse(line string) Entry {
	e := Entry{Raw: line}
	if line == "" {
		return e
	}

	// Look for " [LEVEL] " pattern.
	if li := strings.Index(line, " ["); li != -1 {
		if ri := strings.Index(line[li:], "] "); ri != -1 {
			lvl := line[li+2 : li+ri]
			switch lvl {
			case "INFO", "ERROR", "WARNING", "WARN", "DEBUG":
				e.Time = strings.TrimSpace(line[:li])
				e.Level = lvl
				e.Message = line[li+ri+2:]
				return e
			}
		}
	}

	// Go's log.LstdFlags: "2009/11/10 23:00:00 message"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) == 3 && len(parts[0]) == 10 && len(parts[1]) == 8 {
		e.Time = parts[0] + " " + parts[1]
		e.Level = "INFO"
		e.Message = parts[2]
		return e
	}

	e.Level = "INFO"
	e.Message = line
	return e
}

// ReadRecent returns the last n lines (newest first) from path as parsed entries.
// If opsOnly is true, lines written by the Go application (containing [INFO],
// [ERROR], [WARN], [DEBUG] markers) are excluded, leaving only C-binary logs.
func ReadRecent(path string, n int, opsOnly bool) []Entry {
	lines := readAllLines(path)
	if opsOnly {
		lines = filterOps(lines)
	}
	reverse(lines)
	if len(lines) > n {
		lines = lines[:n]
	}
	entries := make([]Entry, len(lines))
	for i, l := range lines {
		entries[i] = Parse(l)
	}
	return entries
}

// ReadPage reads the log file and returns a Page for the requested page/perPage.
// Lines are returned newest-first.
// If opsOnly is true, Go application log lines are filtered out.
func ReadPage(path string, page, perPage int, opsOnly bool) Page {
	lines := readAllLines(path)
	if opsOnly {
		lines = filterOps(lines)
	}
	reverse(lines)

	total := len(lines)
	totalPages := 1
	if total > 0 {
		totalPages = (total + perPage - 1) / perPage
	}
	if page > totalPages {
		page = totalPages
	}
	if page < 1 {
		page = 1
	}

	start := (page - 1) * perPage
	end := start + perPage
	if end > total {
		end = total
	}

	var slice []string
	if start < total {
		slice = lines[start:end]
	}

	entries := make([]Entry, len(slice))
	for i, l := range slice {
		entries[i] = Parse(l)
	}

	nums, hasPrev, hasNext, prev, next := buildPageNums(page, totalPages)

	return Page{
		Entries:     entries,
		TotalLines:  total,
		CurrentPage: page,
		TotalPages:  totalPages,
		PerPage:     perPage,
		HasPrev:     hasPrev,
		HasNext:     hasNext,
		PrevPage:    prev,
		NextPage:    next,
		PageNums:    nums,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// filterOps removes lines that were written by the Go application logger
// (lines containing " [INFO] ", " [ERROR] ", " [WARN] ", " [DEBUG] ").
// What remains are lines from the C packet broker binary.
func filterOps(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if !isAppLog(l) {
			out = append(out, l)
		}
	}
	return out
}

func isAppLog(line string) bool {
	for _, tag := range []string{" [INFO] ", " [ERROR] ", " [WARN] ", " [WARNING] ", " [DEBUG] "} {
		if strings.Contains(line, tag) {
			return true
		}
	}
	return false
}

func readAllLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		if l := scanner.Text(); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func buildPageNums(current, total int) (nums []int, hasPrev, hasNext bool, prev, next int) {
	hasPrev = current > 1
	hasNext = current < total
	prev = current - 1
	next = current + 1

	start := current - 3
	if start < 1 {
		start = 1
	}
	end := start + 6
	if end > total {
		end = total
		if s := end - 6; s > 0 {
			start = s
		}
	}
	for i := start; i <= end; i++ {
		nums = append(nums, i)
	}
	return
}

// Package errx centralizes the "redirect with a flash message" pattern
// the handlers all hand-rolled before this refactor. Using these
// helpers instead of inline url.QueryEscape calls:
//
//   - removes ~200 lines of boilerplate
//   - makes the success/error vocabulary uniform across pages
//   - gives one place to switch to slog later
//
// Typical call site:
//
//	if err := store.Create(...); err != nil {
//	    errx.RedirectError(w, r, "/rules", err)
//	    return
//	}
//	errx.RedirectSuccess(w, r, "/rules", "Rule added")
package errx

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// RedirectError 303-redirects back to `to` with `?error=<msg>` set.
// Accepts an error value so callers don't need to .Error() at the
// call site. nil errors are no-ops.
func RedirectError(w http.ResponseWriter, r *http.Request, to string, err error) {
	if err == nil {
		return
	}
	http.Redirect(w, r, to+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
}

// RedirectErrorMsg is the string variant.
func RedirectErrorMsg(w http.ResponseWriter, r *http.Request, to, msg string) {
	http.Redirect(w, r, to+"?error="+url.QueryEscape(msg), http.StatusSeeOther)
}

// RedirectSuccess 303-redirects back to `to` with `?success=<msg>`.
func RedirectSuccess(w http.ResponseWriter, r *http.Request, to, msg string) {
	http.Redirect(w, r, to+"?success="+url.QueryEscape(msg), http.StatusSeeOther)
}

// ParseID extracts a numeric path parameter from r.PathValue(name).
// Returns (0, false) on missing/malformed input — handler should
// respond with 400 rather than silently operating on id=0 (which the
// old `id, _ := strconv.ParseInt(...)` pattern did, leading to wrong-
// row deletes on malformed input).
func ParseID(r *http.Request, name string) (int64, bool) {
	raw := r.PathValue(name)
	if raw == "" {
		return 0, false
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// BadRequest is a convenience for 400 with a plain-text body.
func BadRequest(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusBadRequest)
}

// ErrMissingID is returned by handlers that received no usable ID.
var ErrMissingID = errors.New("missing or invalid path id")

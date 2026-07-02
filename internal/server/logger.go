package server

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"

	"packet_broker/internal/i18n"
)

// newLogger constructs the structured logger used by the rest of the
// server. We keep the `[INFO]` / `[ERROR]` text prefix because the
// internal/syslog log-tailer derives RFC 5424 severity from it; the
// rest of the line is JSON for machine consumption.
//
// Result is returned as both a *log.Logger (for the few stdlib call
// sites that need it, e.g. http.Server.ErrorLog) and a *slog.Logger
// (the one handlers should use via a.slog).
func newLogger(out io.Writer) (*log.Logger, *slog.Logger) {
	textLogger := log.New(out, "", log.LstdFlags)

	// JSON handler with a constant severity field. Time/source emitted
	// by slog so the legacy `LstdFlags` prefix is omitted on this path.
	jsonHandler := slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: false,
	})
	return textLogger, slog.New(jsonHandler)
}

// info / logErr are the de-facto logging API used throughout the
// handlers. Internally they fan out to both the legacy text logger
// (so existing syslog tailer regex still works) and the structured
// slog logger (for future SIEM consumers that want JSON).
//
// They accept optional structured key/value args (slog style):
//
//	a.info("rule edited", "index", idx, "in", ifIn, "out", ifOut)
//
// so callers can attach fields instead of building one opaque message
// string with '+' concatenation — the JSON handler then emits real
// attributes rather than a single blob.
func (a *App) info(msg string, args ...any) {
	if len(args) > 0 {
		a.logger.Printf("[INFO] %s %v", msg, args)
	} else {
		a.logger.Printf("[INFO] %s", msg)
	}
	if a.slog != nil {
		a.slog.Info(msg, args...)
	}
}

func (a *App) logErr(msg string, args ...any) {
	if len(args) > 0 {
		a.logger.Printf("[ERROR] %s %v", msg, args)
	} else {
		a.logger.Printf("[ERROR] %s", msg)
	}
	if a.slog != nil {
		a.slog.Error(msg, args...)
	}
}

// safeReferer accepts only relative same-origin Referer values. An
// attacker-controlled Referer (e.g. via a CSRF-bait page) would
// otherwise turn /set-lang into an open redirect to evil.example.
func safeReferer(r *http.Request) string {
	ref := r.Header.Get("Referer")
	if ref == "" {
		return "/"
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "/"
	}
	// Only honor a Referer that:
	//   - is relative (no scheme/host) OR
	//   - has the same host as the current request
	if u.Scheme == "" && u.Host == "" {
		return u.RequestURI()
	}
	if u.Host == r.Host {
		return u.RequestURI()
	}
	return "/"
}

// handleSetLang persists the chosen i18n language in a cookie and
// returns the user to wherever they came from — but ONLY if "wherever"
// is on this same host (see safeReferer).
func (a *App) handleSetLang(w http.ResponseWriter, r *http.Request) {
	lang := r.FormValue("lang")
	i18n.SetLang(w, lang)
	http.Redirect(w, r, safeReferer(r), http.StatusSeeOther)
}

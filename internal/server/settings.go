package server

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"packet_broker/internal/errx"
	"packet_broker/internal/tlsconfig"
)

// Upload limits for appliance settings.
const (
	maxLogoBytes = 1 << 20 // 1 MiB
	maxCertBytes = 256 << 10
	maxNameLen   = 64
)

// handleGuide renders the in-product Administration Guide (any logged-in user).
func (a *App) handleGuide(w http.ResponseWriter, r *http.Request) {
	a.render(w, "guide.html", a.baseData(r, "guide"))
}

// handleSettings renders the appliance settings page (branding + TLS/FQDN).
func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "settings")
	data.AppConfig = a.appCfg.Get()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "settings.html", data)
}

// handleBrandingSave updates the product name and FQDN. html/template escapes
// both on display; we additionally strip control chars / cap length on the name
// and validate the FQDN charset so neither can carry an injection payload.
func (a *App) handleBrandingSave(w http.ResponseWriter, r *http.Request) {
	name := sanitizeBrandName(r.FormValue("product_name"))
	if err := a.appCfg.SetProductName(name); err != nil {
		errx.RedirectError(w, r, "/admin/settings", err)
		return
	}
	fqdn := strings.TrimSpace(r.FormValue("fqdn"))
	if fqdn != "" && !validHostname(fqdn) {
		errx.RedirectErrorMsg(w, r, "/admin/settings", "invalid FQDN")
		return
	}
	if err := a.appCfg.SetFQDN(fqdn); err != nil {
		errx.RedirectError(w, r, "/admin/settings", err)
		return
	}
	a.audit(r, "branding", "name/fqdn updated")
	errx.RedirectSuccess(w, r, "/admin/settings", "Branding updated")
}

// handleLogoUpload accepts a raster image (PNG/JPEG/GIF/ICO only — SVG is
// rejected because it can carry script) and installs it as the appliance logo.
func (a *App) handleLogoUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoBytes+1024)
	if err := r.ParseMultipartForm(maxLogoBytes); err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/settings", "logo too large (max 1 MB)")
		return
	}
	file, _, err := r.FormFile("logo")
	if err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/settings", "logo file required")
		return
	}
	defer file.Close()
	data, _ := io.ReadAll(io.LimitReader(file, maxLogoBytes))
	ext := detectImageExt(data)
	if ext == "" {
		errx.RedirectErrorMsg(w, r, "/admin/settings", "unsupported image — use PNG, JPEG, GIF or ICO")
		return
	}
	dir := filepath.Join(a.rootDir, "static", "branding")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		errx.RedirectError(w, r, "/admin/settings", err)
		return
	}
	for _, e := range []string{".png", ".jpg", ".gif", ".ico"} {
		_ = os.Remove(filepath.Join(dir, "logo"+e))
	}
	if err := os.WriteFile(filepath.Join(dir, "logo"+ext), data, 0o644); err != nil {
		errx.RedirectError(w, r, "/admin/settings", err)
		return
	}
	_ = a.appCfg.SetLogoPath("branding/logo" + ext)
	a.audit(r, "branding_logo", "logo uploaded ("+ext+")")
	errx.RedirectSuccess(w, r, "/admin/settings", "Logo updated")
}

// handleLogoClear reverts to the built-in icon.
func (a *App) handleLogoClear(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Join(a.rootDir, "static", "branding")
	for _, e := range []string{".png", ".jpg", ".gif", ".ico"} {
		_ = os.Remove(filepath.Join(dir, "logo"+e))
	}
	_ = a.appCfg.SetLogoPath("")
	a.audit(r, "branding_logo", "logo cleared")
	errx.RedirectSuccess(w, r, "/admin/settings", "Logo cleared")
}

// handleTLSUpload installs an operator-provided PEM cert+key after validating
// they form a usable pair. The hot-reloading TLS server picks it up on the
// next handshake — no restart.
func (a *App) handleTLSUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2*maxCertBytes+4096)
	if err := r.ParseMultipartForm(2 * maxCertBytes); err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/settings", "upload too large")
		return
	}
	certPEM, err := readUpload(r, "cert", maxCertBytes)
	if err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/settings", "certificate file required")
		return
	}
	keyPEM, err := readUpload(r, "key", maxCertBytes)
	if err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/settings", "private key file required")
		return
	}
	certPath := filepath.Join(a.rootDir, "cert.pem")
	keyPath := filepath.Join(a.rootDir, "key.pem")
	if err := tlsconfig.InstallPEM(certPath, keyPath, certPEM, keyPEM); err != nil {
		errx.RedirectError(w, r, "/admin/settings", err)
		return
	}
	a.audit(r, "tls_cert", "custom certificate installed")
	errx.RedirectSuccess(w, r, "/admin/settings", "TLS certificate installed — applies on next connection")
}

// handleTLSRegen regenerates a self-signed cert that includes the configured FQDN.
func (a *App) handleTLSRegen(w http.ResponseWriter, r *http.Request) {
	fqdn := a.appCfg.Get().FQDN
	certPath := filepath.Join(a.rootDir, "cert.pem")
	keyPath := filepath.Join(a.rootDir, "key.pem")
	if err := tlsconfig.GenerateSelfSignedFor(certPath, keyPath, fqdn); err != nil {
		errx.RedirectError(w, r, "/admin/settings", err)
		return
	}
	a.audit(r, "tls_cert", "self-signed regenerated (fqdn="+fqdn+")")
	errx.RedirectSuccess(w, r, "/admin/settings", "Self-signed certificate regenerated — applies on next connection")
}

// handleBrandingAsset serves the uploaded logo. filepath.Base defeats
// traversal; only known raster image extensions are served.
func (a *App) handleBrandingAsset(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	ct := map[string]string{
		".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
		".gif": "image/gif", ".ico": "image/x-icon",
	}[strings.ToLower(filepath.Ext(name))]
	if ct == "" {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(a.rootDir, "static", "branding", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = io.Copy(w, f)
}

// ── helpers ────────────────────────────────────────────────────────────────

func readUpload(r *http.Request, field string, max int64) ([]byte, error) {
	f, _, err := r.FormFile(field)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// detectImageExt sniffs magic bytes; returns "" for anything that isn't a
// supported raster image (notably rejects SVG/XML).
func detectImageExt(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return ".png"
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return ".jpg"
	case bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a")):
		return ".gif"
	case bytes.HasPrefix(b, []byte{0x00, 0x00, 0x01, 0x00}):
		return ".ico"
	}
	return ""
}

// sanitizeBrandName strips control characters and caps length. Empty resets to
// the default (handled by appcfg). Display is html/template-escaped regardless.
func sanitizeBrandName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxNameLen {
			break
		}
	}
	return b.String()
}

func validHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '-') {
			return false
		}
	}
	return true
}

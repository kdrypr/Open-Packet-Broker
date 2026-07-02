package server

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"packet_broker/internal/errx"
)

// ---------------------------------------------------------------------------
// Backups (Feature 8)
// ---------------------------------------------------------------------------

func (a *App) handleBackups(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "backups")
	data.Backups, _ = a.backups.List()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "backups.html", data)
}

func (a *App) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	desc := strings.TrimSpace(r.FormValue("description"))
	if desc == "" {
		desc = "Manual backup"
	}
	if _, err := a.backups.Create(desc, false); err != nil {
		errx.RedirectError(w, r, "/backups", err)
		return
	}
	errx.RedirectSuccess(w, r, "/backups", "Backup created")
}

func (a *App) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	data, err := a.backups.Download(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"backup_%d.zip\"", id))
	w.Header().Set("Content-Type", "application/zip")
	w.Write(data)
}

func (a *App) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	if err := a.backups.Restore(id); err != nil {
		errx.RedirectError(w, r, "/backups", err)
		return
	}
	a.info("Config restored from backup #" + strconv.FormatInt(id, 10))
	errx.RedirectSuccess(w, r, "/backups", "Configuration restored")
}

func (a *App) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.backups.Delete(id)
	http.Redirect(w, r, "/backups", http.StatusSeeOther)
}

func (a *App) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	// Bound the entire request body — ParseMultipartForm's mem cap only
	// gates how much is buffered in RAM; the rest spills to disk and an
	// attacker could fill /tmp with a 10 GB chunked POST otherwise.
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupImportBytes)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		errx.RedirectErrorMsg(w, r, "/backups", "Upload too large or malformed: "+err.Error())
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		errx.RedirectErrorMsg(w, r, "/backups", "File required")
		return
	}
	defer file.Close()
	// io.LimitReader caps the actual read independent of declared size.
	data, err := io.ReadAll(io.LimitReader(file, maxBackupImportBytes))
	if err != nil {
		errx.RedirectErrorMsg(w, r, "/backups", "Read failed: "+err.Error())
		return
	}
	if _, err := a.backups.Import(data, r.FormValue("description")); err != nil {
		errx.RedirectError(w, r, "/backups", err)
		return
	}
	errx.RedirectSuccess(w, r, "/backups", "Backup imported")
}

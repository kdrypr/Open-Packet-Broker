package server

// Centralized request-size limits for multipart upload handlers.
//
// `r.ParseMultipartForm(N)` only caps how much is buffered in RAM — any
// excess streams to disk. To prevent an attacker filling /tmp with a
// huge chunked POST we ALWAYS wrap the request body in
// `http.MaxBytesReader(w, r.Body, limit)` before parsing. We also clamp
// the FormFile reader with `io.LimitReader(file, limit)` so a declared-
// vs-actual size mismatch can't blow up RAM in `io.ReadAll`.
const (
	maxBackupImportBytes = 32 << 20  // 32 MB — config zip
	maxFirmwareBytes     = 256 << 20 // 256 MB — ELF data-plane binary
	maxLicenseBytes      = 1 << 20   //  1 MB — Ed25519-signed JSON
)

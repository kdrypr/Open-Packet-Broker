package server

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"packet_broker/internal/auth"
	"packet_broker/internal/errx"
)

// ---------------------------------------------------------------------------
// SNMP Agent (#7)
// ---------------------------------------------------------------------------

func (a *App) handleSNMP(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "snmp")
	data.SNMPConfig = a.snmpAgent.GetConfigMasked()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "snmp.html", data)
}
func (a *App) handleSNMPSave(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") == "1"
	port, _ := strconv.Atoi(r.FormValue("port"))
	if err := a.snmpAgent.SaveConfig(enabled,
		strings.TrimSpace(r.FormValue("community")), port,
		strings.TrimSpace(r.FormValue("location")),
		strings.TrimSpace(r.FormValue("contact")),
	); err != nil {
		errx.RedirectError(w, r, "/admin/snmp", err)
		return
	}
	a.audit(r, "snmp_config", "SNMP settings updated")
	errx.RedirectSuccess(w, r, "/admin/snmp", "SNMP configuration saved")
}

// ---------------------------------------------------------------------------
// Audit Log (#14)
// ---------------------------------------------------------------------------

func (a *App) audit(r *http.Request, action, detail string) {
	u, _ := a.authStore.SessionUser(r)
	// Use the trusted-proxy-aware client IP — a raw X-Forwarded-For is
	// attacker-controlled and would let anyone forge the source address
	// recorded against an audited admin action.
	a.auditStore.Log(u.Username, action, detail, auth.ClientIP(r))
}

func (a *App) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "audit")
	data.AuditEntries, _ = a.auditStore.List(200)
	a.render(w, "audit.html", data)
}

// ---------------------------------------------------------------------------
// Firmware (#12)
// ---------------------------------------------------------------------------

func (a *App) handleFirmware(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "firmware")
	data.FirmwareInfo = a.firmwareMgr.CurrentInfo()
	data.FirmwareBackups = a.firmwareMgr.ListBackups()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "firmware.html", data)
}

func (a *App) handleFirmwareUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFirmwareBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/firmware", "Upload too large or malformed: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/firmware", "File required")
		return
	}
	defer file.Close()
	info, err := a.firmwareMgr.Upload(io.LimitReader(file, maxFirmwareBytes), header.Filename)
	if err != nil {
		errx.RedirectError(w, r, "/admin/firmware", err)
		return
	}
	a.audit(r, "firmware_upload", info.Name+" ("+info.SHA256[:16]+"...)")
	a.info("Firmware uploaded: " + info.Name)
	errx.RedirectSuccess(w, r, "/admin/firmware", "Firmware uploaded. Restart broker to apply.")
}

func (a *App) handleFirmwareRollback(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if err := a.firmwareMgr.Rollback(name); err != nil {
		errx.RedirectError(w, r, "/admin/firmware", err)
		return
	}
	a.audit(r, "firmware_rollback", name)
	errx.RedirectSuccess(w, r, "/admin/firmware", "Rolled back to "+name)
}

// ---------------------------------------------------------------------------
// 2FA/TOTP (#15)
// ---------------------------------------------------------------------------

func (a *App) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	u, _ := a.authStore.SessionUser(r)
	code := strings.TrimSpace(r.FormValue("totp_code"))
	if a.totpStore.Verify(u.ID, code) {
		a.audit(r, "2fa_enabled", u.Username)
		errx.RedirectSuccess(w, r, "/profile", "Two-factor authentication enabled")
	} else {
		errx.RedirectErrorMsg(w, r, "/profile", "Invalid code. Try again.")
	}
}

func (a *App) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	u, _ := a.authStore.SessionUser(r)
	a.totpStore.Disable(u.ID)
	a.audit(r, "2fa_disabled", u.Username)
	errx.RedirectSuccess(w, r, "/profile", "Two-factor authentication disabled")
}

// ---------------------------------------------------------------------------
// Email / SMTP
// ---------------------------------------------------------------------------

func (a *App) handleMail(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "mail")
	data.MailConfig = a.mailStore.GetConfig()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "mail.html", data)
}

func (a *App) handleMailSave(w http.ResponseWriter, r *http.Request) {
	port, _ := strconv.Atoi(r.FormValue("port"))
	enabled := r.FormValue("enabled") == "1"
	if err := a.mailStore.SaveConfig(
		r.FormValue("provider"), strings.TrimSpace(r.FormValue("host")), port,
		strings.TrimSpace(r.FormValue("username")), r.FormValue("password"),
		strings.TrimSpace(r.FormValue("from_address")), strings.TrimSpace(r.FormValue("from_name")),
		r.FormValue("encryption"), strings.TrimSpace(r.FormValue("alert_emails")),
		strings.TrimSpace(r.FormValue("tenant_id")),
		strings.TrimSpace(r.FormValue("client_id")),
		r.FormValue("client_secret"),
		enabled,
	); err != nil {
		errx.RedirectError(w, r, "/admin/mail", err)
		return
	}
	a.audit(r, "mail_config", "Email settings updated ("+r.FormValue("provider")+")")
	a.info("Email settings updated")
	errx.RedirectSuccess(w, r, "/admin/mail", "Email settings saved")
}

func (a *App) handleMailTest(w http.ResponseWriter, r *http.Request) {
	to := strings.TrimSpace(r.FormValue("to"))
	if to == "" {
		errx.RedirectErrorMsg(w, r, "/admin/mail", "Recipient required")
		return
	}
	if err := a.mailStore.SendTest(to); err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/mail", "Send failed: "+err.Error())
		return
	}
	a.info("Test email sent to " + to)
	errx.RedirectSuccess(w, r, "/admin/mail", "Test email sent to "+to)
}

// ---------------------------------------------------------------------------
// License (#16)
// ---------------------------------------------------------------------------

func (a *App) handleLicense(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "license")
	data.LicenseStatus = a.licenseMgr.GetStatus()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "license.html", data)
}

func (a *App) handleLicenseUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLicenseBytes)
	if err := r.ParseMultipartForm(maxLicenseBytes); err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/license", "Upload too large or malformed: "+err.Error())
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/license", "License file required")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxLicenseBytes))
	if err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/license", "Read failed: "+err.Error())
		return
	}
	if err := a.licenseMgr.Install(data); err != nil {
		errx.RedirectError(w, r, "/admin/license", err)
		return
	}
	a.info("License installed: " + a.licenseMgr.GetStatus().License.Customer)
	errx.RedirectSuccess(w, r, "/admin/license", "License activated successfully")
}

// ---------------------------------------------------------------------------
// Syslog / SIEM (Feature 11)
// ---------------------------------------------------------------------------

func (a *App) handleSyslog(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "syslog")
	data.SyslogConfig = a.syslogStore.GetConfig()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "syslog.html", data)
}

func (a *App) handleSyslogSave(w http.ResponseWriter, r *http.Request) {
	server := strings.TrimSpace(r.FormValue("server"))
	port, _ := strconv.Atoi(r.FormValue("port"))
	protocol := r.FormValue("protocol")
	facility, _ := strconv.Atoi(r.FormValue("facility"))
	enabled := r.FormValue("enabled") == "1"
	// Checkbox: if checked, form sends "1"; if unchecked, field is absent.
	// Check if "1" exists anywhere in the multi-value slice.
	fwdAlerts := sliceContains(r.Form["forward_alerts"], "1")
	fwdLogs := sliceContains(r.Form["forward_logs"], "1")
	sourceName := strings.TrimSpace(r.FormValue("source_name"))

	if err := a.syslogStore.SaveConfig(server, port, protocol, facility,
		enabled, fwdAlerts, fwdLogs, sourceName); err != nil {
		errx.RedirectError(w, r, "/admin/syslog", err)
		return
	}
	a.info("Syslog config updated: " + server + ":" + strconv.Itoa(port))
	errx.RedirectSuccess(w, r, "/admin/syslog", "Syslog configuration saved")
}

func (a *App) handleSyslogTest(w http.ResponseWriter, r *http.Request) {
	if err := a.syslogStore.SendTest(); err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/syslog", "Test failed: "+err.Error())
		return
	}
	a.info("Syslog test message sent")
	errx.RedirectSuccess(w, r, "/admin/syslog", "Test message sent successfully")
}

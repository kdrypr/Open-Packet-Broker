// Package server holds the packet-broker HTTP server: App wiring,
// middleware, route table, and feature handlers. Entry point is Run().
package server

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"packet_broker/internal/alerts"
	"packet_broker/internal/appcfg"
	"packet_broker/internal/auditlog"
	"packet_broker/internal/auth"
	"packet_broker/internal/backup"
	"packet_broker/internal/broker"
	"packet_broker/internal/capture"
	"packet_broker/internal/cluster"
	"packet_broker/internal/dedup"
	"packet_broker/internal/dpi"
	"packet_broker/internal/dpstats"
	"packet_broker/internal/firmware"
	"packet_broker/internal/healthcheck"
	"packet_broker/internal/i18n"
	"packet_broker/internal/license"
	"packet_broker/internal/logrotate"
	"packet_broker/internal/mailer"
	"packet_broker/internal/masking"
	"packet_broker/internal/mirror"
	"packet_broker/internal/netstats"
	"packet_broker/internal/portgroup"
	"packet_broker/internal/rules"
	"packet_broker/internal/snmpagent"
	"packet_broker/internal/ssldecrypt"
	"packet_broker/internal/sysinfo"
	pb_syslog "packet_broker/internal/syslog"
	"packet_broker/internal/throttle"
	"packet_broker/internal/tlsconfig"
	"packet_broker/internal/totp"
)

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

type App struct {
	broker       *broker.Manager
	rules        *rules.Manager
	authStore    *auth.Store
	stats        *netstats.Collector
	sysinfo      *sysinfo.Collector
	captures     *capture.Manager
	alerts       *alerts.Store
	backups      *backup.Store
	portGroups   *portgroup.Store
	syslogStore  *pb_syslog.Store
	mirrors      *mirror.Store
	throttles    *throttle.Store
	sslChains    *ssldecrypt.Store
	dedupStore   *dedup.Store
	clusterMgr   *cluster.Manager
	healthChecks *healthcheck.Monitor
	licenseMgr   *license.Manager
	mailStore    *mailer.Store
	auditStore   *auditlog.Store
	totpStore    *totp.Store
	firmwareMgr  *firmware.Manager
	logRotator   *logrotate.Rotator
	dpiStore     *dpi.Store
	dpStats      *dpstats.Reader
	maskingStore *masking.Store
	snmpAgent    *snmpagent.Store
	appCfg       *appcfg.Store
	logPath      string
	rootDir      string
	tmpl         *template.Template
	loginTmpl    *template.Template
	logger       *log.Logger  // legacy text logger (kept so syslog tailer regex still works)
	slog         *slog.Logger // structured JSON logger (preferred for new code)

	// defaultAdmin caches whether the built-in admin/admin credentials are
	// still active. Without this the unauthenticated login page ran a
	// bcrypt(cost=12) compare on every render — a cheap DoS amplifier.
	defAdminMu      sync.Mutex
	defAdminVal     bool
	defAdminAt      time.Time
	defAdminLatched bool // once secured it can't revert without a restart
}

// ---------------------------------------------------------------------------
// Template rendering
// ---------------------------------------------------------------------------

func (a *App) render(w http.ResponseWriter, name string, data PageData) {
	if err := a.tmpl.ExecuteTemplate(w, name, data); err != nil {
		a.logErr("template " + name + ": " + err.Error())
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// defaultAdminTTL bounds how often the (expensive) bcrypt probe runs while
// the default credentials are still active.
const defaultAdminTTL = 30 * time.Second

func (a *App) defaultAdminActive() bool {
	a.defAdminMu.Lock()
	defer a.defAdminMu.Unlock()
	if a.defAdminLatched {
		return false // secured already; never bcrypt again
	}
	if !a.defAdminAt.IsZero() && time.Since(a.defAdminAt) < defaultAdminTTL {
		return a.defAdminVal
	}
	active := a.computeDefaultAdmin()
	a.defAdminVal = active
	a.defAdminAt = time.Now()
	if !active {
		a.defAdminLatched = true
	}
	return active
}

func (a *App) computeDefaultAdmin() bool {
	n, err := a.authStore.UserCount()
	if err != nil || n != 1 {
		return false
	}
	_, err = a.authStore.Authenticate("admin", "admin")
	return err == nil
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func fmtBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

// Run is the entry point for the packet-broker daemon. It builds every
// subsystem store, wires router + middleware, opens listening sockets,
// and serves until the process is signaled. Startup failures terminate
// via log.Fatal — the appliance has nothing to do if a subsystem fails.
func Run() {
	rootDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("working directory: %v", err)
	}
	app, err := newApp(rootDir)
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	app.serve()
}

// newApp wires every subsystem store and returns a ready App. It returns an
// error instead of log.Fatal-ing deep in a helper, so construction is
// testable and Run owns the single fatal decision.
func newApp(rootDir string) (*App, error) {
	logPath := filepath.Join(rootDir, "packet_broker.log")
	lf, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	logger, sl := newLogger(lf)

	// Auth store
	authStore, err := auth.New(filepath.Join(rootDir, "users.db"))
	if err != nil {
		return nil, fmt.Errorf("auth store: %w", err)
	}

	if n, _ := authStore.UserCount(); n == 0 {
		// Force the operator through the change-password flow on first
		// login so admin/admin can never persist on a shipped appliance.
		if err := authStore.CreateUserForced("admin", "admin", auth.RoleAdmin, true); err != nil {
			return nil, fmt.Errorf("bootstrap admin: %w", err)
		}
		logger.Printf("[WARN] Default admin user created (admin/admin). Change password after first login.")
	}

	// Shared DB handle
	db := authStore.DB()

	// Net stats collector
	statsCollector := netstats.NewCollector(2 * 1e9) // 2 seconds

	// System info collector
	sysCollector := sysinfo.NewCollector(func() map[string]float64 {
		rates := statsCollector.Rates()
		out := make(map[string]float64)
		for iface, r := range rates {
			out[iface] = r.RxBPS + r.TxBPS
		}
		return out
	})

	// Capture manager
	captureMgr := capture.NewManager(filepath.Join(rootDir, "captures"))

	// Rules manager
	rulesPath := filepath.Join(rootDir, "rules.conf")
	rulesMgr := &rules.Manager{
		Path:      rulesPath,
		StatePath: filepath.Join(rootDir, "rules_state.json"),
	}

	// Alerts
	alertMetricReader := func(metric string) map[string]float64 {
		out := make(map[string]float64)
		switch metric {
		case "drop_rate":
			for iface, r := range statsCollector.Rates() {
				if r.RxPPS > 0 {
					out[iface] = r.RxDrops / r.RxPPS * 100
				}
			}
		case "rx_errors":
			for iface, s := range statsCollector.Stats() {
				out[iface] = float64(s.RxErrors)
			}
		case "link_down":
			for iface, info := range statsCollector.LinkInfo() {
				if info.OperState == "down" {
					out[iface] = 1
				}
			}
		case "cpu":
			out["system"] = sysCollector.Current().CPUPercent
		case "memory":
			out["system"] = sysCollector.Current().MemPercent
		}
		return out
	}
	alertStore, err := alerts.New(db, alertMetricReader)
	if err != nil {
		return nil, fmt.Errorf("alerts: %w", err)
	}

	// Email
	mailStore, err := mailer.New(db)
	if err != nil {
		return nil, fmt.Errorf("mailer: %w", err)
	}

	// Audit log
	auditStore, err := auditlog.New(db)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}

	// TOTP
	totpStore, err := totp.New(db)
	if err != nil {
		return nil, fmt.Errorf("totp: %w", err)
	}

	// Firmware
	firmwareMgr := firmware.NewManager(
		filepath.Join(rootDir, "packet_broker"),
		filepath.Join(rootDir, "firmware_backups"),
	)

	// DPI
	dpiStore, err := dpi.New(db)
	if err != nil {
		return nil, fmt.Errorf("dpi: %w", err)
	}

	// Masking
	maskingStore, err := masking.New(db, filepath.Join(rootDir, "masking.conf"))
	if err != nil {
		return nil, fmt.Errorf("masking: %w", err)
	}

	// SNMP Agent
	snmpProvider := &snmpagent.DataProvider{
		GetBrokerStatus: func() string { return "stopped" }, // overridden after app created
		GetRuleCount:    func() int { r, _ := rulesMgr.Parse(); return len(r) },
		GetCPUPercent:   func() float64 { return sysCollector.Current().CPUPercent },
		GetMemPercent:   func() float64 { return sysCollector.Current().MemPercent },
		GetAlertCount:   func() int { return alertStore.UnackedCount() },
		GetUptime:       func() time.Duration { return 0 },
	}
	snmpStore, err := snmpagent.New(db, snmpProvider)
	if err != nil {
		return nil, fmt.Errorf("snmp: %w", err)
	}

	// Appliance settings (branding + FQDN)
	appCfgStore, err := appcfg.New(db)
	if err != nil {
		return nil, fmt.Errorf("appcfg: %w", err)
	}

	// Log rotation
	logRotator := logrotate.New(logPath, logrotate.Config{MaxSizeMB: 10, MaxBackups: 5})

	// License
	licenseMgr, err := license.NewManager(filepath.Join(rootDir, "license.key"))
	if err != nil {
		return nil, fmt.Errorf("license: %w", err)
	}
	// Firmware uploads must verify against the same vendor key as
	// licenses, so the firmware manager gets the pubkey once license
	// init succeeds.
	firmwareMgr.SetVerifyKey(licenseMgr.VerifyKey())
	logger.Printf("[INFO] Hardware ID: %s", licenseMgr.GetStatus().HardwareID)
	if s := licenseMgr.GetStatus(); s.Valid {
		logger.Printf("[INFO] License: %s (%s), expires: %s", s.License.Customer, s.License.Type, s.License.Expiry)
	} else {
		logger.Printf("[WARN] License: %s", s.Error)
	}

	// Mirror
	mirrorStore, err := mirror.New(db)
	if err != nil {
		return nil, fmt.Errorf("mirror: %w", err)
	}

	// Throttle
	throttleStore, err := throttle.New(db)
	if err != nil {
		return nil, fmt.Errorf("throttle: %w", err)
	}

	// SSL Decrypt
	sslStore, err := ssldecrypt.New(db)
	if err != nil {
		return nil, fmt.Errorf("ssl Decrypt: %w", err)
	}

	// Dedup
	dedupStore, err := dedup.New(db, filepath.Join(rootDir, "dedup.conf"))
	if err != nil {
		return nil, fmt.Errorf("dedup: %w", err)
	}

	// Cluster
	clusterMgr, err := cluster.New(db)
	if err != nil {
		return nil, fmt.Errorf("cluster: %w", err)
	}

	// Syslog
	syslogStore, err := pb_syslog.New(db)
	if err != nil {
		return nil, fmt.Errorf("syslog: %w", err)
	}

	// Connect alerts → syslog + email
	alertStore.SetSyslog(func(ruleName, message string, value float64) {
		syslogStore.SendAlert(ruleName, message, value)
		mailStore.SendAlert(ruleName, message, value)
	})

	// Backups
	backupStore, err := backup.New(db, rulesPath, filepath.Join(rootDir, "users.db"))
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}

	// Port groups
	pgStore, err := portgroup.New(db)
	if err != nil {
		return nil, fmt.Errorf("port groups: %w", err)
	}

	// Templates
	funcs := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"mul": func(a, b int) int { return a * b },
		"min": func(a, b int) int {
			if a < b {
				return a
			}
			return b
		},
		"fmtBytes":  func(b uint64) string { return fmtBytes(b) },
		"join":      strings.Join,
		"hasPrefix": strings.HasPrefix,
		"gaugeArc":  func(pct float64) float64 { return pct / 100 * 125.66 },
		"t":         func(lang, key string) string { return i18n.Translate(lang, key) },
	}
	tmplDir := filepath.Join(rootDir, "templates")
	mainTmpl := template.Must(template.New("").Funcs(funcs).ParseGlob(filepath.Join(tmplDir, "*.html")))
	loginTmpl := template.Must(template.New("").ParseFiles(filepath.Join(tmplDir, "login.html")))

	// Data plane mode is fixed per-process via BROKER_MODE env var.
	// Default = libpcap for backward compatibility. afxdp gives the
	// kernel-visible zero-copy fast path; dpdk requires operator hugepage +
	// NIC-bind setup (set BROKER_MODE in the systemd unit).
	dpMode := strings.ToLower(strings.TrimSpace(os.Getenv("BROKER_MODE")))
	if dpMode != broker.ModeAFXDP && dpMode != broker.ModeDPDK {
		dpMode = broker.ModeLibpcap
	}

	app := &App{
		broker: &broker.Manager{
			BinPath:    filepath.Join(rootDir, "packet_broker"),
			AFXDPPath:  filepath.Join(rootDir, "packet_broker_afxdp"),
			DPDKPath:   filepath.Join(rootDir, "packet_broker_dpdk"),
			StatusPath: filepath.Join(rootDir, "packet_broker.status"),
			PidPath:    filepath.Join(rootDir, "packet_broker.pid"),
			LogPath:    logPath,
			RootDir:    rootDir,
			Mode:       dpMode,
		},
		rules:        rulesMgr,
		dpStats:      dpstats.New(rootDir),
		authStore:    authStore,
		stats:        statsCollector,
		sysinfo:      sysCollector,
		captures:     captureMgr,
		alerts:       alertStore,
		backups:      backupStore,
		portGroups:   pgStore,
		syslogStore:  syslogStore,
		mirrors:      mirrorStore,
		throttles:    throttleStore,
		sslChains:    sslStore,
		dedupStore:   dedupStore,
		clusterMgr:   clusterMgr,
		licenseMgr:   licenseMgr,
		mailStore:    mailStore,
		auditStore:   auditStore,
		totpStore:    totpStore,
		firmwareMgr:  firmwareMgr,
		logRotator:   logRotator,
		dpiStore:     dpiStore,
		maskingStore: maskingStore,
		snmpAgent:    snmpStore,
		appCfg:       appCfgStore,
		logPath:      logPath,
		rootDir:      rootDir,
		tmpl:         mainTmpl,
		loginTmpl:    loginTmpl,
		logger:       logger,
		slog:         sl,
	}

	// Health checks
	hcLinkReader := func() map[string]string {
		info := statsCollector.LinkInfo()
		out := make(map[string]string, len(info))
		for k, v := range info {
			out[k] = v.OperState
		}
		return out
	}
	hcMonitor, err := healthcheck.New(db, hcLinkReader, rulesMgr)
	if err != nil {
		return nil, fmt.Errorf("healthcheck: %w", err)
	}
	app.healthChecks = hcMonitor

	// Cluster heartbeat callback
	clusterMgr.SetHeartbeatCallback(func() cluster.Heartbeat {
		ruleList, _ := rulesMgr.Parse()
		return cluster.Heartbeat{
			RuleCount:    len(ruleList),
			BrokerStatus: app.broker.Status(),
			Uptime:       sysCollector.Current().UptimeStr,
		}
	})

	return app, nil
}

// routes registers every HTTP route and wraps the mux in the middleware chain.
func (a *App) routes() http.Handler {
	// Routes
	mux := http.NewServeMux()

	// Auth
	mux.HandleFunc("GET /login", a.handleLoginPage)
	mux.HandleFunc("POST /login", a.handleLoginSubmit)
	mux.HandleFunc("GET /login/totp", a.handleLoginTOTPPage)
	mux.HandleFunc("POST /login/totp", a.handleLoginTOTPSubmit)
	mux.HandleFunc("GET /logout", a.handleLogout)
	mux.HandleFunc("POST /set-lang", a.handleSetLang)

	// Dashboard
	mux.HandleFunc("GET /{$}", a.handleIndex)
	mux.HandleFunc("POST /start", a.adminOnly(a.handleStart))
	mux.HandleFunc("POST /stop", a.adminOnly(a.handleStop))

	// Rules & Topology
	mux.HandleFunc("GET /rules", a.handleRules)
	mux.HandleFunc("POST /add-rule", a.adminOnly(a.handleAddRule))
	mux.HandleFunc("POST /delete-rule", a.adminOnly(a.handleDeleteRule))
	mux.HandleFunc("POST /rules/{index}/edit", a.adminOnly(a.handleEditRule))
	mux.HandleFunc("POST /rules/{index}/toggle", a.adminOnly(a.handleToggleRule))
	mux.HandleFunc("POST /rules/reorder", a.adminOnly(a.handleReorderRules))

	// Logs
	mux.HandleFunc("GET /logs", a.handleLogs)

	// Profile
	mux.HandleFunc("GET /profile", a.handleProfile)
	mux.HandleFunc("POST /profile/password", a.handleProfilePassword)

	// Admin — users
	mux.HandleFunc("GET /admin/users", a.adminOnly(a.handleAdminUsers))
	mux.HandleFunc("POST /admin/users", a.adminOnly(a.handleAdminAddUser))
	mux.HandleFunc("POST /admin/users/{id}/password", a.adminOnly(a.handleAdminUserPassword))
	mux.HandleFunc("POST /admin/users/{id}/delete", a.adminOnly(a.handleAdminDeleteUser))

	// Captures
	mux.HandleFunc("GET /captures", a.handleCaptures)
	mux.HandleFunc("POST /captures/start", a.adminOnly(a.handleCaptureStart))
	mux.HandleFunc("POST /captures/{id}/stop", a.adminOnly(a.handleCaptureStop))
	mux.HandleFunc("GET /captures/{id}/download", a.adminOnly(a.handleCaptureDownload))
	mux.HandleFunc("POST /captures/{id}/delete", a.adminOnly(a.handleCaptureDelete))

	// Alerts
	mux.HandleFunc("GET /alerts", a.handleAlerts)
	mux.HandleFunc("POST /alerts", a.adminOnly(a.handleAlertCreate))
	mux.HandleFunc("POST /alerts/{id}/delete", a.adminOnly(a.handleAlertDelete))
	mux.HandleFunc("POST /alerts/{id}/toggle", a.adminOnly(a.handleAlertToggle))
	mux.HandleFunc("POST /alerts/{id}/acknowledge", a.adminOnly(a.handleAlertAcknowledge))

	// Backups
	mux.HandleFunc("GET /backups", a.adminOnly(a.handleBackups))
	mux.HandleFunc("POST /backups", a.adminOnly(a.handleBackupCreate))
	mux.HandleFunc("GET /backups/{id}/download", a.adminOnly(a.handleBackupDownload))
	mux.HandleFunc("POST /backups/{id}/restore", a.adminOnly(a.handleBackupRestore))
	mux.HandleFunc("POST /backups/{id}/delete", a.adminOnly(a.handleBackupDelete))
	mux.HandleFunc("POST /backups/import", a.adminOnly(a.handleBackupImport))

	// Load Balancing
	mux.HandleFunc("GET /load-balance", a.adminOnly(a.handleLoadBalance))
	mux.HandleFunc("POST /load-balance", a.adminOnly(a.handleLoadBalanceCreate))
	mux.HandleFunc("POST /load-balance/{id}/delete", a.adminOnly(a.handleLoadBalanceDelete))

	// Mirror
	mux.HandleFunc("GET /mirror", a.adminOnly(a.handleMirror))
	mux.HandleFunc("POST /mirror", a.adminOnly(a.handleMirrorCreate))
	mux.HandleFunc("POST /mirror/{id}/delete", a.adminOnly(a.handleMirrorDelete))
	mux.HandleFunc("POST /mirror/{id}/toggle", a.adminOnly(a.handleMirrorToggle))

	// Throttle
	mux.HandleFunc("GET /throttle", a.adminOnly(a.handleThrottle))
	mux.HandleFunc("POST /throttle", a.adminOnly(a.handleThrottleCreate))
	mux.HandleFunc("POST /throttle/{id}/delete", a.adminOnly(a.handleThrottleDelete))
	mux.HandleFunc("POST /throttle/{id}/toggle", a.adminOnly(a.handleThrottleToggle))

	// SSL Decrypt
	mux.HandleFunc("GET /ssl-decrypt", a.adminOnly(a.handleSSLDecrypt))
	mux.HandleFunc("POST /ssl-decrypt", a.adminOnly(a.handleSSLDecryptCreate))
	mux.HandleFunc("POST /ssl-decrypt/{id}/delete", a.adminOnly(a.handleSSLDecryptDelete))
	mux.HandleFunc("POST /ssl-decrypt/{id}/toggle", a.adminOnly(a.handleSSLDecryptToggle))

	// Dedup
	mux.HandleFunc("GET /dedup", a.adminOnly(a.handleDedup))
	mux.HandleFunc("POST /dedup", a.adminOnly(a.handleDedupCreate))
	mux.HandleFunc("POST /dedup/{id}/delete", a.adminOnly(a.handleDedupDelete))
	mux.HandleFunc("POST /dedup/{id}/toggle", a.adminOnly(a.handleDedupToggle))

	// Cluster
	mux.HandleFunc("GET /cluster", a.adminOnly(a.handleCluster))
	mux.HandleFunc("POST /cluster/config", a.adminOnly(a.handleClusterConfig))
	mux.HandleFunc("POST /cluster/regenerate-secret", a.adminOnly(a.handleClusterRegenSecret))

	// Health Checks
	mux.HandleFunc("GET /health-checks", a.adminOnly(a.handleHealthChecks))
	mux.HandleFunc("POST /health-checks", a.adminOnly(a.handleHealthCheckCreate))
	mux.HandleFunc("POST /health-checks/{id}/delete", a.adminOnly(a.handleHealthCheckDelete))
	mux.HandleFunc("POST /health-checks/{id}/toggle", a.adminOnly(a.handleHealthCheckToggle))

	// DPI
	mux.HandleFunc("GET /dpi", a.adminOnly(a.handleDPI))
	mux.HandleFunc("POST /dpi", a.adminOnly(a.handleDPICreate))
	mux.HandleFunc("POST /dpi/{id}/delete", a.adminOnly(a.handleDPIDelete))
	mux.HandleFunc("POST /dpi/{id}/toggle", a.adminOnly(a.handleDPIToggle))

	// Masking
	mux.HandleFunc("GET /masking", a.adminOnly(a.handleMasking))
	mux.HandleFunc("POST /masking", a.adminOnly(a.handleMaskingCreate))
	mux.HandleFunc("POST /masking/{id}/delete", a.adminOnly(a.handleMaskingDelete))
	mux.HandleFunc("POST /masking/{id}/toggle", a.adminOnly(a.handleMaskingToggle))

	// SNMP
	mux.HandleFunc("GET /admin/snmp", a.adminOnly(a.handleSNMP))
	mux.HandleFunc("POST /admin/snmp", a.adminOnly(a.handleSNMPSave))

	// Appliance settings — branding + TLS/FQDN
	mux.HandleFunc("GET /admin/settings", a.adminOnly(a.handleSettings))
	mux.HandleFunc("POST /admin/settings/branding", a.adminOnly(a.handleBrandingSave))
	mux.HandleFunc("POST /admin/settings/logo", a.adminOnly(a.handleLogoUpload))
	mux.HandleFunc("POST /admin/settings/logo/clear", a.adminOnly(a.handleLogoClear))
	mux.HandleFunc("POST /admin/settings/tls", a.adminOnly(a.handleTLSUpload))
	mux.HandleFunc("POST /admin/settings/tls/regen", a.adminOnly(a.handleTLSRegen))
	// Administration guide (in-product HTML)
	mux.HandleFunc("GET /admin/guide", a.handleGuide)
	// Public branding asset (logo) — pre-auth so the login page can show it.
	mux.HandleFunc("GET /static/branding/{name}", a.handleBrandingAsset)

	// Audit
	mux.HandleFunc("GET /admin/audit", a.adminOnly(a.handleAuditLog))

	// Firmware
	mux.HandleFunc("GET /admin/firmware", a.adminOnly(a.handleFirmware))
	mux.HandleFunc("POST /admin/firmware", a.adminOnly(a.handleFirmwareUpload))
	mux.HandleFunc("POST /admin/firmware/rollback", a.adminOnly(a.handleFirmwareRollback))

	// 2FA
	mux.HandleFunc("POST /profile/totp/verify", a.handleTOTPVerify)
	mux.HandleFunc("POST /profile/totp/disable", a.handleTOTPDisable)

	// License
	mux.HandleFunc("GET /admin/license", a.adminOnly(a.handleLicense))
	mux.HandleFunc("POST /admin/license", a.adminOnly(a.handleLicenseUpload))

	// Email
	mux.HandleFunc("GET /admin/mail", a.adminOnly(a.handleMail))
	mux.HandleFunc("POST /admin/mail", a.adminOnly(a.handleMailSave))
	mux.HandleFunc("POST /admin/mail/test", a.adminOnly(a.handleMailTest))

	// Syslog
	mux.HandleFunc("GET /admin/syslog", a.adminOnly(a.handleSyslog))
	mux.HandleFunc("POST /admin/syslog", a.adminOnly(a.handleSyslogSave))
	mux.HandleFunc("POST /admin/syslog/test", a.adminOnly(a.handleSyslogTest))

	// Cluster API (no auth required for node heartbeats)
	mux.HandleFunc("POST /api/cluster/heartbeat", a.handleClusterHeartbeat)
	mux.HandleFunc("GET /api/cluster/nodes", a.handleClusterNodes)

	// JSON APIs
	mux.HandleFunc("GET /api/stats", a.handleAPIStats)
	mux.HandleFunc("GET /api/stats/sparkline", a.handleAPISparklines)
	mux.HandleFunc("GET /api/system", a.handleAPISystem)
	mux.HandleFunc("GET /api/traffic/24h", a.handleAPITraffic24h)
	mux.HandleFunc("GET /api/captures", a.handleAPICaptures)
	mux.HandleFunc("GET /api/alerts/events", a.handleAPIAlertEvents)
	mux.HandleFunc("GET /api/backups", a.handleAPIBackupsList)

	// Middleware chain
	return securityHeaders(a.requireAuth(a.requirePasswordCurrent(a.requireCSRF(mux))))
}

// serve starts background loops and the HTTPS/HTTP listeners, blocking until a
// shutdown signal arrives, then drains gracefully.
func (a *App) serve() {
	a.clusterMgr.Start()
	stopTailer := a.syslogStore.StartTailer(a.logPath)
	handler := a.routes()

	// TLS setup
	certPath := filepath.Join(a.rootDir, "cert.pem")
	keyPath := filepath.Join(a.rootDir, "key.pem")
	tlsCfg, tlsErr := tlsconfig.Load(tlsconfig.Config{
		CertPath: certPath,
		KeyPath:  keyPath,
		AutoCert: true,
	})

	// Graceful shutdown: drain the HTTP server and stop background
	// subsystems / the child broker on SIGINT/SIGTERM, rather than
	// log.Fatal-ing (which calls os.Exit and runs no defers, leaving the
	// child broker and tailers behind).
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Conservative timeouts on every listener close the Slowloris exposure
	// of the zero-value http.Server (no read/write deadlines).
	const readHeaderTimeout = 10 * time.Second

	if tlsErr == nil {
		// HTTPS on :8443, HTTP redirect on :8005
		a.info("Packet Broker UI starting — HTTPS :8443, HTTP redirect :8005")
		redirectSrv := &http.Server{
			Addr: ":8005",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.RequestURI()
				if h, _, err := net.SplitHostPort(r.Host); err == nil {
					target = "https://" + h + ":8443" + r.URL.RequestURI()
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}),
			ReadHeaderTimeout: readHeaderTimeout,
		}
		srv := &http.Server{
			Addr:              ":8443",
			Handler:           handler,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			if err := redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				a.logErr("HTTP redirect listener: " + err.Error())
			}
		}()
		go func() {
			// Empty cert/key args: leave tls.Config.Certificates empty so the
			// hot-reloading GetCertificate callback (tlsCfg) is the sole cert
			// source on EVERY handshake. Passing the paths here would populate
			// Certificates and make GetCertificate fire only for SNI clients —
			// IP-addressed clients (the appliance's primary access) would then
			// keep the start-up cert and never see UI cert uploads/regenerations.
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server: %v", err)
			}
		}()
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = redirectSrv.Shutdown(ctx)
		a.shutdown(stopTailer)
	} else {
		// Fallback: plain HTTP
		a.info("TLS not available (" + tlsErr.Error() + "), starting HTTP on :8005")
		srv := &http.Server{
			Addr:              ":8005",
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server: %v", err)
			}
		}()
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		a.shutdown(stopTailer)
	}
}

// shutdown stops every background subsystem and the child broker. Invoked on
// SIGINT/SIGTERM so goroutines and the spawned data-plane process exit
// cleanly instead of being killed mid-flight. Each Stop is nil-guarded so a
// partially-constructed App (early fatal during wiring) shuts down safely.
func (a *App) shutdown(stopTailer func()) {
	a.info("shutdown: draining subsystems")
	if stopTailer != nil {
		stopTailer()
	}
	if a.clusterMgr != nil {
		a.clusterMgr.Stop()
	}
	if a.healthChecks != nil {
		a.healthChecks.Stop()
	}
	if a.snmpAgent != nil {
		a.snmpAgent.Stop()
	}
	if a.alerts != nil {
		a.alerts.Stop()
	}
	if a.stats != nil {
		a.stats.Stop()
	}
	if a.sysinfo != nil {
		a.sysinfo.Stop()
	}
	if a.logRotator != nil {
		a.logRotator.Stop()
	}
	if a.broker != nil {
		_ = a.broker.Stop()
	}
	a.info("shutdown complete")
}

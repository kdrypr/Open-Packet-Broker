package server

import (
	"net/http"

	"packet_broker/internal/alerts"
	"packet_broker/internal/appcfg"
	"packet_broker/internal/auditlog"
	"packet_broker/internal/auth"
	"packet_broker/internal/backup"
	"packet_broker/internal/capture"
	"packet_broker/internal/cluster"
	"packet_broker/internal/dedup"
	"packet_broker/internal/dpi"
	"packet_broker/internal/firmware"
	"packet_broker/internal/healthcheck"
	"packet_broker/internal/i18n"
	"packet_broker/internal/license"
	"packet_broker/internal/logs"
	"packet_broker/internal/mailer"
	"packet_broker/internal/masking"
	"packet_broker/internal/mirror"
	"packet_broker/internal/portgroup"
	"packet_broker/internal/rules"
	"packet_broker/internal/snmpagent"
	"packet_broker/internal/ssldecrypt"
	pb_syslog "packet_broker/internal/syslog"
	"packet_broker/internal/throttle"
)

// PageData is the bag of values every authenticated template gets. It
// is intentionally a flat struct (rather than per-page subtypes) so the
// shared layout.html sidebar + status pill can read the same fields
// without per-route assembly logic.
type PageData struct {
	ActivePage  string
	Status      string
	DPMode      string // data plane backend: "libpcap" | "afxdp" | "dpdk"
	ProductName string // appliance branding (operator-set; defaults to "Packet Broker")
	LogoURL     string // uploaded logo static URL; "" = built-in icon
	Username    string
	UserRole    string
	IsAdmin     bool
	CSRFToken   string

	// dashboard
	RuleCount    int
	RecentLogs   []logs.Entry
	DefaultAdmin bool

	// system info (dashboard)
	Uptime     string
	CPUPercent float64
	MemPercent float64
	MemTotal   string
	MemUsed    string

	// rules page
	Rules           []rules.Rule
	Interfaces      []string          // data-plane ports offered in pickers (mgmt auto-filtered)
	InterfaceLabels map[string]string // dpdk only: port-id → "port N · PCI"; nil for kernel modes
	MgmtIfaces      []string          // detected management interface(s), for UI banner

	// logs page
	logs.Page

	// user management
	Users []auth.UserInfo

	// captures
	Captures []capture.Session

	// alerts
	AlertRules    []alerts.Rule
	AlertEvents   []alerts.Event
	UnackedAlerts int

	// backups
	Backups []backup.Entry

	// port groups
	PortGroups []portgroup.Group

	// syslog
	SyslogConfig pb_syslog.Config

	// mirror
	MirrorSessions []mirror.Session

	// throttle
	ThrottleConfigs []throttle.Config

	// SSL decrypt
	SSLChains []ssldecrypt.Chain

	// dedup
	DedupConfigs []dedup.Config

	// cluster
	ClusterConfig cluster.Config
	ClusterNodes  []cluster.NodeInfo

	// health checks
	HealthChecks []healthcheck.PortCheck

	// license
	LicenseStatus license.Status

	// mail
	MailConfig mailer.Config

	// audit
	AuditEntries []auditlog.Entry

	// firmware
	FirmwareInfo    firmware.Info
	FirmwareBackups []firmware.Info

	// 2FA
	TOTPEnabled bool
	TOTPSecret  string
	TOTPURI     string

	// DPI
	DPIRules []dpi.Rule
	DPIStats []dpi.DetectionStat

	// Masking
	MaskingRules []masking.Rule

	// SNMP
	SNMPConfig snmpagent.Config

	// appliance settings (branding + identity)
	AppConfig appcfg.Config

	// theme
	Theme string

	// i18n
	Lang string // "en" or "tr"

	// flash messages
	FlashError   string
	FlashSuccess string
}

// LoginData is the (separate) bag for the un-authenticated login page.
type LoginData struct {
	Error        string
	Username     string
	DefaultAdmin bool
	TOTPMode     bool   // when true, render the 2FA challenge instead of credentials
	ProductName  string // branding
	LogoURL      string // branding (uploaded logo); "" = built-in icon
}

// loginBranding returns the product name + logo URL for the un-authenticated
// login/TOTP pages.
func (a *App) loginBranding() (name, logoURL string) {
	name = appcfg.DefaultProductName
	if a.appCfg != nil {
		c := a.appCfg.Get()
		name = c.ProductName
		if c.LogoPath != "" {
			logoURL = "/static/" + c.LogoPath
		}
	}
	return name, logoURL
}

// baseData populates the fields every authenticated page needs.
// Per-handler code calls this then layers on its page-specific values.
func (a *App) baseData(r *http.Request, activePage string) PageData {
	u, _ := a.authStore.SessionUser(r)
	bc := appcfg.Config{ProductName: appcfg.DefaultProductName}
	if a.appCfg != nil {
		bc = a.appCfg.Get()
	}
	logoURL := ""
	if bc.LogoPath != "" {
		logoURL = "/static/" + bc.LogoPath
	}
	d := PageData{
		DPMode:      a.broker.Mode,
		ProductName: bc.ProductName,
		LogoURL:     logoURL,
		MgmtIfaces:  a.MgmtIfaces(),
		ActivePage:  activePage,
		Status:      a.broker.Status(),
		Username:    u.Username,
		UserRole:    u.Role,
		IsAdmin:     u.Role == auth.RoleAdmin,
		CSRFToken:   a.authStore.CSRFToken(r),
		Lang:        i18n.GetLang(r),
	}
	if a.alerts != nil {
		d.UnackedAlerts = a.alerts.UnackedCount()
	}
	return d
}

// Package i18n provides lightweight internationalization (TR/EN).
// No external dependencies — uses a simple map[string]map[string]string.
// Language preference stored in "pb_lang" cookie.
package i18n

import "net/http"

const CookieName = "pb_lang"
const DefaultLang = "en"

// Translate returns the localized string for a key.
func Translate(lang, key string) string {
	if m, ok := translations[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	// Fallback to English
	if v, ok := translations["en"][key]; ok {
		return v
	}
	return key // Return key itself as last resort
}

// GetLang reads language preference from cookie.
func GetLang(r *http.Request) string {
	if c, err := r.Cookie(CookieName); err == nil {
		if c.Value == "tr" || c.Value == "en" {
			return c.Value
		}
	}
	return DefaultLang
}

// SetLang writes language preference cookie.
func SetLang(w http.ResponseWriter, lang string) {
	if lang != "tr" && lang != "en" {
		lang = DefaultLang
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    lang,
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		Secure:   true,
		HttpOnly: false, // JS needs to read this for client-side elements
		SameSite: http.SameSiteLaxMode,
	})
}

// translations holds all UI strings.
var translations = map[string]map[string]string{
	"en": {
		// ── Navigation ──
		"nav.operations":   "Operations",
		"nav.dashboard":    "Dashboard",
		"nav.rules":        "Rules & Topology",
		"nav.logs":         "Logs",
		"nav.captures":     "Captures",
		"nav.network":      "Network",
		"nav.mirror":       "Mirror / SPAN",
		"nav.loadbalance":  "Load Balance",
		"nav.throttle":     "Throttle",
		"nav.dedup":        "Deduplication",
		"nav.ssl":          "SSL Inspection",
		"nav.monitoring":   "Monitoring",
		"nav.alerts":       "Alerts",
		"nav.healthchecks": "Health Checks",
		"nav.system":       "System",
		"nav.cluster":      "Cluster",
		"nav.backups":      "Backups",
		"nav.email":        "Email / SMTP",
		"nav.siem":         "SIEM / Syslog",
		"nav.firmware":     "Firmware",
		"nav.audit":        "Audit Log",
		"nav.license":      "License",
		"nav.users":        "Users",
		"nav.signout":      "Sign out",
		"nav.dpi":          "App Intelligence",
		"nav.masking":      "Packet Masking",
		"nav.snmp":         "SNMP Agent",

		// ── Dashboard ──
		"dash.title":          "Dashboard",
		"dash.subtitle":       "Packet broker control panel",
		"dash.broker_running": "Broker Running",
		"dash.broker_stopped": "Broker Stopped",
		"dash.uptime":         "System Uptime",
		"dash.cpu":            "CPU Usage",
		"dash.memory":         "Memory",
		"dash.rules":          "active rules",
		"dash.live":           "live",
		"dash.offline":        "offline",
		"dash.start":          "Start",
		"dash.stop":           "Stop",
		"dash.live_traffic":   "Live Traffic",
		"dash.port_status":    "Port Status",
		"dash.quick_access":   "Quick Access",
		"dash.recent":         "Recent Activity",
		"dash.view_logs":      "View all logs",
		"dash.processor":      "Processor Usage",
		"dash.loading":        "Loading...",
		"dash.no_port_data":   "No port data (Linux only)",

		// ── Rules ──
		"rules.title":        "Rules & Topology",
		"rules.add_conn":     "Add Connection",
		"rules.manual":       "Manual",
		"rules.drag_hint":    "Drag port-to-port to connect",
		"rules.click_delete": "Click line to delete",
		"rules.view_only":    "View only",
		"rules.details":      "Rule Details",
		"rules.search":       "Search rules...",
		"rules.no_rules":     "No rules configured yet.",
		"rules.create_hint":  "Click Add Connection above to create one.",
		"rules.new_conn":     "New Connection",
		"rules.create":       "Create Connection",
		"rules.delete_title": "Delete Connection",
		"rules.delete_msg":   "Are you sure you want to remove this rule? This action cannot be undone.",

		// ── Common ──
		"common.save":      "Save Configuration",
		"common.cancel":    "Cancel",
		"common.delete":    "Delete",
		"common.enable":    "Enable",
		"common.disable":   "Disable",
		"common.enabled":   "Enabled",
		"common.disabled":  "Disabled",
		"common.create":    "Create",
		"common.upload":    "Upload",
		"common.download":  "Download",
		"common.test":      "Test",
		"common.status":    "Status",
		"common.actions":   "Actions",
		"common.name":      "Name",
		"common.port":      "Port",
		"common.active":    "Active",
		"common.inactive":  "Inactive",
		"common.none":      "None",
		"common.all":       "All",
		"common.time":      "Time",
		"common.level":     "Level",
		"common.message":   "Message",
		"common.filter":    "Filter",
		"common.interface": "Interface",
		"common.unlimited": "unlimited",
		"common.never":     "Never",
		"common.online":    "Online",
		"common.offline":   "Offline",
		"common.up":        "UP",
		"common.down":      "DOWN",
		"common.unknown":   "Unknown",

		// ── Auth ──
		"auth.login":        "Sign in",
		"auth.username":     "Username",
		"auth.password":     "Password",
		"auth.default_warn": "Default credentials active (admin / admin). Change your password now.",
		"auth.change_pw":    "Change your password",

		// ── Profile ──
		"profile.title":       "Profile",
		"profile.subtitle":    "Manage your account settings",
		"profile.account":     "Account",
		"profile.change_pw":   "Change Password",
		"profile.current_pw":  "Current Password",
		"profile.new_pw":      "New Password",
		"profile.confirm_pw":  "Confirm Password",
		"profile.update_pw":   "Update Password",
		"profile.2fa":         "Two-Factor Authentication",
		"profile.2fa_active":  "Two-factor authentication is active on your account.",
		"profile.2fa_scan":    "Scan this secret with Google Authenticator or Authy, then enter the 6-digit code to verify.",
		"profile.2fa_secret":  "Secret Key (manual entry)",
		"profile.2fa_code":    "6-Digit Code",
		"profile.2fa_verify":  "Verify & Enable",
		"profile.2fa_disable": "Disable 2FA",

		// ── Alerts ──
		"alerts.title":     "Alerts",
		"alerts.subtitle":  "Threshold monitoring & webhook notifications",
		"alerts.create":    "Create Alert Rule",
		"alerts.rules":     "Alert Rules",
		"alerts.events":    "Recent Events",
		"alerts.metric":    "Metric",
		"alerts.threshold": "Threshold",
		"alerts.operator":  "Operator",
		"alerts.webhook":   "Webhook URL",
		"alerts.ack":       "Acknowledge",

		// ── Captures ──
		"captures.title":     "Packet Capture",
		"captures.subtitle":  "Record traffic with tcpdump",
		"captures.start":     "Start Capture",
		"captures.recording": "Start Recording",
		"captures.sessions":  "Capture Sessions",
		"captures.max_dur":   "Max Duration (sec)",
		"captures.bpf":       "BPF Filter",

		// ── Backups ──
		"backups.title":    "Configuration Backups",
		"backups.subtitle": "Export, import & restore configurations",
		"backups.create":   "Create Backup",
		"backups.import":   "Import Backup",
		"backups.history":  "Backup History",
		"backups.restore":  "Restore",
		"backups.desc":     "Description",

		// ── Syslog ──
		"syslog.title":      "Syslog / SIEM",
		"syslog.subtitle":   "Forward alerts & logs to a remote syslog server (RFC 5424)",
		"syslog.config":     "Syslog Configuration",
		"syslog.test":       "Test Connection",
		"syslog.test_desc":  "Send a test syslog message to verify connectivity with your SIEM.",
		"syslog.send_test":  "Send Test Message",
		"syslog.fwd_alerts": "Forward Alert Events",
		"syslog.fwd_logs":   "Forward Operational Logs",
		"syslog.fwd_opts":   "Forwarding Options",

		// ── License ──
		"license.title":     "License",
		"license.subtitle":  "Hardware-locked license management",
		"license.status":    "License Status",
		"license.install":   "Install License",
		"license.upload":    "Upload & Activate",
		"license.hwid":      "Hardware ID",
		"license.customer":  "Customer",
		"license.type":      "Type",
		"license.features":  "Features",
		"license.max_ports": "Max Ports",
		"license.expiry":    "Expiry",
		"license.days_left": "days left",
		"license.perpetual": "perpetual",

		// ── Users ──
		"users.title":     "User Management",
		"users.subtitle":  "Manage accounts and access levels",
		"users.add":       "Add User",
		"users.role":      "Role",
		"users.admin":     "Admin",
		"users.user":      "User",
		"users.change_pw": "Change Password",
	},

	"tr": {
		// ── Navigasyon ──
		"nav.operations":   "Operasyon",
		"nav.dashboard":    "Kontrol Paneli",
		"nav.rules":        "Kurallar & Topoloji",
		"nav.logs":         "Loglar",
		"nav.captures":     "Yakalama",
		"nav.network":      "Ag",
		"nav.mirror":       "Yansitma / SPAN",
		"nav.loadbalance":  "Yuk Dengeleme",
		"nav.throttle":     "Hiz Siniri",
		"nav.dedup":        "Tekrar Onleme",
		"nav.ssl":          "SSL Denetim",
		"nav.monitoring":   "Izleme",
		"nav.alerts":       "Alarmlar",
		"nav.healthchecks": "Saglik Kontrol",
		"nav.system":       "Sistem",
		"nav.cluster":      "Kume",
		"nav.backups":      "Yedekleme",
		"nav.email":        "E-posta / SMTP",
		"nav.siem":         "SIEM / Syslog",
		"nav.firmware":     "Yazilim",
		"nav.audit":        "Denetim Kaydi",
		"nav.license":      "Lisans",
		"nav.users":        "Kullanicilar",
		"nav.signout":      "Cikis Yap",
		"nav.dpi":          "Uygulama Zekasi",
		"nav.masking":      "Paket Maskeleme",
		"nav.snmp":         "SNMP Ajan",

		// ── Kontrol Paneli ──
		"dash.title":          "Kontrol Paneli",
		"dash.subtitle":       "Paket broker yonetim ekrani",
		"dash.broker_running": "Broker Calisiyor",
		"dash.broker_stopped": "Broker Durdu",
		"dash.uptime":         "Sistem Calisma Suresi",
		"dash.cpu":            "CPU Kullanimi",
		"dash.memory":         "Bellek",
		"dash.rules":          "aktif kural",
		"dash.live":           "canli",
		"dash.offline":        "cevrimdisi",
		"dash.start":          "Baslat",
		"dash.stop":           "Durdur",
		"dash.live_traffic":   "Canli Trafik",
		"dash.port_status":    "Port Durumu",
		"dash.quick_access":   "Hizli Erisim",
		"dash.recent":         "Son Aktivite",
		"dash.view_logs":      "Tum loglari gor",
		"dash.processor":      "Islemci Kullanimi",
		"dash.loading":        "Yukleniyor...",
		"dash.no_port_data":   "Port verisi yok (sadece Linux)",

		// ── Kurallar ──
		"rules.title":        "Kurallar & Topoloji",
		"rules.add_conn":     "Baglanti Ekle",
		"rules.manual":       "Manuel",
		"rules.drag_hint":    "Baglamak icin portu surukle-birak",
		"rules.click_delete": "Silmek icin cizgiye tikla",
		"rules.view_only":    "Salt okunur",
		"rules.details":      "Kural Detaylari",
		"rules.search":       "Kural ara...",
		"rules.no_rules":     "Henuz kural tanimlanmadi.",
		"rules.create_hint":  "Olusturmak icin yukardaki Baglanti Ekle'ye tiklayin.",
		"rules.new_conn":     "Yeni Baglanti",
		"rules.create":       "Baglanti Olustur",
		"rules.delete_title": "Baglantiyi Sil",
		"rules.delete_msg":   "Bu kurali silmek istediginize emin misiniz? Bu islem geri alinamaz.",

		// ── Genel ──
		"common.save":      "Yapilandirmayi Kaydet",
		"common.cancel":    "Iptal",
		"common.delete":    "Sil",
		"common.enable":    "Etkinlestir",
		"common.disable":   "Devre Disi Birak",
		"common.enabled":   "Etkin",
		"common.disabled":  "Devre Disi",
		"common.create":    "Olustur",
		"common.upload":    "Yukle",
		"common.download":  "Indir",
		"common.test":      "Test",
		"common.status":    "Durum",
		"common.actions":   "Islemler",
		"common.name":      "Ad",
		"common.port":      "Port",
		"common.active":    "Aktif",
		"common.inactive":  "Pasif",
		"common.none":      "Yok",
		"common.all":       "Tumu",
		"common.time":      "Zaman",
		"common.level":     "Seviye",
		"common.message":   "Mesaj",
		"common.filter":    "Filtre",
		"common.interface": "Arayuz",
		"common.unlimited": "sinirsiz",
		"common.never":     "Hicbir zaman",
		"common.online":    "Cevrimici",
		"common.offline":   "Cevrimdisi",
		"common.up":        "YUKARI",
		"common.down":      "ASAGI",
		"common.unknown":   "Bilinmiyor",

		// ── Giris ──
		"auth.login":        "Giris Yap",
		"auth.username":     "Kullanici Adi",
		"auth.password":     "Sifre",
		"auth.default_warn": "Varsayilan kimlik bilgileri aktif (admin / admin). Sifrenizi hemen degistirin.",
		"auth.change_pw":    "Sifrenizi degistirin",

		// ── Profil ──
		"profile.title":       "Profil",
		"profile.subtitle":    "Hesap ayarlarinizi yonetin",
		"profile.account":     "Hesap",
		"profile.change_pw":   "Sifre Degistir",
		"profile.current_pw":  "Mevcut Sifre",
		"profile.new_pw":      "Yeni Sifre",
		"profile.confirm_pw":  "Sifre Tekrar",
		"profile.update_pw":   "Sifreyi Guncelle",
		"profile.2fa":         "Iki Faktorlu Dogrulama",
		"profile.2fa_active":  "Hesabinizda iki faktorlu dogrulama aktif.",
		"profile.2fa_scan":    "Bu gizli anahtari Google Authenticator veya Authy ile tarayin, ardindan 6 haneli kodu girin.",
		"profile.2fa_secret":  "Gizli Anahtar (manuel giris)",
		"profile.2fa_code":    "6 Haneli Kod",
		"profile.2fa_verify":  "Dogrula ve Etkinlestir",
		"profile.2fa_disable": "2FA'yi Devre Disi Birak",

		// ── Alarmlar ──
		"alerts.title":     "Alarmlar",
		"alerts.subtitle":  "Esik izleme ve webhook bildirimleri",
		"alerts.create":    "Alarm Kurali Olustur",
		"alerts.rules":     "Alarm Kurallari",
		"alerts.events":    "Son Olaylar",
		"alerts.metric":    "Metrik",
		"alerts.threshold": "Esik Deger",
		"alerts.operator":  "Operator",
		"alerts.webhook":   "Webhook URL",
		"alerts.ack":       "Onayla",

		// ── Yakalama ──
		"captures.title":     "Paket Yakalama",
		"captures.subtitle":  "tcpdump ile trafik kaydi",
		"captures.start":     "Yakalama Baslat",
		"captures.recording": "Kaydi Baslat",
		"captures.sessions":  "Yakalama Oturumlari",
		"captures.max_dur":   "Maks Sure (sn)",
		"captures.bpf":       "BPF Filtresi",

		// ── Yedekleme ──
		"backups.title":    "Yapilandirma Yedekleri",
		"backups.subtitle": "Yapilandirmalari disa aktar, ice aktar ve geri yukle",
		"backups.create":   "Yedek Olustur",
		"backups.import":   "Yedek Iceri Aktar",
		"backups.history":  "Yedek Gecmisi",
		"backups.restore":  "Geri Yukle",
		"backups.desc":     "Aciklama",

		// ── Syslog ──
		"syslog.title":      "Syslog / SIEM",
		"syslog.subtitle":   "Alarm ve loglari uzak syslog sunucusuna ilet (RFC 5424)",
		"syslog.config":     "Syslog Yapilandirmasi",
		"syslog.test":       "Baglanti Testi",
		"syslog.test_desc":  "SIEM'inize baglantiyi dogrulamak icin test mesaji gonderin.",
		"syslog.send_test":  "Test Mesaji Gonder",
		"syslog.fwd_alerts": "Alarm Olaylarini Ilet",
		"syslog.fwd_logs":   "Operasyonel Loglari Ilet",
		"syslog.fwd_opts":   "Iletim Secenekleri",

		// ── Lisans ──
		"license.title":     "Lisans",
		"license.subtitle":  "Donanima kilitli lisans yonetimi",
		"license.status":    "Lisans Durumu",
		"license.install":   "Lisans Yukle",
		"license.upload":    "Yukle ve Etkinlestir",
		"license.hwid":      "Donanim Kimlik No",
		"license.customer":  "Musteri",
		"license.type":      "Tip",
		"license.features":  "Ozellikler",
		"license.max_ports": "Maks Port",
		"license.expiry":    "Son Kullanma",
		"license.days_left": "gun kaldi",
		"license.perpetual": "suresiz",

		// ── Kullanicilar ──
		"users.title":     "Kullanici Yonetimi",
		"users.subtitle":  "Hesaplari ve erisim duzeylerini yonetin",
		"users.add":       "Kullanici Ekle",
		"users.role":      "Rol",
		"users.admin":     "Yonetici",
		"users.user":      "Kullanici",
		"users.change_pw": "Sifre Degistir",
	},
}

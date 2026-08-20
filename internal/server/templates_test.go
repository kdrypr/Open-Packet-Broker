package server

import (
	"html/template"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"packet_broker/internal/appcfg"
)

// repoTemplates parses the shipped templates the way newApp does, so a broken
// action or a field renamed out from under a page fails here instead of at
// runtime on an appliance.
func repoTemplates(t *testing.T) *template.Template {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "templates")
	tmpl, err := template.New("").Funcs(templateFuncs()).ParseGlob(filepath.Join(dir, "*.html"))
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	return tmpl
}

func TestSettingsPageRendersAutoStart(t *testing.T) {
	tmpl := repoTemplates(t)

	data := PageData{
		ActivePage: "settings",
		Status:     "stopped",
		Lang:       "en",
		IsAdmin:    true,
		AppConfig: appcfg.Config{
			ProductName:  appcfg.DefaultProductName,
			AutoStart:    appcfg.AutoStartAlways,
			DesiredState: appcfg.StateRunning,
		},
		AutoStart:       appcfg.AutoStartAlways,
		AutoStartLocked: true,
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "settings.html", data); err != nil {
		t.Fatalf("render settings.html: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`action="/admin/settings/autostart"`,
		`name="auto_start"`,
		`value="always" selected`,
		"PB_AUTOSTART",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}
}

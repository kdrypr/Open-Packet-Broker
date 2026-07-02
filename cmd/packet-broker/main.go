// Command packet-broker is the appliance's UI + control-plane binary.
//
// Normally it just starts the server (server.Run()). For appliance
// provisioning it also accepts:
//
//	packet_broker_ui -set-admin-password '<pw>' [-root /opt/packet-broker]
//
// which creates/updates the web UI admin account and exits — used by the
// first-boot wizard so the operator sets the UI password at install time.
//
// Build:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
//	    go build -ldflags="-s -w" -o packet_broker_ui ./cmd/packet-broker
package main

import (
	"flag"
	"fmt"
	"os"

	"packet_broker/internal/server"
)

func main() {
	var setPw, rootDir string
	flag.StringVar(&setPw, "set-admin-password", "", "set the web UI admin password and exit (provisioning)")
	flag.StringVar(&rootDir, "root", "", "appliance data dir (default: current directory)")
	flag.Parse()

	if setPw != "" {
		if err := server.SetAdminPassword(rootDir, setPw); err != nil {
			fmt.Fprintln(os.Stderr, "set-admin-password:", err)
			os.Exit(1)
		}
		fmt.Println("web UI admin password updated")
		return
	}

	server.Run()
}

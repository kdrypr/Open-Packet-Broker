// keygen — Offline tool for generating license keys.
//
// Usage:
//
//	go run cmd/keygen/main.go -generate-keys          # create key pair
//	go run cmd/keygen/main.go -sign                    # sign a license
//	go run cmd/keygen/main.go -hwid                    # show this machine's hardware ID
//
// Examples:
//
//	# Generate vendor key pair (do once, keep private key SECRET):
//	go run cmd/keygen/main.go -generate-keys
//
//	# Create a license for a customer:
//	go run cmd/keygen/main.go -sign \
//	  -privkey "hex_private_key" \
//	  -hwid "customer_hardware_id" \
//	  -customer "ACME Corp" \
//	  -type enterprise \
//	  -features "all" \
//	  -ports 24 \
//	  -expiry "2027-01-01" \
//	  -out license.key
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"packet_broker/internal/license"
)

func main() {
	genKeys := flag.Bool("generate-keys", false, "Generate a new Ed25519 key pair")
	sign := flag.Bool("sign", false, "Sign a license")
	signFirmware := flag.Bool("sign-firmware", false, "Sign a firmware ELF binary")
	showHWID := flag.Bool("hwid", false, "Show this machine's hardware ID")

	// Sign flags (shared by license + firmware modes)
	privKeyHex := flag.String("privkey", "", "Private key (hex)")
	inFile := flag.String("in", "", "Input ELF file (for -sign-firmware)")
	hwid := flag.String("hardware-id", "", "Target hardware ID")
	customer := flag.String("customer", "", "Customer name")
	licType := flag.String("type", "enterprise", "License type: trial, standard, enterprise")
	features := flag.String("features", "all", "Comma-separated features or 'all'")
	maxPorts := flag.Int("ports", 0, "Max ports (0=unlimited)")
	expiry := flag.String("expiry", "perpetual", "Expiry date YYYY-MM-DD or 'perpetual'")
	outFile := flag.String("out", "license.key", "Output file path")

	flag.Parse()

	if *showHWID {
		fmt.Println("Hardware ID:", license.GenerateHardwareID())
		return
	}

	if *genKeys {
		pub, priv, err := license.GenerateKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("=== Ed25519 Key Pair ===")
		fmt.Println()
		fmt.Println("PUBLIC KEY (embed in license.go vendorPubKeyHex):")
		fmt.Println(pub)
		fmt.Println()
		fmt.Println("PRIVATE KEY (keep SECRET, use for signing):")
		fmt.Println(priv)
		fmt.Println()
		fmt.Println("Save the private key securely. It cannot be recovered.")
		return
	}

	if *sign {
		if *privKeyHex == "" {
			fmt.Fprintln(os.Stderr, "Error: -privkey is required")
			os.Exit(1)
		}
		privBytes, err := hex.DecodeString(*privKeyHex)
		if err != nil || len(privBytes) != ed25519.PrivateKeySize {
			fmt.Fprintln(os.Stderr, "Error: invalid private key (must be 128 hex chars / 64 bytes)")
			os.Exit(1)
		}

		var featureList []string
		for _, f := range strings.Split(*features, ",") {
			if t := strings.TrimSpace(f); t != "" {
				featureList = append(featureList, t)
			}
		}

		lic := license.License{
			HardwareID: *hwid,
			Customer:   *customer,
			Expiry:     *expiry,
			Features:   featureList,
			MaxPorts:   *maxPorts,
			Type:       *licType,
		}

		data, err := license.GenerateLicense(ed25519.PrivateKey(privBytes), lic)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(*outFile, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}

		// Pretty print
		var pretty json.RawMessage
		json.Unmarshal(data, &pretty)
		fmt.Printf("License written to: %s\n", *outFile)
		fmt.Printf("Customer: %s\n", *customer)
		fmt.Printf("Type: %s\n", *licType)
		fmt.Printf("Hardware: %s\n", *hwid)
		fmt.Printf("Features: %v\n", featureList)
		fmt.Printf("Expiry: %s\n", *expiry)
		return
	}

	if *signFirmware {
		if *privKeyHex == "" || *inFile == "" {
			fmt.Fprintln(os.Stderr, "Error: -privkey and -in are required for -sign-firmware")
			os.Exit(1)
		}
		privBytes, err := hex.DecodeString(*privKeyHex)
		if err != nil || len(privBytes) != ed25519.PrivateKeySize {
			fmt.Fprintln(os.Stderr, "Error: invalid private key (must be 128 hex chars / 64 bytes)")
			os.Exit(1)
		}
		elf, err := os.ReadFile(*inFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", *inFile, err)
			os.Exit(1)
		}
		if len(elf) < 4 || string(elf[:4]) != "\x7fELF" {
			fmt.Fprintln(os.Stderr, "Error: input is not an ELF executable")
			os.Exit(1)
		}
		sum := sha256.Sum256(elf)
		sig := ed25519.Sign(ed25519.PrivateKey(privBytes), sum[:])

		// Bundle: [4-byte BE sigLen][sig][elf]
		out := *outFile
		if out == "license.key" {
			out = *inFile + ".signed"
		}
		bundle := make([]byte, 0, 4+len(sig)+len(elf))
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(sig)))
		bundle = append(bundle, hdr[:]...)
		bundle = append(bundle, sig...)
		bundle = append(bundle, elf...)
		if err := os.WriteFile(out, bundle, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", out, err)
			os.Exit(1)
		}
		fmt.Printf("Signed firmware bundle written to: %s\n", out)
		fmt.Printf("ELF size: %d bytes\n", len(elf))
		fmt.Printf("SHA-256:  %x\n", sum)
		return
	}

	flag.Usage()
}

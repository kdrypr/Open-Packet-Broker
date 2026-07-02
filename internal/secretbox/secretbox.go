// Package secretbox provides optional authenticated encryption for secrets at
// rest (connector credentials in the bbolt stores). It is opt-in: when the
// environment variable PB_SECRET_KEY holds a 64-char hex (32-byte) key,
// Seal/Open use AES-256-GCM; otherwise they pass data through unchanged so the
// system keeps working with the legacy plaintext format. Open transparently
// reads BOTH encrypted and legacy-plaintext values, so enabling a key is a
// zero-downtime migration (old rows decode, new writes are encrypted).
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
)

// magic marks a Seal'd value so Open can distinguish it from legacy plaintext.
var magic = []byte("NESB1\x00")

var (
	once sync.Once
	aead cipher.AEAD // nil => encryption disabled (passthrough)
)

func load() {
	raw := os.Getenv("PB_SECRET_KEY")
	if raw == "" {
		return
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return // misconfigured key => stay in passthrough rather than crash
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	aead = g
}

// Enabled reports whether a valid key is configured.
func Enabled() bool {
	once.Do(load)
	return aead != nil
}

// Seal encrypts plain when a key is configured; otherwise returns it unchanged.
func Seal(plain []byte) []byte {
	once.Do(load)
	if aead == nil {
		return plain
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plain // never block a write on RNG failure
	}
	out := append([]byte{}, magic...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plain, nil)
}

// Open decrypts a Seal'd value, or returns legacy plaintext unchanged.
func Open(data []byte) ([]byte, error) {
	once.Do(load)
	if len(data) < len(magic) || string(data[:len(magic)]) != string(magic) {
		return data, nil // legacy plaintext
	}
	if aead == nil {
		return nil, errors.New("secretbox: encrypted value but no PB_SECRET_KEY configured")
	}
	body := data[len(magic):]
	ns := aead.NonceSize()
	if len(body) < ns {
		return nil, errors.New("secretbox: short ciphertext")
	}
	return aead.Open(nil, body[:ns], body[ns:], nil)
}

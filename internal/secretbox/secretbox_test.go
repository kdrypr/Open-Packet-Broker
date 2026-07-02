package secretbox

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	t.Setenv("PB_SECRET_KEY", hex.EncodeToString(key))
	pt := []byte(`{"api_key":"s3cr3t","host":"fw"}`)
	ct := Seal(pt)
	if bytes.Equal(ct, pt) {
		t.Fatal("expected ciphertext to differ from plaintext")
	}
	got, err := Open(ct)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("roundtrip failed: %v %q", err, got)
	}
	if g, err := Open(pt); err != nil || !bytes.Equal(g, pt) {
		t.Fatalf("legacy plaintext should pass through: %v", err)
	}
}

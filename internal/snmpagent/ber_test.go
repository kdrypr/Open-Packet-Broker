package snmpagent

import (
	"testing"
	"time"
)

// buildGet crafts a minimal SNMPv2c GET request for one OID.
func buildGet(community, oid string, pduTag byte) []byte {
	vb := enc(tagSequence, append(enc(tagOID, encodeOID(oid)), enc(tagNull, nil)...))
	pdu := append([]byte{}, encInt(tagInteger, 12345)...) // request-id
	pdu = append(pdu, encInt(tagInteger, 0)...)           // error-status
	pdu = append(pdu, encInt(tagInteger, 0)...)           // error-index
	pdu = append(pdu, enc(tagSequence, vb)...)            // varbinds
	body := append([]byte{}, encInt(tagInteger, 1)...)    // version v2c
	body = append(body, enc(tagOctetStr, []byte(community))...)
	body = append(body, enc(pduTag, pdu)...)
	return enc(tagSequence, body)
}

func testStore() *Store {
	return &Store{provider: &DataProvider{
		GetBrokerStatus: func() string { return "running" },
		GetRuleCount:    func() int { return 7 },
		GetCPUPercent:   func() float64 { return 42 },
		GetMemPercent:   func() float64 { return 55 },
		GetAlertCount:   func() int { return 3 },
		GetUptime:       func() time.Duration { return 90 * time.Second },
	}}
}

func TestHandleSNMP_GetSysDescr(t *testing.T) {
	s := testStore()
	cfg := Config{Community: "public", Location: "Rack 1", Contact: "ops@x"}
	resp := s.handleSNMP(buildGet("public", "1.3.6.1.2.1.1.1.0", tagGetReq), cfg)
	if resp == nil {
		t.Fatal("nil response to valid GET")
	}
	// outer SEQUENCE → version, community, GetResponse PDU
	tag, body, _, ok := tlv(resp)
	if !ok || tag != tagSequence {
		t.Fatalf("bad outer tag %#x", tag)
	}
	_, _, r1, _ := tlv(body)   // version
	ct, comm, r2, _ := tlv(r1) // community
	if ct != tagOctetStr || string(comm) != "public" {
		t.Fatalf("community mismatch: %q", comm)
	}
	pt, pdu, _, _ := tlv(r2)
	if pt != tagGetResp {
		t.Fatalf("expected GET-RESPONSE, got %#x", pt)
	}
	// walk to varbinds and confirm the value is our sysDescr octet string
	_, _, p1, _ := tlv(pdu) // request-id
	_, _, p2, _ := tlv(p1)  // error-status
	_, _, p3, _ := tlv(p2)  // error-index
	_, vbList, _, _ := tlv(p3)
	_, vb, _, _ := tlv(vbList)
	ot, oidB, after, _ := tlv(vb)
	if ot != tagOID || parseOID(oidB) != "1.3.6.1.2.1.1.1.0" {
		t.Fatalf("response OID wrong: %s", parseOID(oidB))
	}
	vt, val, _, _ := tlv(after)
	if vt != tagOctetStr || len(val) == 0 {
		t.Fatalf("expected non-empty octet string value, tag=%#x", vt)
	}
}

func TestHandleSNMP_WrongCommunity(t *testing.T) {
	s := testStore()
	cfg := Config{Community: "secret"}
	if resp := s.handleSNMP(buildGet("public", "1.3.6.1.2.1.1.1.0", tagGetReq), cfg); resp != nil {
		t.Fatal("expected nil response for wrong community")
	}
}

func TestHandleSNMP_GetNextWalks(t *testing.T) {
	s := testStore()
	cfg := Config{Community: "public"}
	// GETNEXT from the table root should return the first scalar (sysDescr).
	resp := s.handleSNMP(buildGet("public", "1.3.6.1.2.1.1", tagGetNext), cfg)
	if resp == nil {
		t.Fatal("nil GETNEXT response")
	}
}

func TestOIDRoundTrip(t *testing.T) {
	for _, oid := range []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.99999.5.0"} {
		if got := parseOID(encodeOID(oid)); got != oid {
			t.Fatalf("oid roundtrip %s -> %s", oid, got)
		}
	}
}

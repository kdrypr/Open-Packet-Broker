package snmpagent

import (
	"sort"
	"strconv"
	"strings"
)

// Minimal ASN.1 BER codec for an SNMPv2c GET / GETNEXT responder. Just enough to
// answer the scalar OIDs monitoring tools (Zabbix/Nagios/PRTG, snmpget/snmpwalk)
// poll — no SET, no tables, no v3.

const (
	tagInteger   = 0x02
	tagOctetStr  = 0x04
	tagNull      = 0x05
	tagOID       = 0x06
	tagSequence  = 0x30
	tagGetReq    = 0xA0
	tagGetNext   = 0xA1
	tagGetResp   = 0xA2
	tagGauge32   = 0x42
	tagTimeTicks = 0x43

	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82
)

// tlv splits one BER element off the front of b, returning its tag, content, and
// the remaining bytes. ok=false on a malformed/short element.
func tlv(b []byte) (tag byte, content, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	l := int(b[1])
	i := 2
	if l&0x80 != 0 { // long form
		nb := l & 0x7f
		if nb == 0 || nb > 4 || len(b) < 2+nb {
			return 0, nil, nil, false
		}
		l = 0
		for j := 0; j < nb; j++ {
			l = l<<8 | int(b[2+j])
		}
		i = 2 + nb
	}
	if len(b) < i+l {
		return 0, nil, nil, false
	}
	return tag, b[i : i+l], b[i+l:], true
}

// encodeLen renders a BER length (short form < 128, else long form).
func encodeLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0xff)}, tmp...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(tmp))}, tmp...)
}

// enc wraps content in a tag+length envelope.
func enc(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, encodeLen(len(content))...)
	return append(out, content...)
}

func encInt(tag byte, v int) []byte {
	if v == 0 {
		return enc(tag, []byte{0})
	}
	var b []byte
	n := v
	neg := n < 0
	for {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
		if n == 0 || n == -1 {
			break
		}
	}
	// ensure sign bit correctness for positive values
	if !neg && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return enc(tag, b)
}

// parseOID decodes BER OID content into dotted-string form.
func parseOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []string{strconv.Itoa(int(b[0]) / 40), strconv.Itoa(int(b[0]) % 40)}
	var v int
	for _, c := range b[1:] {
		v = v<<7 | int(c&0x7f)
		if c&0x80 == 0 {
			parts = append(parts, strconv.Itoa(v))
			v = 0
		}
	}
	return strings.Join(parts, ".")
}

// encodeOID encodes a dotted OID string into BER content bytes.
func encodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil
	}
	nums := make([]int, len(parts))
	for i, p := range parts {
		nums[i], _ = strconv.Atoi(p)
	}
	out := []byte{byte(nums[0]*40 + nums[1])}
	for _, n := range nums[2:] {
		out = append(out, base128(n)...)
	}
	return out
}

func base128(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0x7f)}, b...)
		n >>= 7
	}
	for i := 0; i < len(b)-1; i++ {
		b[i] |= 0x80
	}
	return b
}

// oidLess compares two dotted OIDs lexicographically by numeric component.
func oidLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, _ := strconv.Atoi(as[i])
		y, _ := strconv.Atoi(bs[i])
		if x != y {
			return x < y
		}
	}
	return len(as) < len(bs)
}

// varbind is one OID → typed value in the MIB.
type varbind struct {
	oid   string
	value []byte // already BER-encoded (tag+len+content)
}

func vbInt(oid string, tag byte, v int) varbind { return varbind{oid, encInt(tag, v)} }
func vbStr(oid, s string) varbind               { return varbind{oid, enc(tagOctetStr, []byte(s))} }

// sortMIB orders varbinds by OID so GETNEXT walks correctly.
func sortMIB(mib []varbind) {
	sort.Slice(mib, func(i, j int) bool { return oidLess(mib[i].oid, mib[j].oid) })
}

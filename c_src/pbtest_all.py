#!/usr/bin/env python3
# Comprehensive packet-broker feature test orchestrator (runs as root).
# Single process: per test it (re)writes rules.conf/dedup.conf/dpi.conf, restarts
# the broker, opens the recv socket(s) BEFORE injecting (no missed frames), injects
# crafted L2 frames on the veth, counts forwarded markers, asserts, prints one JSON.
import socket, struct, time, json, subprocess, os, select, sys

PB = '/tmp/pbtest'
os.chdir(PB)
BIN = './packet_broker'

# Linux strips the 802.1Q tag off the frame bytes on receive and moves it into
# a PACKET_AUXDATA cmsg, so d[12:14] won't show 0x8100 even for a tagged frame.
# Read the tag from aux data instead — the authoritative source.
SOL_PACKET = getattr(socket, 'SOL_PACKET', 263)
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4  # 0x10
_AUX = struct.Struct('=IIIHHHH')  # tpacket_auxdata: status,len,snaplen,mac,net,vlan_tci,vlan_tpid

def aux_vlan(ancdata):
    """Return vlan id from a recvmsg ancillary list, or None if untagged."""
    for lvl, typ, data in ancdata:
        if lvl == SOL_PACKET and typ == PACKET_AUXDATA and len(data) >= _AUX.size:
            st = _AUX.unpack(data[:_AUX.size])
            if st[0] & TP_STATUS_VLAN_VALID:
                return st[5] & 0xFFF
    return None

SMAC = b'\x02\x00\x00\x00\x00\x01'
DMAC = b'\x02\x00\x00\x00\x00\x02'

def tflags(s):
    m = {'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16, 'U': 32}
    f = 0
    for c in s:
        f |= m.get(c, 0)
    return f

def craft(proto, dport, flags='-', payload='', sip='10.1.1.1', dip='10.1.1.2', vlan=None):
    pl = payload.encode() if isinstance(payload, str) else payload
    if proto == 'tcp':
        l4 = struct.pack('!HHIIBBHHH', 1234, dport, 0, 0, 5 << 4, tflags(flags), 8192, 0, 0) + pl
        ipp = 6
    elif proto == 'udp':
        l4 = struct.pack('!HHHH', 1234, dport, 8 + len(pl), 0) + pl
        ipp = 17
    else:
        l4 = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + pl
        ipp = 1
    tot = 20 + len(l4)
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, 0x1234, 0, 64, ipp, 0,
                      socket.inet_aton(sip), socket.inet_aton(dip))
    if vlan is not None:
        l2 = DMAC + SMAC + struct.pack('!HH', 0x8100, vlan & 0xFFF) + struct.pack('!H', 0x0800)
    else:
        l2 = DMAC + SMAC + struct.pack('!H', 0x0800)
    return l2 + iph + l4

def write_conf(name, text):
    p = os.path.join(PB, name)
    if text is None:
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    else:
        with open(p, 'w') as f:
            f.write(text + '\n')

_proc = None
def restart(rules, dedup=None, dpi=None):
    global _proc
    subprocess.run(['pkill', '-f', BIN[2:]], stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    write_conf('rules.conf', rules)
    write_conf('dedup.conf', dedup)
    write_conf('dpi.conf', dpi)
    _proc = subprocess.Popen([BIN], stdout=open(os.path.join(PB, 'pb.log'), 'a'),
                             stderr=subprocess.STDOUT)
    time.sleep(1.4)

def trial(rules, sends, recv_ifaces=('pbout1',), markers=(), secs=2.2, inject_at=0.5,
          dedup=None, dpi=None):
    """sends: list of (iface, frame_bytes, count). Returns per-iface stats."""
    restart(rules, dedup, dpi)
    socks = {}
    for ifc in recv_ifaces:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((ifc, 0))
        s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        s.setblocking(False)
        socks[s.fileno()] = (ifc, s)
    stats = {ifc: {'total': 0, 'counts': {m: 0 for m in markers}, 'minlen': 0,
                   'maxlen': 0, 'vlan': 0, 'vids': [], 'lens': []} for ifc in recv_ifaces}
    injected = False
    t0 = time.time()
    while time.time() - t0 < secs:
        if not injected and time.time() - t0 >= inject_at:
            for iface, frame, cnt in sends:
                ss = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                ss.bind((iface, 0))
                for _ in range(cnt):
                    ss.send(frame)
                ss.close()
            injected = True
        r, _, _ = select.select([s for _, s in socks.values()], [], [], 0.2)
        for s in r:
            try:
                d, ancdata, _, _ = s.recvmsg(65535, socket.CMSG_SPACE(64))
            except (BlockingIOError, OSError):
                continue
            ifc, _ = socks[s.fileno()]
            st = stats[ifc]
            st['total'] += 1
            st['lens'].append(len(d))
            vid = aux_vlan(ancdata)
            if vid is None and len(d) >= 14 and d[12:14] == b'\x81\x00':
                vid = struct.unpack('!H', d[14:16])[0] & 0xFFF  # tag in-band (offload off)
            if vid is not None:
                st['vlan'] += 1
                st['vids'].append(vid)
            for m in markers:
                if m and m.encode() in d:
                    st['counts'][m] += 1
    for ifc, st in stats.items():
        st['minlen'] = min(st['lens']) if st['lens'] else 0
        st['maxlen'] = max(st['lens']) if st['lens'] else 0
        st['vids'] = sorted(set(st['vids']))
        del st['lens']
    for _, s in socks.values():
        s.close()
    return stats

# ── Test definitions ──────────────────────────────────────────────────────
results = []
def check(name, ok, detail):
    results.append({'name': name, 'pass': bool(ok), 'detail': detail})

def C(out):
    return out['pbout1']['counts']

# T1 port filter
o = trial("pbin1,0,80,0,0,0,0,pbout0",
          [('pbin0', craft('udp', 80, payload='M80'), 4),
           ('pbin0', craft('udp', 99, payload='M99'), 4)],
          markers=('M80', 'M99'))
c = C(o); check('port-filter :80', c['M80'] == 4 and c['M99'] == 0, c)

# T2 protocol filter (UDP only)
o = trial("pbin1,0,0,UDP,0,0,0,pbout0",
          [('pbin0', craft('udp', 1234, payload='MU'), 4),
           ('pbin0', craft('tcp', 1234, 'PA', payload='MT'), 4)],
          markers=('MU', 'MT'))
c = C(o); check('proto-filter UDP', c['MU'] == 4 and c['MT'] == 0, c)

# T3 string match
o = trial("pbin1,0,0,0,0,SECRET,0,pbout0",
          [('pbin0', craft('udp', 1, payload='SECRETyes_MSY'), 4),
           ('pbin0', craft('udp', 1, payload='nope_MSN'), 4)],
          markers=('MSY', 'MSN'))
c = C(o); check('string-match SECRET', c['MSY'] == 4 and c['MSN'] == 0, c)

# T4 tcp flags (SYN only)
o = trial("pbin1,S,0,0,0,0,0,pbout0",
          [('pbin0', craft('tcp', 1, 'S', payload='MSYN'), 4),
           ('pbin0', craft('tcp', 1, 'A', payload='MACK'), 4)],
          markers=('MSYN', 'MACK'))
c = C(o); check('tcp-flag SYN', c['MSYN'] == 4 and c['MACK'] == 0, c)

# T5 exclude (NOT :80)
o = trial("pbin1,0,80,0,0,0,1,pbout0",
          [('pbin0', craft('udp', 80, payload='X80'), 4),
           ('pbin0', craft('udp', 99, payload='X99'), 4)],
          markers=('X80', 'X99'))
c = C(o); check('exclude :80', c['X80'] == 0 and c['X99'] == 4, c)

# T6 VLAN add 100 (untagged in -> tagged 100 out, tag read from aux data)
o = trial("pbin1,0,0,0,0,0,0,pbout0,1,1,add,100",
          [('pbin0', craft('udp', 1, payload='MVADD'), 4)], markers=('MVADD',))
c = C(o); v = o['pbout1']
check('vlan-add 100', c['MVADD'] == 4 and v['vlan'] >= 4 and v['vids'] == [100],
      {'counts': c, 'vlan': v['vlan'], 'vids': v['vids']})

# T7 VLAN remove (input tagged 100 -> output untagged)
o = trial("pbin1,0,0,0,0,0,0,pbout0,1,1,remove,0",
          [('pbin0', craft('udp', 1, payload='MVREM', vlan=100), 4)], markers=('MVREM',))
c = C(o); v = o['pbout1']
check('vlan-remove', c['MVREM'] == 4 and v['vlan'] == 0,
      {'counts': c, 'vlan': v['vlan'], 'vids': v['vids']})

# T8 VLAN change (100 -> 200)
o = trial("pbin1,0,0,0,0,0,0,pbout0,1,1,change,200",
          [('pbin0', craft('udp', 1, payload='MVCHG', vlan=100), 4)], markers=('MVCHG',))
c = C(o); v = o['pbout1']
check('vlan-change 200', c['MVCHG'] == 4 and v['vids'] == [200],
      {'counts': c, 'vlan': v['vlan'], 'vids': v['vids']})

# T9 truncate 40
o = trial("pbin1,0,0,0,0,0,0,pbout0,1,1,none,0,40",
          [('pbin0', craft('udp', 1, payload='MTRUNC' + 'z' * 60), 4)], markers=('MTRUNC',))
v = o['pbout1']
check('truncate 40B', v['total'] >= 4 and v['maxlen'] <= 40,
      {'total': v['total'], 'maxlen': v['maxlen']})

# T10 src-ip filter (10.1.1.1/32 only)
o = trial("pbin1,0,0,0,0,0,0,pbout0,1,1,none,0,0,10.1.1.1/32",
          [('pbin0', craft('udp', 1, payload='MSIPok', sip='10.1.1.1'), 4),
           ('pbin0', craft('udp', 1, payload='MSIPno', sip='10.9.9.9'), 4)],
          markers=('MSIPok', 'MSIPno'))
c = C(o); check('src-ip 10.1.1.1', c['MSIPok'] == 4 and c['MSIPno'] == 0, c)

# T11 dst-ip filter (10.1.1.2/32 only)
o = trial("pbin1,0,0,0,0,0,0,pbout0,1,1,none,0,0,0.0.0.0/0,10.1.1.2/32",
          [('pbin0', craft('udp', 1, payload='MDIPok', dip='10.1.1.2'), 4),
           ('pbin0', craft('udp', 1, payload='MDIPno', dip='10.5.5.5'), 4)],
          markers=('MDIPok', 'MDIPno'))
c = C(o); check('dst-ip 10.1.1.2', c['MDIPok'] == 4 and c['MDIPno'] == 0, c)

# T12 BPF filter ("udp port 53")
o = trial("pbin1,0,0,0,0,0,0,pbout0,1,1,none,0,0,0.0.0.0/0,0.0.0.0/0,,,udp port 53",
          [('pbin0', craft('udp', 53, payload='MBPFok'), 4),
           ('pbin0', craft('udp', 80, payload='MBPFno'), 4)],
          markers=('MBPFok', 'MBPFno'))
c = C(o); check('bpf udp/53', c['MBPFok'] == 4 and c['MBPFno'] == 0, c)

# T13 rate-limit pps=5 (field idx 19): burst 30 -> only ~<=12 forwarded
rl = "pbin1,0,0,0,0,0,0,pbout0,1,1,none,0,0,0.0.0.0/0,0.0.0.0/0,,,,0,5"
o = trial(rl, [('pbin0', craft('udp', 1, payload='MRATE'), 30)], markers=('MRATE',), secs=2.0)
c = C(o); check('rate-limit 5pps', 1 <= c['MRATE'] <= 12,
                {'forwarded_of_30': c['MRATE']})

# T14 dedup (8 identical -> ~1 forwarded)
o = trial("pbin1,0,0,0,0,0,0,pbout0",
          [('pbin0', craft('udp', 1, payload='MDEDUP'), 8)], markers=('MDEDUP',),
          dedup="0,1,200,128")
c = C(o); check('dedup identical', 1 <= c['MDEDUP'] <= 2,
                {'forwarded_of_8': c['MDEDUP']})

# T15 DPI forward (http -> pbmir0, skip normal rule to pbout0)
o = trial("pbin1,0,0,0,0,0,0,pbout0",
          [('pbin0', craft('tcp', 12345, 'PA', payload='GET /x HTTP/1.1\r\nMHTTP\r\n'), 4)],
          recv_ifaces=('pbout1', 'pbmir1'), markers=('MHTTP',),
          dpi="http,forward,pbmir0")
mir = o['pbmir1']['counts']['MHTTP']; main = o['pbout1']['counts']['MHTTP']
check('dpi-forward http->mirror', mir == 4 and main == 0,
      {'mirror': mir, 'main': main})

# T16 DPI drop (dns dropped)
o = trial("pbin1,0,0,0,0,0,0,pbout0",
          [('pbin0', craft('udp', 53, payload='MDNS' + 'x' * 20), 4)],
          markers=('MDNS',), dpi="dns,drop,")
c = C(o); check('dpi-drop dns', c['MDNS'] == 0, {'main': c['MDNS']})

# T17 DPI mirror (http copied to pbmir0 AND continues to pbout0)
o = trial("pbin1,0,0,0,0,0,0,pbout0",
          [('pbin0', craft('tcp', 12345, 'PA', payload='GET /y HTTP/1.1\r\nMMIR\r\n'), 4)],
          recv_ifaces=('pbout1', 'pbmir1'), markers=('MMIR',),
          dpi="http,mirror,pbmir0")
mir = o['pbmir1']['counts']['MMIR']; main = o['pbout1']['counts']['MMIR']
check('dpi-mirror http both', mir == 4 and main == 4, {'mirror': mir, 'main': main})

# T18 load-balance / fan-out: two rules same input, two outputs (pbout0 + pbmir0)
o = trial("pbin1,0,0,0,0,0,0,pbout0\npbin1,0,0,0,0,0,0,pbmir0",
          [('pbin0', craft('udp', 1, payload='MFAN'), 4)],
          recv_ifaces=('pbout1', 'pbmir1'), markers=('MFAN',))
a = o['pbout1']['counts']['MFAN']; b = o['pbmir1']['counts']['MFAN']
check('fan-out 2 outputs', a == 4 and b == 4, {'out': a, 'mir': b})

# cleanup
subprocess.run(['pkill', '-f', BIN[2:]], stderr=subprocess.DEVNULL)

npass = sum(1 for r in results if r['pass'])
print(json.dumps({'pass': npass, 'fail': len(results) - npass, 'tests': results}, indent=1))

#!/usr/bin/env python3
# Broker capture-capacity load test (runs as root).
#
# Answers "at what packet rate does the broker start dropping?" — the concrete
# version of "kurumsal mirror'da çatlar mıyız?". It creates isolated veth pairs,
# runs the libpcap broker capturing one end with a permissive forward rule, blasts
# UDP frames at a sweep of target rates (pbcap_blast), and reads the broker's
# pcap_stats (packet_broker.stats.json — recv / ring-drop) to report the drop% at
# each rate. The first rate with non-trivial drop% is the capture "knee".
#
# This is isolated from any live capture (its own veths, its own broker instance,
# its own work dir) — it does NOT touch the production ens37 broker.
#
# usage: sudo ./pbcap_loadtest.py [--broker ./packet_broker] [--secs 5] [--size 64]
#                                 [--rates 50000,100000,250000,500000,1000000,0]
import argparse, json, os, signal, subprocess, sys, time

WORK = '/tmp/pbcap'
IN0, IN1 = 'lpbin0', 'lpbin1'        # blast on IN0 → broker captures IN1
OUT0, OUT1 = 'lpbout0', 'lpbout1'    # broker forwards to OUT0 → OUT1 drains
RULE = f'{IN1},0,0,0,0,0,0,{OUT0}'   # permissive: forward everything IN1 → OUT0
STATS_INTERVAL = 5                    # must match the broker's STATS_INTERVAL


def sh(cmd, check=False):
    return subprocess.run(cmd, shell=True, check=check,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup_veths():
    for a, b in ((IN0, IN1), (OUT0, OUT1)):
        sh(f'ip link del {a}')
        sh(f'ip link add {a} type veth peer name {b}', check=True)
        for ifc in (a, b):
            sh(f'ip link set {ifc} up')
            # disable offloads so frames aren't coalesced (realistic per-packet load)
            sh(f'ethtool -K {ifc} gro off gso off tso off tx off rx off')


def teardown_veths():
    for a in (IN0, OUT0):
        sh(f'ip link del {a}')


# Stop a broker by its RECORDED PID only — never `pkill -f <name>`, which would
# also match this orchestrator's own argv (it carries the binary path) and could
# even hit the live production broker.
def kill_stale_broker():
    pidf = os.path.join(WORK, 'packet_broker.pid')
    try:
        os.kill(int(open(pidf).read().strip()), signal.SIGTERM)
        time.sleep(0.4)
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        pass


def stop_broker(p):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()


def start_broker(broker_bin):
    kill_stale_broker()
    for f in ('rules.conf', 'packet_broker.log', 'packet_broker.stats.json'):
        try: os.remove(os.path.join(WORK, f))
        except FileNotFoundError: pass
    with open(os.path.join(WORK, 'rules.conf'), 'w') as fh:
        fh.write(RULE + '\n')
    p = subprocess.Popen([os.path.abspath(broker_bin)], cwd=WORK,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # wait for the capture thread to attach to IN1
    log = os.path.join(WORK, 'packet_broker.log')
    for _ in range(30):
        time.sleep(0.2)
        try:
            if f'Capture thread started for {IN1}' in open(log).read():
                return p
        except FileNotFoundError:
            pass
    return p  # proceed anyway; stats will reveal if capture never started


def read_stats():
    try:
        s = json.load(open(os.path.join(WORK, 'packet_broker.stats.json')))
        ifc = s.get('ifaces', {}).get(IN1, {})
        return ifc.get('rx_pkts', 0), ifc.get('rx_drop', 0)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0, 0


def run_rate(broker_bin, blast_bin, pps, secs, size):
    p = start_broker(broker_bin)
    cmd = [os.path.abspath(blast_bin), IN0, str(size), str(secs)]
    if pps:
        cmd.append(str(pps))
    out = subprocess.run(cmd, capture_output=True, text=True)
    try:
        blast = json.loads(out.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        blast = {'sent': 0, 'pps': 0}
    # let the broker flush its next stats snapshot (cumulative since start)
    time.sleep(STATS_INTERVAL + 1.5)
    recv, drop = read_stats()
    stop_broker(p)
    time.sleep(0.3)
    total = recv + drop
    drop_pct = (100.0 * drop / total) if total else 0.0
    return {'target': pps, 'sent': blast.get('sent', 0), 'achieved_pps': blast.get('pps', 0),
            'recv': recv, 'drop': drop, 'drop_pct': drop_pct}


def main():
    if os.geteuid() != 0:
        sys.exit('must run as root (veth + AF_PACKET)')
    ap = argparse.ArgumentParser()
    ap.add_argument('--broker', default='./packet_broker')
    ap.add_argument('--blast', default='./pbcap_blast')
    ap.add_argument('--secs', type=float, default=5.0)
    ap.add_argument('--size', type=int, default=64)
    ap.add_argument('--rates', default='50000,100000,250000,500000,1000000,0')
    a = ap.parse_args()

    if not os.path.exists(a.broker):
        sys.exit(f'broker binary not found: {a.broker}')
    os.makedirs(WORK, exist_ok=True)
    # auto-build the blaster next to this script if missing
    if not os.path.exists(a.blast):
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pbcap_blast.c')
        if subprocess.run(['gcc', '-O2', '-o', a.blast, src]).returncode != 0:
            sys.exit('failed to build pbcap_blast')

    rates = [int(x) for x in a.rates.split(',')]
    print(f'# broker capture load test — size={a.size}B secs={a.secs} rule="{RULE}"')
    print(f'{"target_pps":>12} {"sent":>12} {"achieved_pps":>13} {"recv":>12} {"drop":>10} {"drop%":>7}')
    setup_veths()
    knee = None
    try:
        for pps in rates:
            r = run_rate(a.broker, a.blast, pps, a.secs, a.size)
            tgt = 'max' if r['target'] == 0 else f"{r['target']:,}"
            print(f'{tgt:>12} {r["sent"]:>12,} {r["achieved_pps"]:>13,.0f} '
                  f'{r["recv"]:>12,} {r["drop"]:>10,} {r["drop_pct"]:>6.2f}%')
            if knee is None and r['drop_pct'] >= 1.0:
                knee = r['achieved_pps']
    finally:
        kill_stale_broker()
        teardown_veths()
    print('#')
    if knee:
        print(f'# capture knee: first ≥1% drop at ~{knee:,.0f} pps (single libpcap thread on veth)')
    else:
        print('# no ≥1% drop observed at the tested rates — raise --rates to find the knee')


if __name__ == '__main__':
    main()

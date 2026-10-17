#!/usr/bin/env python3
"""
shield gate — the socket gate (CYCLONE-SHIELD-0 D2.4, 2026-10-14; brainstorm § 2 "socket gate", § 3.5 dispositions, § 3.6 tiers).
A front listener for ONE of our own services.

WATCH-ONLY by default: every connection is forwarded and a verdict is logged with its reason; nothing is blocked unless
`--enforce` is passed (J-confirmed per run, never a default). The verdict is the pocket's disposition (VOCAB "the pocket"):

  +1 GIVE    pass — greenmarked by a trusted key, under its rate
   0 HOLD    pass, optionally slowed — unsigned, unknown key, or over the soft rate
  -1 COMMIT  deny (only with --enforce) — bad signature, revoked key, or over the hard rate cap

Verdict inputs per connection (flow level; of the payload only an HTTP request line + headers are read):
  · greenmark tier (projects/greenmark: RFC 9421 Signature / Signature-Input, Ed25519) against this gate's trust file
  · rate per source over a sliding window (heavy-hitter rule)
  · rhythm: the spread of inter-arrival gaps per source (a scheduled bot ticks; people do not) — reported, never enforcing
Every verdict is one JSON line, so a run can be replayed and audited.

  projects/shield/gate.py --listen 127.0.0.1:8791 --to 127.0.0.1:8790 [--keys trusted.json] [--log results/gate.jsonl]
                          [--enforce] [--rate N] [--hard M] [--window S] [--hold-ms MS]
"""
import argparse, base64, json, os, select, socket, socketserver, statistics, sys, threading, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "greenmark"))
try:
    import greenmark as gm
except Exception:                                                    # the gate still runs; every flow is then tier 0
    gm = None

STATE = {}                                                           # source ip -> arrival times
LOCK = threading.Lock()


def rhythm(ts, tail=9):
    """spread of inter-arrival gaps / their mean over the most recent `tail` arrivals: low = machine-regular, high = human.
    A TAIL, not the whole window (GATE-WATCH-0 run 1: a whole-window mean mixes phases and buries a regular burst)."""
    ts = ts[-tail:]
    if len(ts) < 4: return None
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    m = statistics.fmean(gaps)
    return round(statistics.pstdev(gaps) / m, 3) if m > 0 else 0.0


def parse_http(head):
    """request line + headers in the shape the greenmark verifier wants. None when it is not HTTP."""
    try: text = head.decode("latin-1")
    except Exception: return None
    lines = text.split("\r\n")
    if not lines or " " not in lines[0]: return None
    parts = lines[0].split()
    if len(parts) < 3 or not parts[2].startswith("HTTP/"): return None
    hs = []
    for l in lines[1:]:
        if not l: break
        if ": " in l:
            k, v = l.split(": ", 1); hs.append((k, v))
    host = next((v for k, v in hs if k.lower() == "host"), "")
    return {"method": parts[0], "target": parts[1], "scheme": "http", "authority": host, "headers": hs}


class Gate(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        cfg = self.server.cfg
        src = self.client_address[0]
        now = time.time()
        with LOCK:
            ts = STATE.setdefault(src, [])
            ts.append(now); del ts[:-256]
            recent = [t for t in ts if now - t <= cfg.window]
        rate = len(recent)
        head = b""
        self.request.settimeout(cfg.read_timeout)
        try:
            while b"\r\n\r\n" not in head and len(head) < 65536:
                b = self.request.recv(4096)
                if not b: break
                head += b
        except (socket.timeout, OSError):
            pass
        req = parse_http(head)
        if req is None:
            tier, why = 0, "not http"
        elif gm is None:
            tier, why = 0, "greenmark unavailable"
        else:
            tier, why = gm.tier(req, self.server.trusted, self.server.revoked)
        if rate > cfg.hard:
            tier, why = -1, f"rate {rate} > hard cap {cfg.hard} in {cfg.window}s ({why})"
        elif tier == 1 and rate > cfg.rate:
            tier, why = 0, f"rate {rate} > {cfg.rate} in {cfg.window}s ({why})"
        rec = {"t": round(now, 3), "src": src, "verdict": tier, "why": why, "window_s": cfg.window, "rate": rate,
               "rhythm_cv": rhythm(recent), "method": (req or {}).get("method"), "target": (req or {}).get("target"),
               "action": {1: "GIVE", 0: "HOLD", -1: "COMMIT"}[tier], "enforced": bool(cfg.enforce and tier == -1)}
        self.server.log(rec)
        if cfg.enforce and tier == -1:
            self.request.close(); return
        if tier == 0 and cfg.hold_ms:
            time.sleep(cfg.hold_ms / 1000.0)                         # HOLD: the slow lane, so probing costs the prober time
        self.forward(head)

    def forward(self, head):
        host, port = self.server.cfg.to.rsplit(":", 1)
        try:
            up = socket.create_connection((host, int(port)), timeout=5)
        except OSError as e:
            self.server.log({"t": round(time.time(), 3), "src": self.client_address[0], "verdict": 0,
                             "why": f"upstream unreachable: {e}", "action": "HOLD", "enforced": False})
            return
        with up:
            if head: up.sendall(head)
            socks = [self.request, up]
            self.request.settimeout(None); up.settimeout(None)
            while True:
                r, _, _ = select.select(socks, [], [], 30)
                if not r: break
                done = False
                for s in r:
                    try: data = s.recv(65536)
                    except OSError: data = b""
                    if not data: done = True; break
                    try: (up if s is self.request else self.request).sendall(data)
                    except OSError: done = True; break
                if done: break


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", default="127.0.0.1:8791"); ap.add_argument("--to", default="127.0.0.1:8790")
    ap.add_argument("--keys", default=os.path.join(HERE, "trusted.json"))
    ap.add_argument("--log", default=os.path.join(HERE, "results", "gate.jsonl"))
    ap.add_argument("--enforce", action="store_true", help="deny on -1 (J-confirmed per run; watch-only without it)")
    ap.add_argument("--rate", type=int, default=120, help="per-source requests per window above which a +1 becomes 0")
    ap.add_argument("--hard", type=int, default=600, help="per-source hard cap per window -> -1")
    ap.add_argument("--window", type=float, default=10.0); ap.add_argument("--hold-ms", type=int, default=0)
    ap.add_argument("--read-timeout", type=float, default=2.0)
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.log), exist_ok=True)
    trusted, revoked = {}, set()
    if os.path.exists(a.keys):
        raw = json.load(open(a.keys))
        trusted = {k: base64.b64decode(v) for k, v in raw.get("trusted", {}).items()}
        revoked = set(raw.get("revoked", []))
    host, port = a.listen.rsplit(":", 1)
    srv = Gate((host, int(port)), Handler)
    srv.cfg, srv.trusted, srv.revoked = a, trusted, revoked
    fh = open(a.log, "a"); lk = threading.Lock()

    def log(rec):
        with lk:
            fh.write(json.dumps(rec) + "\n"); fh.flush()
    srv.log = log
    log({"t": round(time.time(), 3), "event": "gate up", "listen": a.listen, "to": a.to, "enforce": bool(a.enforce),
         "trusted_keys": sorted(trusted), "greenmark": gm is not None})
    print(json.dumps({"listening": a.listen, "to": a.to, "enforce": bool(a.enforce), "log": a.log,
                      "trusted": sorted(trusted)}), flush=True)
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        log({"t": round(time.time(), 3), "event": "gate down"}); fh.close()


if __name__ == "__main__":
    main()

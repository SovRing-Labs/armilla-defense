#!/usr/bin/env python3
"""
shield ugate — the greenmark gate for a UNIX-SOCKET service (CYCLONE-SHIELD-0 #3, 2026-10-14).

Our inter-agent services (omnid and its shard socket) speak over a Unix socket, not HTTP, so the greenmark here uses the
non-HTTP profile of the spec (projects/shield/lanes.py): a signature over the request's content digest, its kind and its
source, with `keyid` naming a key in the fleet trust file. The gate sits in front of the real socket and relays.

Modes, in the order we are allowed to use them (brief rule: detect + report first):
  default        WATCH-ONLY — every request is relayed, and a verdict is logged with its reason
  --default-deny ENFORCING — only +1 (signed by a trusted key) is relayed; 0 and -1 are refused with a one-line reply
                 This is the mode that must not be switched on a live service until its callers are signed: an unsigned
                 fleet caller would be cut off. `census` measures exactly that first.

  ugate.py serve --listen PATH --to PATH [--keys F] [--log F] [--default-deny]
  ugate.py census --log F                 who called, signed vs unsigned, from a watch-only log
  ugate.py send --to PATH --key F --keyid K --kind KIND [--source S]     a signed client, reads the body from stdin
"""
import argparse, base64, json, os, socket, socketserver, sys, threading, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "greenmark"))
import greenmark as gm, lanes

MARK = b"X-Greenmark: "                                              # one header line, then a blank line, then the body


def split_marks(buf):
    """our framing: optional `X-Greenmark: <json>` line, then an empty line, then the body."""
    if not buf.startswith(MARK):
        return {}, buf
    line, _, rest = buf.partition(b"\n")
    try:
        marks = json.loads(line[len(MARK):].decode())
    except ValueError:
        return {}, buf
    if rest.startswith(b"\n"): rest = rest[1:]
    return marks, rest


def frame(marks, body):
    return MARK + json.dumps(marks).encode() + b"\n\n" + body


class UGate(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        cfg = self.server.cfg
        self.request.settimeout(cfg.read_timeout)
        buf = b""
        try:
            while len(buf) < 1 << 20:
                b = self.request.recv(65536)
                if not b: break
                buf += b
                if len(b) < 65536: break
            
        except (socket.timeout, OSError):
            pass
        marks, body = split_marks(buf)
        env = lanes.seal(body, source=cfg.source, kind=cfg.kind, marks=marks or None,
                         trusted=self.server.trusted, revoked=self.server.revoked)
        rec = {"t": round(time.time(), 3), "verdict": env["verdict"], "why": env["why"], "bytes": len(body),
               "keyid": (marks or {}).get("Signature-Input", "").split('keyid="')[-1].rstrip('"') if marks else None,
               "action": {1: "GIVE", 0: "HOLD", -1: "COMMIT"}[env["verdict"]],
               "enforced": bool(cfg.default_deny and env["verdict"] != 1)}
        self.server.log(rec)
        if cfg.default_deny and env["verdict"] != 1:
            try: self.request.sendall(json.dumps({"error": "greenmark required", "why": env["why"]}).encode() + b"\n")
            except OSError: pass
            return
        try:
            up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); up.settimeout(10); up.connect(cfg.to)
        except OSError as e:
            self.server.log({"t": round(time.time(), 3), "verdict": 0, "why": f"upstream unreachable: {e}", "action": "HOLD"})
            return
        with up:
            up.sendall(body)
            while True:
                try: data = up.recv(65536)
                except OSError: break
                if not data: break
                try: self.request.sendall(data)
                except OSError: break


def cmd_serve(a):
    trusted, revoked = lanes.load_keys(a.keys)
    if os.path.exists(a.listen): os.remove(a.listen)
    os.makedirs(os.path.dirname(a.log), exist_ok=True)
    srv = UGate(a.listen, Handler)
    srv.cfg, srv.trusted, srv.revoked = a, trusted, revoked
    fh = open(a.log, "a"); lk = threading.Lock()

    def log(rec):
        with lk: fh.write(json.dumps(rec) + "\n"); fh.flush()
    srv.log = log
    log({"t": round(time.time(), 3), "event": "ugate up", "listen": a.listen, "to": a.to,
         "default_deny": bool(a.default_deny), "trusted_keys": sorted(trusted)})
    print(json.dumps({"listening": a.listen, "to": a.to, "default_deny": bool(a.default_deny), "log": a.log}), flush=True)
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        log({"t": round(time.time(), 3), "event": "ugate down"}); fh.close()


def cmd_census(a):
    rows = [json.loads(l) for l in open(a.log) if '"verdict"' in l]
    by = {}
    for r in rows:
        k = r.get("keyid") or "(unsigned)"
        d = by.setdefault(k, {"calls": 0, "verdicts": {}})
        d["calls"] += 1
        d["verdicts"][str(r["verdict"])] = d["verdicts"].get(str(r["verdict"]), 0) + 1
    out = {"log": a.log, "calls": len(rows), "callers": by,
           "unsigned_calls": sum(1 for r in rows if r["verdict"] == 0),
           "would_be_denied_under_default_deny": sum(1 for r in rows if r["verdict"] != 1)}
    print(json.dumps(out, indent=1))


def cmd_send(a):
    sk = base64.b64decode(open(a.key).read().strip())
    body = sys.stdin.buffer.read()
    marks = lanes.sign_content(sk, a.keyid, body, kind=a.kind, source=a.source)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10); s.connect(a.to)
    with s:
        s.sendall(frame(marks, body))
        out = b""
        while True:
            try: d = s.recv(65536)
            except OSError: break
            if not d: break
            out += d
    sys.stdout.buffer.write(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("serve")
    s.add_argument("--listen", required=True); s.add_argument("--to", required=True)
    s.add_argument("--keys", default=os.path.join(HERE, "trusted.json"))
    s.add_argument("--log", default=os.path.join(HERE, "results", "ugate.jsonl"))
    s.add_argument("--default-deny", action="store_true"); s.add_argument("--read-timeout", type=float, default=2.0)
    s.add_argument("--kind", default="request"); s.add_argument("--source", default="fleet")
    s.set_defaults(fn=cmd_serve)
    c = sp.add_parser("census"); c.add_argument("--log", default=os.path.join(HERE, "results", "ugate.jsonl")); c.set_defaults(fn=cmd_census)
    d = sp.add_parser("send")
    d.add_argument("--to", required=True); d.add_argument("--key", required=True); d.add_argument("--keyid", required=True)
    d.add_argument("--kind", default="request"); d.add_argument("--source", default="fleet"); d.set_defaults(fn=cmd_send)
    a = ap.parse_args(); a.fn(a)


if __name__ == "__main__":
    main()

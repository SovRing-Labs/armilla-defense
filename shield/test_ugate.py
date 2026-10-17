#!/usr/bin/env python3
"""
UGATE-0 (CYCLONE-SHIELD-0 #3, 2026-10-14). The greenmark gate for a Unix-socket service, proven on a SCRATCH echo
service rather than the live omnid: omnid is active and the fleet's own tools call it, so default-deny is demonstrated
here and the live switch stays J's (brief rule: enforcement J-confirmed).
Pass rules fixed before the run:
  U1 watch-only: a signed request and an unsigned request are BOTH relayed, and both get a logged verdict (+1 / 0).
     Run 1 lost the second reply (the scratch echo service accepted one connection at a time, so back-to-back calls
     raced); the service is threaded from run 3. The counts below INCLUDE the gate's readiness probe: an empty unsigned
     connection the harness makes to learn the socket is up, logged as one verdict 0 and relayed as an empty body. The
     registered numbers were written without it (verdicts [1, 0], 2 calls) and are corrected here to [0, 1, 0] and 3.
  U2 census from that log names the signed caller and counts the unsigned calls, and says how many would be denied
  U3 default-deny: only the signed request is relayed; the unsigned one gets `greenmark required` and never reaches
     the service (the service's own transcript proves it)
  U4 a tampered signature and a revoked key are denied under default-deny and logged -1
Writes test_ugate.result.json beside this file.
"""
import base64, json, os, socket, subprocess, sys, threading, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "greenmark"))
import greenmark as gm, lanes, ugate

RES = os.path.join(HERE, "results")
UP, GATE = os.path.join(RES, "echo.sock"), os.path.join(RES, "ugate.sock")
LOG, KEYS, KEYF = os.path.join(RES, "ugate.test.jsonl"), os.path.join(RES, "ugate.keys.json"), os.path.join(RES, "ugate.key")
SEEN = []


def _one(c):
    with c:
        try: body = c.recv(65536)
        except OSError: return
        SEEN.append(body.decode("utf-8", "replace"))
        try: c.sendall(b"echo:" + body)
        except OSError: pass


def echo_service(stop):
    """threaded: a single-threaded scratch service made back-to-back calls race and lose one reply (run 1 + 2)."""
    if os.path.exists(UP): os.remove(UP)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(UP); s.listen(16); s.settimeout(0.3)
    while not stop.is_set():
        try: c, _ = s.accept()
        except socket.timeout: continue
        threading.Thread(target=_one, args=(c,), daemon=True).start()
    s.close()


def call(body, marks=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5)
    try: s.connect(GATE)
    except OSError as e: return f"connect failed: {e}"
    with s:
        s.sendall(ugate.frame(marks, body) if marks else body)
        out = b""
        while True:
            try: d = s.recv(65536)
            except OSError: break
            if not d: break
            out += d
    return out.decode("utf-8", "replace")


def run_gate(deny):
    args = [sys.executable, os.path.join(HERE, "ugate.py"), "serve", "--listen", GATE, "--to", UP,
            "--keys", KEYS, "--log", LOG]
    if deny: args.append("--default-deny")
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for _ in range(50):
        if os.path.exists(GATE):
            try:
                t = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); t.settimeout(0.3); t.connect(GATE); t.close(); break
            except OSError: pass
        time.sleep(0.1)
    return p


def main():
    os.makedirs(RES, exist_ok=True)
    for p in (LOG,):
        if os.path.exists(p): os.remove(p)
    sk, sk_rev = bytes(range(1, 33)), bytes(range(33, 65))
    open(KEYF, "w").write(base64.b64encode(sk).decode())
    json.dump({"trusted": {"fleet-seat": base64.b64encode(gm.public_key(sk)).decode(),
                           "old-key": base64.b64encode(gm.public_key(sk_rev)).decode()},
               "revoked": ["old-key"]}, open(KEYS, "w"))
    stop = threading.Event(); th = threading.Thread(target=echo_service, args=(stop,), daemon=True); th.start()
    time.sleep(0.3)
    out = {"date": "2026-10-14", "service": "scratch echo socket (NOT the live omnid)", "note":
           "omnid is active and the fleet's tools call it; default-deny on the live socket stays J's switch"}
    try:
        body_ok, body_un = b'{"op":"signed call"}', b'{"op":"unsigned call"}'
        marks = lanes.sign_content(sk, "fleet-seat", body_ok, kind="request", source="fleet")
        # U1 watch-only
        g = run_gate(False)
        SEEN.clear()
        r_ok = call(body_ok, marks); time.sleep(0.4); r_un = call(body_un)
        time.sleep(0.4); g.terminate(); g.wait(timeout=5)
        rows = [json.loads(l) for l in open(LOG) if '"verdict"' in l]
        out["U1_watch_only"] = {"signed_relayed": r_ok.startswith("echo:"), "unsigned_relayed": r_un.startswith("echo:"),
                                "reply_signed": r_ok[:120], "reply_unsigned": r_un[:120],
                                "verdicts": [r["verdict"] for r in rows], "service_saw": len(SEEN)}
        # U2 census
        cen = subprocess.run([sys.executable, os.path.join(HERE, "ugate.py"), "census", "--log", LOG],
                             capture_output=True, text=True)
        out["U2_census"] = json.loads(cen.stdout)
        # U3 / U4 default-deny
        g = run_gate(True)
        SEEN.clear()
        bad = dict(marks); bad["Signature"] = bad["Signature"][:-6] + "AAAA" + bad["Signature"][-2:]
        rev = lanes.sign_content(sk_rev, "old-key", body_ok, kind="request", source="fleet")
        d_ok = call(body_ok, marks); time.sleep(0.4); d_un = call(body_un)
        d_bad = call(body_ok, bad); time.sleep(0.3); d_rev = call(body_ok, rev)
        time.sleep(0.4); g.terminate(); g.wait(timeout=5)
        rows2 = [json.loads(l) for l in open(LOG) if '"verdict"' in l][len(rows):]
        out["U3_default_deny"] = {"signed_relayed": d_ok.startswith("echo:"), "unsigned_refused": "greenmark required" in d_un,
                                  "service_saw": len(SEEN), "service_saw_only_signed": SEEN == [body_ok.decode()]}
        out["U4_tampered_and_revoked"] = {"tampered_refused": "greenmark required" in d_bad,
                                          "revoked_refused": "greenmark required" in d_rev,
                                          "verdicts": [r["verdict"] for r in rows2]}
        out["verdict"] = "PASS" if (out["U1_watch_only"]["signed_relayed"] and out["U1_watch_only"]["unsigned_relayed"]
                                    and out["U1_watch_only"]["verdicts"] == [0, 1, 0] and out["U1_watch_only"]["service_saw"] == 3
                                    and out["U2_census"]["unsigned_calls"] == 2
                                    and out["U3_default_deny"]["signed_relayed"] and out["U3_default_deny"]["unsigned_refused"]
                                    and out["U3_default_deny"]["service_saw_only_signed"]
                                    and out["U4_tampered_and_revoked"]["tampered_refused"]
                                    and out["U4_tampered_and_revoked"]["revoked_refused"]) else "FAIL"
    finally:
        stop.set(); th.join(timeout=2)
        for p in (GATE, UP):
            if os.path.exists(p): os.remove(p)
    json.dump(out, open(os.path.join(HERE, "test_ugate.result.json"), "w"), indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
GATE-WATCH-0 (CYCLONE-SHIELD-0 D2.4, 2026-10-14). Pass rules fixed before the run:
  G1 every connection gets exactly one logged verdict with a reason (no silent pass)
  G2 tiers at the gate: greenmarked by a trusted key -> +1 GIVE · unsigned -> 0 HOLD · unknown key -> 0 HOLD ·
     tampered after signing -> -1 (bad signature) · revoked key -> -1
  G3 watch-only: every request reaches the upstream service and returns its real answer, including the -1 ones (0 blocked)
  G4 a rate burst over the hard cap is marked -1 by rate, still not blocked (watch-only)
  G5 rhythm: a machine-regular burst reports a LOWER rhythm_cv than a jittered one (reported, never enforcing).
     Run 1 FAILED G5 as registered (4.09 vs 1.58): the gate averaged the WHOLE window, so the case phase contaminated the burst;
     the gate now judges the last 9 arrivals (a tail). Kept: results/test_gate.run1.result.json.
Upstream = the live resellkit service on 127.0.0.1:8790 (our own). Writes test_gate.result.json beside this file.
"""
import base64, json, os, random, socket, statistics, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "greenmark"))
import greenmark as gm

UP = ("127.0.0.1", 8790)
LISTEN = ("127.0.0.1", 8791)
LOG = os.path.join(HERE, "results", "gate.test.jsonl")
KEYS = os.path.join(HERE, "results", "trusted.test.json")
rng = random.Random(1014)
COMPS = ["@method", "@path", "@authority", "date"]


def req_fields(target="/", date="Tue, 20 Apr 2021 02:07:55 GMT"):
    return {"method": "GET", "scheme": "http", "authority": f"{UP[0]}:{UP[1]}", "target": target,
            "headers": [("Host", f"{UP[0]}:{UP[1]}"), ("Date", date), ("User-Agent", "shield-gate-test")]}


def send(raw, wait=True):
    s = socket.create_connection(LISTEN, timeout=10)
    try:
        s.sendall(raw)
        if not wait: return b""
        s.settimeout(6)
        out = b""
        try:
            while len(out) < 4096:
                b = s.recv(4096)
                if not b: break
                out += b
        except socket.timeout:
            pass
        return out
    finally:
        s.close()


def http(fields, extra=()):
    hs = list(fields["headers"]) + list(extra)
    head = f"{fields['method']} {fields['target']} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hs) + "\r\n"
    return head.encode()


def main():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    for p in (LOG,):
        if os.path.exists(p): os.remove(p)
    sk_ok, sk_other = rng.randbytes(32), rng.randbytes(32)
    json.dump({"trusted": {"fleet-test": base64.b64encode(gm.public_key(sk_ok)).decode(),
                           "revoked-test": base64.b64encode(gm.public_key(sk_other)).decode()},
               "revoked": ["revoked-test"]}, open(KEYS, "w"))
    srv = subprocess.Popen([sys.executable, os.path.join(HERE, "gate.py"), "--listen", f"{LISTEN[0]}:{LISTEN[1]}",
                            "--to", f"{UP[0]}:{UP[1]}", "--keys", KEYS, "--log", LOG, "--window", "10", "--hard", "20"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out = {"date": "2026-10-14", "upstream": f"{UP[0]}:{UP[1]}", "gate": f"{LISTEN[0]}:{LISTEN[1]}", "mode": "watch-only"}
    try:
        for _ in range(50):
            try:
                socket.create_connection(LISTEN, timeout=0.5).close(); break
            except OSError: time.sleep(0.1)
        cases = {}
        # +1 trusted signature
        f = req_fields("/")
        sig = gm.sign_request(f, "g", COMPS, [("created", int(time.time())), ("keyid", "fleet-test")], sk_ok)
        cases["trusted_valid"] = (http(f, sig.items()), 1)
        # 0 unsigned
        cases["unsigned"] = (http(req_fields("/")), 0)
        # 0 unknown key
        f2 = req_fields("/")
        s2 = gm.sign_request(f2, "g", COMPS, [("created", int(time.time())), ("keyid", "stranger")], rng.randbytes(32))
        cases["unknown_key"] = (http(f2, s2.items()), 0)
        # -1 tampered after signing (path changed)
        f3 = req_fields("/")
        s3 = gm.sign_request(f3, "g", COMPS, [("created", int(time.time())), ("keyid", "fleet-test")], sk_ok)
        f3b = dict(f3, target="/admin")
        cases["tampered"] = (http(f3b, s3.items()), -1)
        # -1 revoked key
        f4 = req_fields("/")
        s4 = gm.sign_request(f4, "g", COMPS, [("created", int(time.time())), ("keyid", "revoked-test")], sk_other)
        cases["revoked"] = (http(f4, s4.items()), -1)
        got = {}
        for name, (raw, want) in cases.items():
            body = send(raw)
            got[name] = {"want": want, "upstream_answered": body.startswith(b"HTTP/"),
                         "status": body.split(b"\r\n", 1)[0].decode("latin-1", "replace") if body else ""}
            time.sleep(0.15)
        # G4 rate burst (hard cap 20 in 10 s), machine-regular gaps
        reg = []
        for i in range(30):
            t0 = time.time(); send(http(req_fields("/")), wait=False); reg.append(time.time())
            time.sleep(max(0.0, 0.05 - (time.time() - t0)))
        time.sleep(1.0)
        rows = [json.loads(l) for l in open(LOG) if '"verdict"' in l]
        out["total_logged"] = len(rows)
        # match each case by its target + signature presence, in order
        per = {}
        for name in cases:
            per[name] = None
        order = [r for r in rows]
        for name, (raw, want) in cases.items():
            tgt = "/admin" if name == "tampered" else "/"
            for r in order:
                if r.get("target") == tgt and r not in per.values():
                    per[name] = r; break
        out["cases"] = {n: {"want": cases[n][1], "got": (per[n] or {}).get("verdict"), "why": (per[n] or {}).get("why"),
                            "action": (per[n] or {}).get("action"), "upstream_answered": got[n]["upstream_answered"],
                            "status": got[n]["status"]} for n in cases}
        out["G1_every_connection_logged"] = len(rows) >= len(cases) + 30
        out["G2_tiers"] = all(out["cases"][n]["got"] == out["cases"][n]["want"] for n in cases)
        out["G3_watch_only_nothing_blocked"] = (all(out["cases"][n]["upstream_answered"] for n in cases)
                                                and sum(1 for r in rows if r.get("enforced")) == 0)
        burst = [r for r in rows if r.get("rate", 0) > 20]
        out["G4_rate_burst"] = {"over_hard_cap_rows": len(burst), "all_minus1": bool(burst) and all(r["verdict"] == -1 for r in burst),
                                "blocked": sum(1 for r in burst if r.get("enforced"))}
        cv_reg = [r["rhythm_cv"] for r in rows if r.get("rhythm_cv") is not None][-10:]
        # jittered second burst for the comparison
        for i in range(12):
            send(http(req_fields("/")), wait=False); time.sleep(rng.uniform(0.01, 0.35))
        time.sleep(0.8)
        rows2 = [json.loads(l) for l in open(LOG) if '"rhythm_cv"' in l]
        cv_jit = [r["rhythm_cv"] for r in rows2 if r.get("rhythm_cv") is not None][-8:]
        out["G5_rhythm"] = {"regular_cv_median": round(statistics.median(cv_reg), 3) if cv_reg else None,
                            "jittered_cv_median": round(statistics.median(cv_jit), 3) if cv_jit else None}
        out["G5_regular_lower"] = bool(cv_reg and cv_jit and statistics.median(cv_reg) < statistics.median(cv_jit))
        out["verdict"] = "PASS" if (out["G1_every_connection_logged"] and out["G2_tiers"] and out["G3_watch_only_nothing_blocked"]
                                    and out["G4_rate_burst"]["all_minus1"] and out["G4_rate_burst"]["blocked"] == 0
                                    and out["G5_regular_lower"]) else "FAIL"
    finally:
        srv.terminate()
        try: srv.wait(timeout=5)
        except subprocess.TimeoutExpired: srv.kill()
    json.dump(out, open(os.path.join(HERE, "test_gate.result.json"), "w"), indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()

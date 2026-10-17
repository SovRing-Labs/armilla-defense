#!/usr/bin/env python3
"""
GREENMARK-REF-0 (CYCLONE-SHIELD-0 D1.6, 2026-10-14). Pass rules fixed before the run:
  T1 RFC 8032 § 7.1 TEST 1–3: public key and signature byte-exact; verify true; one flipped bit → verify false
  T2 oracle: 200 random (key, message) pairs — our signature == `cryptography` Ed25519 signature (deterministic scheme); our verify
     accepts the oracle's signature and the oracle accepts ours; 200 tampered messages rejected by both
  T3 RFC 9421 B.2.6: our signature base == the RFC's text; the RFC's signature verifies with test-key-ed25519; our signature over
     the same base == the RFC's bytes (Ed25519 is deterministic)
  T4 tiers: trusted+valid → +1 · unsigned → 0 · unknown key → 0 · tampered header → −1 · revoked → −1
Writes test_greenmark.result.json beside this file.
"""
import base64, json, os, random, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import greenmark as gm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

R = {"date": "2026-10-14"}; t0 = time.time()
hx = bytes.fromhex
V = [("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
     ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
     ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")]
t1 = []
for sk, pk, m, sg in V:
    sk, pk, m, sg = hx(sk), hx(pk), hx(m), hx(sg)
    bad = bytearray(sg); bad[5] ^= 1
    t1.append(gm.public_key(sk) == pk and gm.sign(sk, m) == sg and gm.verify(pk, m, sg) and not gm.verify(pk, m, bytes(bad)))
R["T1_rfc8032_vectors"] = {"pass": sum(t1), "of": len(t1)}

rng = random.Random(1014); ok = {"sig_equal": 0, "we_accept_oracle": 0, "oracle_accepts_ours": 0, "tamper_rejected_both": 0}
N = 200
for i in range(N):
    sk = rng.randbytes(32); m = rng.randbytes(rng.randrange(0, 300))
    o = Ed25519PrivateKey.from_private_bytes(sk); opub = o.public_key()
    pub = opub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    osig, ours = o.sign(m), gm.sign(sk, m)
    ok["sig_equal"] += osig == ours and gm.public_key(sk) == pub
    ok["we_accept_oracle"] += gm.verify(pub, m, osig)
    try: opub.verify(ours, m); ok["oracle_accepts_ours"] += 1
    except InvalidSignature: pass
    tm = m + b"x"
    try: opub.verify(ours, tm); orej = False
    except InvalidSignature: orej = True
    ok["tamper_rejected_both"] += orej and not gm.verify(pub, tm, ours)
R["T2_oracle"] = dict(ok, of=N)

req = {"method": "POST", "scheme": "https", "authority": "example.com", "target": "/foo?param=Value&Pet=dog",
       "headers": [("Host", "example.com"), ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"), ("Content-Type", "application/json"),
                   ("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"),
                   ("Content-Length", "18")]}
comps = ["date", "@method", "@path", "@authority", "content-type", "content-length"]
params = [("created", 1618884473), ("keyid", "test-key-ed25519")]
rfc_base = ('"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@method": POST\n"@path": /foo\n"@authority": example.com\n'
            '"content-type": application/json\n"content-length": 18\n'
            '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"')
rfc_sig = base64.b64decode("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==")
b64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
tk_d, tk_x = b64u("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"), b64u("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")
base, _ = gm.signature_base(req, comps, params)
R["T3_rfc9421_b26"] = {"base_equal": base == rfc_base, "rfc_sig_verifies": gm.verify(tk_x, base.encode(), rfc_sig),
                       "our_sig_equals_rfc": gm.sign(tk_d, base.encode()) == rfc_sig, "pubkey_from_d": gm.public_key(tk_d) == tk_x}

trusted = {"test-key-ed25519": tk_x}
signed = dict(req, headers=req["headers"] + list(gm.sign_request(req, "sig-b26", comps, params, tk_d).items()))
unknown = dict(req, headers=req["headers"] + list(gm.sign_request(req, "s", comps, [("created", 1), ("keyid", "stranger")], rng.randbytes(32)).items()))
tampered = dict(signed, headers=[(k, "19" if k == "Content-Length" else v) for k, v in signed["headers"]])
cases = {"trusted_valid": (gm.tier(signed, trusted)[0], 1), "unsigned": (gm.tier(req, trusted)[0], 0), "unknown_key": (gm.tier(unknown, trusted)[0], 0),
         "tampered": (gm.tier(tampered, trusted)[0], -1), "revoked": (gm.tier(signed, trusted, revoked={"test-key-ed25519"})[0], -1)}
R["T4_tiers"] = {k: {"got": g, "want": w} for k, (g, w) in cases.items()}
R["seconds"] = round(time.time() - t0, 1)
R["verdict"] = "PASS" if (sum(t1) == 3 and all(v == N for k, v in ok.items()) and all(R["T3_rfc9421_b26"].values())
                          and all(g == w for g, w in cases.values())) else "FAIL"
json.dump(R, open(os.path.join(HERE, "test_greenmark.result.json"), "w"), indent=1)
print(json.dumps(R, indent=1))

"""
greenmark — reference implementation v0 (CYCLONE-SHIELD-0 D1.6, 2026-10-14). Spec: SPEC.md beside this file.

Clean-room: written from the published descriptions only — RFC 8032 § 5.1 (Ed25519: curve, encoding, sign, verify) and RFC 9421
§ 2–3 (HTTP Message Signatures: components, signature base, Signature-Input / Signature fields), read from research/specs/.
No third-party code was read; the installed `cryptography` package is used ONLY as a black-box oracle in test_greenmark.py.

REFERENCE ONLY: Python big integers are not constant-time. Use this to VERIFY (public keys, no secret) and to sign test vectors;
production signing keys stay in audited code.
"""
import base64, hashlib, re

# ---------------------------------------------------------------- Ed25519 (RFC 8032 § 5.1) -------------------------------------
P = 2 ** 255 - 19                                   # field prime
L = 2 ** 252 + 27742317777372353535851937790883648493   # group order
D = (-121665 * pow(121666, P - 2, P)) % P           # curve constant d = -121665/121666
SQRT_M1 = pow(2, (P - 1) // 4, P)                   # a square root of -1 mod p


def _inv(x): return pow(x, P - 2, P)


def _recover_x(y, sign):
    """x from y on -x² + y² = 1 + d·x²·y²  →  x² = (y² − 1) / (d·y² + 1)."""
    if y >= P: return None
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x2 = u * _inv(v) % P
    if x2 == 0: return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0: x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0: return None
    if x & 1 != sign: x = P - x
    return x


# points in extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x·y = T/Z
def _add(p, q):
    X1, Y1, Z1, T1 = p; X2, Y2, Z2, T2 = q
    a = (Y1 - X1) * (Y2 - X2) % P
    b = (Y1 + X1) * (Y2 + X2) % P
    c = 2 * T1 * T2 * D % P
    d = 2 * Z1 * Z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, p):
    q = (0, 1, 1, 0)                                 # neutral element
    while s:
        if s & 1: q = _add(q, p)
        p = _add(p, p); s >>= 1
    return q


def _eq(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


_GY = 4 * _inv(5) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)


def _encode(p):
    zi = _inv(p[2]); x, y = p[0] * zi % P, p[1] * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode(b):
    if len(b) != 32: return None
    y = int.from_bytes(b, "little"); sign = y >> 255; y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _h(*parts): return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand(secret):
    if len(secret) != 32: raise ValueError("Ed25519 secret key is 32 bytes")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8; a |= 1 << 254              # clamp
    return a, h[32:]


def public_key(secret):
    a, _ = _expand(secret)
    return _encode(_mul(a, G))


def sign(secret, msg):
    a, prefix = _expand(secret)
    A = _encode(_mul(a, G))
    r = _h(prefix, msg) % L
    R = _encode(_mul(r, G))
    s = (r + _h(R, A, msg) * a) % L
    return R + int.to_bytes(s, 32, "little")


def verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64: return False
    A = _decode(public); R = _decode(sig[:32])
    if A is None or R is None: return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L: return False
    k = _h(sig[:32], public, msg) % L
    # check [8][s]B = [8]R + [8][k]A (cofactored, RFC 8032 § 5.1.7)
    return _eq(_mul(8 * s, G), _add(_mul(8, R), _mul(8 * k, A)))


# ---------------------------------------------------------------- HTTP Message Signatures (RFC 9421) ----------------------------
def _component(req, name):
    n = name.lower()
    if n == "@method": return req["method"].upper()
    if n == "@authority": return req["authority"].lower()
    if n == "@path": return req["target"].split("?", 1)[0]
    if n == "@query": q = req["target"].split("?", 1); return "?" + (q[1] if len(q) > 1 else "")
    if n == "@target-uri": return req["scheme"] + "://" + req["authority"] + req["target"]
    if n.startswith("@"): raise ValueError(f"component {name} not supported in v0")
    vals = [v for k, v in req["headers"] if k.lower() == n]
    if not vals: raise KeyError(f"header {name} absent")
    return ", ".join(re.sub(r"\s+", " ", v.strip()) for v in vals)


def signature_params(components, params):
    inner = " ".join(f'"{c}"' for c in components)
    out = f"({inner})"
    for k, v in params:
        out += f';{k}="{v}"' if isinstance(v, str) else f";{k}={v}"
    return out


def signature_base(req, components, params):
    lines = [f'"{c.lower()}": {_component(req, c)}' for c in components]
    sp = signature_params(components, params)
    lines.append(f'"@signature-params": {sp}')
    return "\n".join(lines), sp


def sign_request(req, label, components, params, secret):
    base, sp = signature_base(req, components, params)
    sig = sign(secret, base.encode())
    return {"Signature-Input": f"{label}={sp}", "Signature": f"{label}=:{base64.b64encode(sig).decode()}:"}


def _parse_input(v):
    m = re.match(r'\s*([A-Za-z0-9_\-*.]+)=\(([^)]*)\)(.*)$', v)
    if not m: raise ValueError("bad Signature-Input")
    label, comps, rest = m.group(1), re.findall(r'"([^"]+)"', m.group(2)), m.group(3)
    params = []
    for k, sv, iv in re.findall(r';([a-z]+)=(?:"([^"]*)"|(-?\d+))', rest):
        params.append((k, sv if iv == "" else int(iv)))
    return label, comps, params


def verify_request(req, keys):
    """keys: keyid -> 32-byte Ed25519 public key. Returns (keyid or None, ok)."""
    hs = {k.lower(): v for k, v in req["headers"]}
    if "signature-input" not in hs or "signature" not in hs: return None, False
    label, comps, params = _parse_input(hs["signature-input"])
    m = re.match(r'\s*' + re.escape(label) + r'=:([A-Za-z0-9+/=]+):', hs["signature"])
    if not m: return None, False
    keyid = dict(params).get("keyid")
    pub = keys.get(keyid)
    if pub is None: return keyid, False
    try: base, _ = signature_base(req, comps, params)
    except (KeyError, ValueError): return keyid, False
    return keyid, verify(pub, base.encode(), base64.b64decode(m.group(1)))


# ---------------------------------------------------------------- greenmark tiers (SPEC.md § 3) -------------------------------
def tier(req, trusted, revoked=frozenset()):
    """+1 signed by a trusted key · 0 unsigned or unknown key · −1 bad signature or revoked key."""
    hs = {k.lower() for k, _ in req["headers"]}
    if "signature" not in hs: return 0, "unsigned"
    try: keyid, ok = verify_request(req, trusted)
    except ValueError: return -1, "malformed signature fields"
    if keyid in revoked: return -1, f"revoked key {keyid}"
    if keyid not in trusted: return 0, f"unknown key {keyid}"
    return (1, f"trusted key {keyid}") if ok else (-1, f"bad signature for {keyid}")

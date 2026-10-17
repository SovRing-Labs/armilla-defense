"""Own RFC8032 Ed25519 reference arithmetic only; variable time and unaudited."""
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



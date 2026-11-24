"""Local Stellina Authorization header (no external server).

Algorithm and embedded key pair from pyvaonis (MIT, https://github.com/DouweM/pyvaonis,
PROTOCOL.md section 3), which reproduces InstrumentRepository.getAuthHeader() of the
official Stellina app:

    first  = challenge[0]                      # selector char, passed through
    rest   = base64decode(challenge[1:])
    digest = SHA512(rest + "|telescopeId|bootCount")
    signed = Ed25519_sign(digest) || digest    # 64 + 64 = 128 bytes (TweetNaCl sign)
    header = "Basic android|" + first + "|" + base64(signed)

The challenge rotates with every STATUS_UPDATED push, so compute a fresh header
immediately before every REST request.

Uses PyNaCl if installed, otherwise a pure-Python RFC 8032 Ed25519 (standard library only).
"""
import base64, hashlib, os, json, pathlib

# The signing key is NOT shipped in the app. It is loaded from (in order):
#   1) env vars STELLINA_PUBLIC_KEY_B64 + STELLINA_SECRET_KEY_B64
#   2) a file `stellina_key.json` next to this module: {"public_key_b64":..., "secret_key_b64":...}
# Without it the app runs read-only: status, FTP and diagnostics work, but no command
# that controls the telescope can be authorized. Hand the key file only to trusted users.
def _data_dirs():
    """Where to look for user files (key, config), newest/most-specific first.
    Works both as plain .py and inside a PyInstaller .app/.exe bundle."""
    import sys
    dirs = []
    if getattr(sys, 'frozen', False):
        dirs.append(pathlib.Path(sys.executable).resolve().parent)          # next to the executable
        try: dirs.append(pathlib.Path(sys.executable).resolve().parents[2]) # next to the .app bundle (macOS)
        except IndexError: pass
    dirs.append(pathlib.Path(__file__).resolve().parent)                    # module dir (dev / bundled resources)
    dirs.append(pathlib.Path.cwd())
    seen = []
    for d in dirs:
        if d not in seen: seen.append(d)
    return seen

def _load_keys():
    pub = os.environ.get('STELLINA_PUBLIC_KEY_B64'); sec = os.environ.get('STELLINA_SECRET_KEY_B64')
    if pub and sec: return pub.strip(), sec.strip(), 'env'
    for base in _data_dirs():
        f = base / 'stellina_key.json'
        if f.exists():
            try:
                d = json.loads(f.read_text(encoding='utf-8'))
                if d.get('public_key_b64') and d.get('secret_key_b64'):
                    return d['public_key_b64'].strip(), d['secret_key_b64'].strip(), 'file'
            except (ValueError, OSError): pass
    return None, None, None

PUBLIC_KEY_B64, SECRET_KEY_B64, KEY_SOURCE = _load_keys()
KEY_LOADED = bool(PUBLIC_KEY_B64 and SECRET_KEY_B64)
PUBLIC_KEY = None; SEED = None

# ---- pure-Python Ed25519 (RFC 8032), signing only needs to be correct, not constant-time ----
_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)

def _inv(x): return pow(x, _p - 2, _p)

def _xrecover(y):
    xx = (y*y - 1) * _inv(_d*y*y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x*x - xx) % _p: x = x * _I % _p
    if x % 2: x = _p - x
    return x

_By = 4 * _inv(5) % _p
_B = (_xrecover(_By), _By, 1, _xrecover(_By) * _By % _p)  # extended coords

def _add(P, Q):
    x1, y1, z1, t1 = P; x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _p; b = (y1 + x1) * (y2 + x2) % _p
    c = 2 * t1 * t2 * _d % _p; dd = 2 * z1 * z2 % _p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e*f % _p, g*h % _p, f*g % _p, e*h % _p)

def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s:
        if s & 1: Q = _add(Q, P)
        P = _add(P, P); s >>= 1
    return Q

def _enc(P):
    x, y, z, _ = P; zi = _inv(z); x = x * zi % _p; y = y * zi % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, 'little')

def _ed25519_sign_py(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8; a |= 1 << 254
    A = _enc(_mul(a, _B))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), 'little') % _L
    R = _enc(_mul(r, _B))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), 'little') % _L
    S = (r + k * a) % _L
    return R + int.to_bytes(S, 32, 'little')

if KEY_LOADED:
    PUBLIC_KEY = base64.b64decode(PUBLIC_KEY_B64)
    _SECRET = base64.b64decode(SECRET_KEY_B64)
    SEED = _SECRET[:32]
    if _SECRET[32:] != PUBLIC_KEY:
        raise RuntimeError("Stellina key pair in the key file is inconsistent")
    try:
        from nacl.signing import SigningKey as _SK
        _NACL = _SK(SEED)
        def ed25519_sign(msg): return bytes(_NACL.sign(msg).signature)
        BACKEND = 'PyNaCl'
    except Exception:
        def ed25519_sign(msg): return _ed25519_sign_py(SEED, msg)
        BACKEND = 'pure-python'
    if _enc(_mul((lambda h: (int.from_bytes(h[:32], 'little') & ((1 << 254) - 8)) | (1 << 254))(hashlib.sha512(SEED).digest()), _B)) != PUBLIC_KEY:
        raise RuntimeError("Ed25519 self-test failed")
else:
    BACKEND = 'no key'
    def ed25519_sign(msg):
        raise RuntimeError('Authorization key not installed')


def build_auth_header(challenge, telescope_id, boot_count):
    if not KEY_LOADED:
        raise RuntimeError('Authorization key not installed. Add stellina_key.json to the app folder (ask the owner for it).')
    if not isinstance(challenge, str) or len(challenge) < 2:
        raise ValueError('challenge missing or too short')
    rest = base64.b64decode(challenge[1:])
    digest = hashlib.sha512(rest + f"|{telescope_id}|{boot_count}".encode()).digest()
    signed = ed25519_sign(digest) + digest
    return f"Basic android|{challenge[0]}|{base64.b64encode(signed).decode('ascii')}"

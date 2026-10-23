"""
ByteENDE core · JWT decode / encode (HS256 family)
Decoding never requires the secret (header + payload are just Base64URL JSON).
Verifying/signing does require it.
"""
import base64
import hashlib
import hmac
import json
import time

ALG_MAP = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(data: str) -> bytes:
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def decode(token: str) -> dict:
    """Decode header + payload without verifying the signature."""
    parts = token.strip().split('.')
    if len(parts) != 3:
        raise ValueError('A JWT must have exactly 3 dot-separated parts (header.payload.signature)')
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        raise ValueError('Could not parse JWT header/payload as JSON')
    return {
        'header': header,
        'payload': payload,
        'signature': parts[2],
        'expired': _is_expired(payload),
    }


def verify(token: str, secret: str) -> bool:
    """Verify an HS256/384/512 signature with the given secret."""
    parts = token.strip().split('.')
    if len(parts) != 3:
        raise ValueError('Malformed JWT')
    header = json.loads(_b64url_decode(parts[0]))
    alg = header.get('alg', 'HS256')
    if alg not in ALG_MAP:
        raise ValueError(f'Unsupported/unsafe alg "{alg}" for verification (only HS256/384/512 supported)')
    signing_input = f'{parts[0]}.{parts[1]}'.encode('ascii')
    expected = hmac.new(secret.encode('utf-8'), signing_input, ALG_MAP[alg]).digest()
    actual = _b64url_decode(parts[2])
    return hmac.compare_digest(expected, actual)


def encode(payload: dict, secret: str, alg: str = 'HS256', header_extra: dict = None) -> str:
    if alg not in ALG_MAP:
        raise ValueError(f'alg must be one of {", ".join(ALG_MAP)}')
    header = {'alg': alg, 'typ': 'JWT'}
    if header_extra:
        header.update(header_extra)
    h = _b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    p = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    signing_input = f'{h}.{p}'.encode('ascii')
    sig = hmac.new(secret.encode('utf-8'), signing_input, ALG_MAP[alg]).digest()
    s = _b64url_encode(sig)
    return f'{h}.{p}.{s}'


def _is_expired(payload: dict):
    exp = payload.get('exp')
    if exp is None:
        return None
    try:
        return time.time() > float(exp)
    except Exception:
        return None

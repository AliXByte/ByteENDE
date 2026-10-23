"""
ByteENDE core · text/binary codecs
Base64, Base32, Hex, Binary, URL, ROT13, Morse
All functions raise ValueError on bad input - callers (the web panel and the REST API) turn that into a clean error message.
"""
import base64
import urllib.parse
import codecs as _codecs

MORSE_MAP = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
    '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
    ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
    '"': '.-..-.', '$': '...-..-', '@': '.--.-.', ' ': '/'
}
MORSE_REV = {v: k for k, v in MORSE_MAP.items()}


def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


def b64_decode(text: str) -> str:
    try:
        pad = '=' * (-len(text) % 4)
        return base64.b64decode(text + pad).decode('utf-8')
    except Exception:
        raise ValueError('Invalid Base64 input')


def b32_encode(text: str) -> str:
    return base64.b32encode(text.encode('utf-8')).decode('ascii')


def b32_decode(text: str) -> str:
    try:
        pad = '=' * (-len(text) % 8)
        return base64.b32decode(text.upper() + pad).decode('utf-8')
    except Exception:
        raise ValueError('Invalid Base32 input')


def hex_encode(text: str) -> str:
    return text.encode('utf-8').hex()


def hex_decode(text: str) -> str:
    try:
        clean = text.replace(' ', '').replace('0x', '').replace('\n', '')
        return bytes.fromhex(clean).decode('utf-8')
    except Exception:
        raise ValueError('Invalid Hex input')


def bin_encode(text: str) -> str:
    return ' '.join(format(b, '08b') for b in text.encode('utf-8'))


def bin_decode(text: str) -> str:
    try:
        clean = text.replace(' ', '').replace('\n', '')
        if len(clean) % 8 != 0:
            raise ValueError
        b = bytes(int(clean[i:i + 8], 2) for i in range(0, len(clean), 8))
        return b.decode('utf-8')
    except Exception:
        raise ValueError('Invalid Binary input')


def url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe='')


def url_decode(text: str) -> str:
    try:
        return urllib.parse.unquote(text, errors='strict')
    except Exception:
        raise ValueError('Invalid URL-encoded input')


def rot13(text: str) -> str:
    return _codecs.encode(text, 'rot_13')


def morse_encode(text: str) -> str:
    out = []
    for ch in text.upper():
        if ch in MORSE_MAP:
            out.append(MORSE_MAP[ch])
        else:
            raise ValueError(f'Character not supported in Morse: "{ch}"')
    return ' '.join(out)


def morse_decode(text: str) -> str:
    out = []
    for code in text.strip().split(' '):
        if code == '':
            continue
        if code == '/':
            out.append(' ')
        elif code in MORSE_REV:
            out.append(MORSE_REV[code])
        else:
            raise ValueError(f'Invalid Morse token: "{code}"')
    return ''.join(out)


# registry shared by the web panel and the REST API so adding a new codec is one entry
CODECS = {
    'base64': (b64_encode, b64_decode),
    'base32': (b32_encode, b32_decode),
    'hex': (hex_encode, hex_decode),
    'binary': (bin_encode, bin_decode),
    'url': (url_encode, url_decode),
    'rot13': (rot13, rot13),  # symmetric
    'morse': (morse_encode, morse_decode),
}


def run_codec(name: str, mode: str, text: str) -> str:
    if name not in CODECS:
        raise ValueError(f'Unknown codec "{name}". Available: {", ".join(CODECS)}')
    if mode not in ('encode', 'decode'):
        raise ValueError('mode must be "encode" or "decode"')
    enc, dec = CODECS[name]
    fn = enc if mode == 'encode' else dec
    return fn(text)

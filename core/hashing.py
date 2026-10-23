"""ByteENDE core · hash generation (MD5, SHA1, SHA256, SHA512)."""
import hashlib

ALGOS = ['md5', 'sha1', 'sha256', 'sha512']


def hash_text(text: str, algo: str) -> str:
    algo = algo.lower()
    if algo not in ALGOS:
        raise ValueError(f'Unknown algorithm "{algo}". Available: {", ".join(ALGOS)}')
    h = hashlib.new(algo)
    h.update(text.encode('utf-8'))
    return h.hexdigest()


def hash_all(text: str) -> dict:
    return {a: hash_text(text, a) for a in ALGOS}

"""
ByteENDE core · QR code generate (to PNG bytes) and read (from an image file).

Imports are lazy (done inside each function, not at module load) so the rest of
ByteENDE - codecs, hashing, JWT, AES - keeps working even on a machine where
`qrcode` / `pyzbar` (and its system `libzbar`) aren't installed yet. Only calling
these two functions requires them, and the error message says exactly what to install.
"""
import io


def generate(text: str, box_size: int = 10, border: int = 4) -> bytes:
    """Return PNG bytes of a QR code encoding `text`."""
    try:
        import qrcode
    except ImportError:
        raise RuntimeError('QR generation needs the "qrcode" and "Pillow" packages: pip install qrcode pillow')
    qr = qrcode.QRCode(box_size=box_size, border=border)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def read(image_bytes: bytes) -> list:
    """Return a list of decoded strings found in the image (usually 0 or 1)."""
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as _zbar_decode
    except ImportError:
        raise RuntimeError(
            'QR reading needs the "pyzbar" and "Pillow" packages (and the system libzbar '
            'library, e.g. "apt install libzbar0"): pip install pyzbar pillow'
        )
    img = Image.open(io.BytesIO(image_bytes))
    results = _zbar_decode(img)
    if not results:
        raise ValueError('No QR code found in the image')
    return [r.data.decode('utf-8', errors='replace') for r in results]

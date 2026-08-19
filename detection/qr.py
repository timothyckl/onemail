"""Optional QR-code decoding used to recover URLs hidden inside images.

Quishing ("QR phishing") hides the credential-harvesting URL inside an image so
that text- and header-based URL extraction never sees it. Decoding runs at parse
time so the recovered URL becomes an ordinary observable that the existing URL
detectors can evaluate.

The image backend is an **optional** dependency. If it is not installed this
module decodes nothing and never raises, so core detection stays dependency
light: install the extra to activate it.

    python -m pip install "onemail[qr]"

Two backends are supported and tried in order: OpenCV (``opencv-python-headless``)
and pyzbar (``pyzbar`` + the system ``libzbar0``). Everything here is offline and
purely passive: images are decoded, never rendered, executed, or fetched.
"""

import struct
from typing import List, Optional, Tuple

# Only http(s) URLs are treated as links. QR codes also encode Wi-Fi joins,
# mailto:, tel:, geo:, and free text; those are ignored here.
_URL_PREFIXES: Tuple[str, ...] = ("http://", "https://")

# Bounds that keep a hostile or oversized image from dominating parse time.
MAX_IMAGE_BYTES: int = 12_000_000
MAX_IMAGE_PIXELS: int = 25_000_000
MAX_URLS_PER_IMAGE: int = 8
_URL_LENGTH_LIMIT: int = 400


def available() -> bool:
    """Return whether any QR backend can be imported in this environment."""

    return _opencv() is not None or _pyzbar() is not None


def decode_qr_urls(image: bytes) -> Tuple[str, ...]:
    """Return http(s) URLs decoded from QR codes in ``image``.

    Returns an empty tuple when the image is empty, too large, contains no QR
    code, encodes non-URL content, or when no backend is installed. Any backend
    error is swallowed: hostile input must become "no result", never a crash.
    """

    if not image or len(image) > MAX_IMAGE_BYTES or not _within_pixel_limit(image):
        return ()

    payloads: List[str] = []
    for decoder in (_decode_opencv, _decode_pyzbar):
        try:
            payloads = decoder(image)
        except Exception:
            # One optional backend failing must not prevent the other from
            # decoding the same image.
            continue
        if payloads:
            break

    urls: List[str] = []
    seen = set()
    for payload in payloads:
        candidate = payload.strip()
        if not candidate.lower().startswith(_URL_PREFIXES):
            continue
        candidate = candidate[:_URL_LENGTH_LIMIT]
        if candidate in seen:
            continue
        seen.add(candidate)
        urls.append(candidate)
        if len(urls) >= MAX_URLS_PER_IMAGE:
            break
    return tuple(urls)


def _decode_opencv(image: bytes) -> List[str]:
    modules = _opencv()
    if modules is None:
        return []
    cv2, np = modules
    array = cv2.imdecode(np.frombuffer(image, np.uint8), cv2.IMREAD_GRAYSCALE)
    if array is None or array.size > MAX_IMAGE_PIXELS:
        return []
    detector = cv2.QRCodeDetector()
    results: List[str] = []
    ok, decoded, points, _ = detector.detectAndDecodeMulti(array)
    if ok and decoded:
        results.extend(text for text in decoded if text)
    if not results:
        text, points, _ = detector.detectAndDecode(array)
        if text:
            results.append(text)
    return results


def _decode_pyzbar(image: bytes) -> List[str]:
    modules = _pyzbar()
    if modules is None:
        return []
    Image, decode, ZBarSymbol, io = modules
    with Image.open(io.BytesIO(image)) as handle:
        width, height = handle.size
        if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
            return []
        frame = handle.convert("L")
        symbols = decode(frame, symbols=[ZBarSymbol.QRCODE])
    return [symbol.data.decode("utf-8", "replace") for symbol in symbols]


def _within_pixel_limit(image: bytes) -> bool:
    """Reject oversized common image formats before allocating decoded pixels."""

    dimensions = _image_dimensions(image)
    if dimensions is None:
        return True
    width, height = dimensions
    return width > 0 and height > 0 and width * height <= MAX_IMAGE_PIXELS


def _image_dimensions(image: bytes) -> Optional[Tuple[int, int]]:
    """Read dimensions from PNG, GIF, BMP, or JPEG headers without decoding."""

    if image.startswith(b"\x89PNG\r\n\x1a\n") and len(image) >= 24:
        return struct.unpack(">II", image[16:24])
    if image[:6] in (b"GIF87a", b"GIF89a") and len(image) >= 10:
        return struct.unpack("<HH", image[6:10])
    if image.startswith(b"BM") and len(image) >= 26:
        width, height = struct.unpack("<ii", image[18:26])
        return abs(width), abs(height)
    if image.startswith(b"\xff\xd8"):
        return _jpeg_dimensions(image)
    return None


def _jpeg_dimensions(image: bytes) -> Optional[Tuple[int, int]]:
    """Return JPEG dimensions from a start-of-frame marker, when present."""

    start_of_frame = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
        0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF,
    }
    offset = 2
    while offset + 4 <= len(image):
        if image[offset] != 0xFF:
            offset += 1
            continue
        while offset < len(image) and image[offset] == 0xFF:
            offset += 1
        if offset >= len(image):
            return None
        marker = image[offset]
        offset += 1
        if marker == 0x01 or 0xD0 <= marker <= 0xD9:
            continue
        if offset + 2 > len(image):
            return None
        length = struct.unpack(">H", image[offset:offset + 2])[0]
        if length < 2 or offset + length > len(image):
            return None
        if marker in start_of_frame and length >= 7:
            height, width = struct.unpack(">HH", image[offset + 3:offset + 7])
            return width, height
        offset += length
    return None


def _opencv():
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore
    except Exception:
        return None
    return cv2, np


def _pyzbar():
    try:
        import io

        from PIL import Image  # type: ignore
        from pyzbar.pyzbar import ZBarSymbol, decode  # type: ignore
    except Exception:
        return None
    return Image, decode, ZBarSymbol, io

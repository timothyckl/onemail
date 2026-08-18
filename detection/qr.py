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

from typing import List, Tuple

# Only http(s) URLs are treated as links. QR codes also encode Wi-Fi joins,
# mailto:, tel:, geo:, and free text; those are ignored here.
_URL_PREFIXES: Tuple[str, ...] = ("http://", "https://")

# Bounds that keep a hostile or oversized image from dominating parse time.
MAX_IMAGE_BYTES: int = 12_000_000
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

    if not image or len(image) > MAX_IMAGE_BYTES:
        return ()

    payloads: List[str] = []
    try:
        payloads = _decode_opencv(image) or _decode_pyzbar(image)
    except Exception:
        return ()

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
    if array is None:
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
        frame = handle.convert("L")
        symbols = decode(frame, symbols=[ZBarSymbol.QRCODE])
    return [symbol.data.decode("utf-8", "replace") for symbol in symbols]


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

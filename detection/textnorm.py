"""Deterministic Unicode normalization for phrase and brand matching.

Phishing text routinely defeats literal substring matching with HTML entities
(``&#118;erify``), Unicode homoglyphs (Cyrillic ``е`` in ``Wallеt``), combining
marks (``Aܿmܿaܿzܿon``), and mathematical alphanumeric letters (``𝘌𝘪𝘯𝘥𝘦``).

``normalize`` folds all of these into plain lower-case Latin text so that the
existing phrase lists match the text a human reads. It is a pure function of
its input: no locale, no network, no state.

The module also exposes obfuscation *counts*. Mixed-script and combining-mark
abuse is itself a detection signal, so the parser records how many characters
were folded; detectors can consume those counts without re-deriving them.
"""

import html
import unicodedata
from typing import Final, Mapping


# Homoglyph -> plain-Latin fold map. Deliberately small and static: it covers
# the confusables observed in phishing corpora (Cyrillic and Greek letters that
# render identically to Latin ones) rather than the full Unicode confusables
# database, so behaviour is auditable and deterministic.
CONFUSABLES: Final[Mapping[str, str]] = {
    # Cyrillic lower case
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k",
    "м": "m", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y",
    "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ԛ": "q", "ԝ": "w",
    # Cyrillic upper case
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
    "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek lower case
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
    # Greek upper case
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Latin-adjacent symbols not folded by NFKC
    "ℓ": "l", "℮": "e", "ı": "i", "ɡ": "g", "ǀ": "l",
}

# Mathematical Alphanumeric Symbols block (𝐀 .. 𝟿). NFKC folds these to plain
# Latin; the range is used only for counting obfuscated characters.
_MATH_ALPHANUMERIC_START: Final = 0x1D400
_MATH_ALPHANUMERIC_END: Final = 0x1D7FF


def normalize(text: str) -> str:
    """Return lower-case plain-Latin text suitable for phrase matching.

    Pipeline: HTML-entity unescape -> NFKC (folds math letters, fullwidth
    forms, ligatures) -> NFKD + strip combining marks (folds accents and
    combining-mark obfuscation) -> homoglyph fold -> casefold -> collapse
    whitespace. Deterministic and total: any ``str`` input yields a ``str``.
    """

    if not text:
        return ""
    unescaped = html.unescape(text)
    compat = unicodedata.normalize("NFKC", unescaped)
    decomposed = unicodedata.normalize("NFKD", compat)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    folded = "".join(CONFUSABLES.get(c, c) for c in stripped)
    return " ".join(folded.casefold().split())


def count_confusables(text: str) -> int:
    """Return the number of homoglyph or math-alphanumeric characters.

    Counted on the HTML-unescaped input, before any folding, so the value
    reflects what the sender actually transmitted.
    """

    if not text:
        return 0
    unescaped = html.unescape(text)
    return sum(
        1
        for c in unescaped
        if c in CONFUSABLES
        or _MATH_ALPHANUMERIC_START <= ord(c) <= _MATH_ALPHANUMERIC_END
    )


def count_combining_marks(text: str) -> int:
    """Return the number of combining-mark characters in the raw text.

    Precomposed accented letters (``é`` as one code point) are not counted;
    only explicit combining code points are, which is the pattern used to
    disguise brand names (``Aܿmܿaܿzܿon``).
    """

    if not text:
        return 0
    return sum(1 for c in text if unicodedata.combining(c))

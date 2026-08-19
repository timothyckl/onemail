"""Static brand vocabulary and legitimate-domain map for impersonation rules.

Brand names are written in *normalized* form (lower-case ASCII, see
``detection.textnorm.normalize``) because they are matched against normalized
display names and message text. Matching requires a left token boundary so
``apple`` does not match inside ``pineapple`` while ``paypal24`` still matches.

``BRAND_DOMAINS`` records the registered domains a brand legitimately mails
from or links to, so real brand mail stays clear. The map is deliberately
static and conservative: an unknown legitimate domain can only cause a false
positive on mail that *also* mentions the brand while linking elsewhere.
"""

import re
from typing import Final, Mapping, Optional, Tuple


# Original entries first; order defines match priority and is part of the
# deterministic contract.
BRANDS: Final[Tuple[str, ...]] = (
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "docusign",
    "office365",
    "google",
    "bank",
    "irs",
    "dhl",
    "fedex",
    # Crypto exchanges and wallets (dominant impersonation cluster in corpus).
    "binance",
    "coinbase",
    "metamask",
    "trust wallet",
    "ledger",
    "trezor",
    "kraken",
    "bitvavo",
    "kucoin",
    "ripple",
    # Brazilian banking / retail / loyalty.
    "banco do brasil",
    "bradesco",
    "itau",
    "nubank",
    "santander",
    "caixa",
    "livelo",
    "mercado livre",
    "mercado pago",
    "serasa",
    "correios",
    "americanas",
    # Payment / card networks.
    "american express",
    "wells fargo",
    "citibank",
    "hsbc",
    "barclays",
    "mastercard",
    # Tech and services.
    "adobe",
    "dropbox",
    "wetransfer",
    "linkedin",
    "facebook",
    "instagram",
    "whatsapp",
    "outlook",
    "onedrive",
    "sharepoint",
    "spotify",
    "mcafee",
    "norton",
    "geek squad",
    # Telecom, logistics, hospitality, retail.
    "at&t",
    "verizon",
    "vodafone",
    "usps",
    "royal mail",
    "correos",
    "hilton",
    "walmart",
    "costco",
)

# Generic terms kept for display-name spoof detection ("XYZ Bank Support")
# but excluded from content matching, where they would fire on ordinary prose.
GENERIC_BRANDS: Final[Tuple[str, ...]] = ("bank",)

CONTENT_BRANDS: Final[Tuple[str, ...]] = tuple(
    brand for brand in BRANDS if brand not in GENERIC_BRANDS
)

# Registered domains a brand legitimately uses. Compared with exact or
# dot-boundary suffix matching, so ``mail.livelo.com.br`` is related to
# ``livelo.com.br`` but ``evil-livelo.com.br.example.tld`` is not.
BRAND_DOMAINS: Final[Mapping[str, Tuple[str, ...]]] = {
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "msn.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.de", "amazon.fr", "amazon.it", "amazon.es"),
    "netflix": ("netflix.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "office365": ("microsoft.com", "office.com", "office365.com"),
    "google": ("google.com", "gmail.com", "googlemail.com", "youtube.com"),
    "irs": ("irs.gov",),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "metamask": ("metamask.io",),
    "trust wallet": ("trustwallet.com",),
    "ledger": ("ledger.com",),
    "trezor": ("trezor.io",),
    "kraken": ("kraken.com",),
    "bitvavo": ("bitvavo.com",),
    "kucoin": ("kucoin.com",),
    "ripple": ("ripple.com",),
    "banco do brasil": ("bb.com.br",),
    "bradesco": ("bradesco.com.br",),
    "itau": ("itau.com.br",),
    "nubank": ("nubank.com.br",),
    "santander": ("santander.com", "santander.com.br"),
    "caixa": ("caixa.gov.br",),
    "livelo": ("livelo.com.br",),
    "mercado livre": ("mercadolivre.com.br", "mercadolibre.com"),
    "mercado pago": ("mercadopago.com", "mercadopago.com.br"),
    "serasa": ("serasa.com.br",),
    "correios": ("correios.com.br",),
    "americanas": ("americanas.com.br",),
    "american express": ("americanexpress.com", "amex.com"),
    "wells fargo": ("wellsfargo.com",),
    "citibank": ("citibank.com", "citi.com"),
    "hsbc": ("hsbc.com",),
    "barclays": ("barclays.com",),
    "mastercard": ("mastercard.com",),
    "adobe": ("adobe.com",),
    "dropbox": ("dropbox.com",),
    "wetransfer": ("wetransfer.com",),
    "linkedin": ("linkedin.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "outlook": ("outlook.com", "microsoft.com", "live.com"),
    "onedrive": ("onedrive.com", "microsoft.com", "live.com"),
    "sharepoint": ("sharepoint.com", "microsoft.com"),
    "spotify": ("spotify.com",),
    "mcafee": ("mcafee.com",),
    "norton": ("norton.com", "nortonlifelock.com"),
    "geek squad": ("geeksquad.com", "bestbuy.com"),
    "at&t": ("att.com", "att.net"),
    "verizon": ("verizon.com", "verizon.net"),
    "vodafone": ("vodafone.com", "vodafone.de"),
    "usps": ("usps.com", "usps.gov"),
    "royal mail": ("royalmail.com",),
    "correos": ("correos.es",),
    "hilton": ("hilton.com",),
    "walmart": ("walmart.com",),
    "costco": ("costco.com",),
}


def _pattern(brand: str) -> "re.Pattern[str]":
    return re.compile(r"(?<![a-z0-9])" + re.escape(brand))


_BRAND_PATTERNS: Final[Tuple[Tuple[str, "re.Pattern[str]"], ...]] = tuple(
    (brand, _pattern(brand)) for brand in BRANDS
)
_CONTENT_BRAND_PATTERNS: Final[Tuple[Tuple[str, "re.Pattern[str]"], ...]] = tuple(
    (brand, _pattern(brand)) for brand in CONTENT_BRANDS
)


def find_brand(normalized_text: str) -> Optional[str]:
    """Return the first configured brand found in already-normalized text."""

    if not normalized_text:
        return None
    for brand, pattern in _BRAND_PATTERNS:
        if pattern.search(normalized_text):
            return brand
    return None


def find_content_brand(normalized_text: str) -> Optional[str]:
    """Return the first non-generic brand found in already-normalized text."""

    if not normalized_text:
        return None
    for brand, pattern in _CONTENT_BRAND_PATTERNS:
        if pattern.search(normalized_text):
            return brand
    return None


def brand_matches_domain(brand: str, host: Optional[str]) -> bool:
    """Return True when ``host`` plausibly belongs to ``brand``.

    Related when the space/ampersand-squeezed brand token occurs in the host
    (preserving the original ``brand in from_domain`` behaviour) or the host
    equals / is a subdomain of one of the brand's known registered domains.
    """

    if not brand or not host:
        return False
    candidate = host.strip().strip(".").lower()
    squeezed = brand.replace("&", "").replace(" ", "")
    if squeezed and squeezed in candidate:
        return True
    for domain in BRAND_DOMAINS.get(brand, ()):
        if candidate == domain or candidate.endswith("." + domain):
            return True
    return False

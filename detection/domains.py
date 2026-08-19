"""Registrable-domain derivation with a vendored static suffix list.

The original detector contract compared the final two DNS labels, which
breaks in two directions:

- ``example.co.uk`` and ``attacker.co.uk`` both reduced to ``co.uk`` and were
  treated as the *same* sender (false negatives across every ccTLD that
  registers at the third level, e.g. ``com.br`` -- ubiquitous in this corpus).
- ``victim.firebaseapp.com`` reduced to ``firebaseapp.com``, so a sender on a
  shared platform "owned" every other tenant of that platform.

This module vendors a small, auditable subset of the Public Suffix List
(multi-label public suffixes) plus shared-hosting platforms whose subdomains
belong to separate registrants. It is deliberately static data -- no network,
no dependency -- so results stay deterministic and reviewable.

Hosts whose suffix is not listed fall back to the original two-label rule,
so behaviour only ever changes where the naive rule was demonstrably wrong.
"""

from typing import Final, FrozenSet, Optional


# Multi-label *public* suffixes (subset of the PSL, most common ccTLD
# second-level registries, weighted toward languages seen in the corpus).
_PUBLIC_SUFFIXES: Final[FrozenSet[str]] = frozenset(
    {
        # United Kingdom
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk",
        "plc.uk", "sch.uk",
        # Brazil
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "adv.br", "art.br",
        "blog.br", "eco.br", "emp.br", "ind.br", "inf.br", "srv.br", "tv.br",
        # Australia / New Zealand
        "com.au", "net.au", "org.au", "gov.au", "edu.au", "id.au",
        "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
        # South Africa
        "co.za", "org.za", "net.za", "gov.za", "web.za", "ac.za",
        # Latin America
        "com.mx", "org.mx", "gob.mx", "edu.mx",
        "com.ar", "org.ar", "net.ar", "gob.ar", "edu.ar",
        "com.co", "net.co", "edu.co", "gov.co",
        "com.pe", "org.pe", "gob.pe",
        "com.ve", "org.ve", "gob.ve",
        "com.ec", "com.bo", "com.uy", "com.py", "com.do", "com.gt",
        "com.sv", "com.hn", "com.ni", "com.pa",
        # Asia
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "com.hk", "org.hk", "edu.hk", "gov.hk",
        "com.tw", "org.tw", "edu.tw", "gov.tw",
        "com.sg", "org.sg", "edu.sg", "gov.sg",
        "com.my", "org.my", "gov.my", "edu.my",
        "co.id", "or.id", "ac.id", "go.id", "web.id",
        "co.in", "org.in", "net.in", "gov.in", "ac.in", "firm.in",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr", "go.kr", "ac.kr",
        "co.th", "ac.th", "go.th", "or.th",
        "com.ph", "com.vn", "com.pk", "com.bd", "com.np",
        # Middle East / Africa
        "co.il", "org.il", "ac.il", "gov.il",
        "com.tr", "org.tr", "gov.tr", "edu.tr", "net.tr",
        "com.sa", "com.eg", "com.kw", "com.qa", "com.om", "com.lb",
        "com.jo", "com.ng", "com.gh", "com.ke", "co.ke",
        # Europe
        "com.ua", "org.ua", "net.ua", "gov.ua", "in.ua",
        "com.pl", "org.pl", "net.pl", "edu.pl", "gov.pl", "waw.pl",
        "com.pt", "edu.pt", "com.es", "nom.es", "org.es", "gob.es",
        "com.gr", "com.ro", "com.ru",
    }
)

# *Private* suffixes: shared platforms whose subdomains are separate tenants.
# A sender or link at ``tenant.<platform>`` must not be considered related to
# a different tenant on the same platform.
_PRIVATE_SUFFIXES: Final[FrozenSet[str]] = frozenset(
    {
        "firebaseapp.com",
        "web.app",
        "run.app",
        "appspot.com",
        "herokuapp.com",
        "github.io",
        "gitlab.io",
        "pages.dev",
        "workers.dev",
        "netlify.app",
        "vercel.app",
        "glitch.me",
        "repl.co",
        "blogspot.com",
        "wordpress.com",
        "wixsite.com",
        "weebly.com",
        "weeblysite.com",
        "000webhostapp.com",
        "godaddysites.com",
        "square.site",
        "canva.site",
        "zendesk.com",
        "myshopify.com",
        "azurewebsites.net",
        "cloudapp.net",
        "onmicrosoft.com",
        "sharepoint.com",
        "amazonaws.com",
        "s3.amazonaws.com",
        "cloudfront.net",
        "sendgrid.net",
    }
)

_SUFFIXES: Final[FrozenSet[str]] = _PUBLIC_SUFFIXES | _PRIVATE_SUFFIXES


def registered_domain(host: Optional[str]) -> Optional[str]:
    """Return the registrable domain for ``host``.

    Longest listed suffix wins; the registrable domain is that suffix plus
    one label. A host that *is* a listed suffix returns itself. Hosts with
    no listed suffix use the original final-two-labels rule.
    """

    if not host:
        return None
    labels = host.strip().strip(".").lower().split(".")
    # Scan from the longest candidate suffix to the shortest so the most
    # specific listed suffix (e.g. ``s3.amazonaws.com`` over
    # ``amazonaws.com``) determines the registrable boundary.
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in _SUFFIXES:
            start = index - 1 if index > 0 else 0
            return ".".join(labels[start:])
    return ".".join(labels if len(labels) <= 2 else labels[-2:])

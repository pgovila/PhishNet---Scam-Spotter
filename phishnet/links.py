"""PhishNet link analysis — offline URL inspection.

Extracts URLs from message text, classifies them against known official
domains, flags shorteners, raw IPs, homoglyphs, odd TLDs, and brand
impersonation.  NEVER fetches or visits a user-submitted URL (SSRF-safe).
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

# pyrefly: ignore[missing-import]
import tldextract

from phishnet.engine import CONFIG_DIR, Finding

# ── Config loading ────────────────────────────────────────────────────────────

_official_domains: set[str] | None = None
_brand_tokens: dict[str, list[str]] | None = None
_shorteners: set[str] | None = None


def _load_official_domains() -> tuple[set[str], dict[str, list[str]]]:
    """Load official_domains.yaml and build lookup structures."""
    global _official_domains, _brand_tokens
    if _official_domains is not None and _brand_tokens is not None:
        return _official_domains, _brand_tokens

    import yaml

    path = CONFIG_DIR / "official_domains.yaml"
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    domains: set[str] = set()
    tokens: dict[str, list[str]] = {}  # brand_token_lower → [official domains]

    for brand, dom_list in data.get("brands", {}).items():
        for d in dom_list:
            dl = d.lower().strip()
            domains.add(dl)
        # Create brand tokens for impersonation checks
        brand_lower = brand.lower().replace(" ", "")
        tokens[brand_lower] = [d.lower().strip() for d in dom_list]

    _official_domains = domains
    _brand_tokens = tokens
    return domains, tokens


def _load_shorteners() -> set[str]:
    """Load shorteners.txt."""
    global _shorteners
    if _shorteners is not None:
        return _shorteners

    path = CONFIG_DIR / "shorteners.txt"
    shorteners: set[str] = set()
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    shorteners.add(line.lower())
    _shorteners = shorteners
    return shorteners


# ── URL extraction ────────────────────────────────────────────────────────────

# Matches URLs with or without scheme, including common shortener patterns
_URL_RE = re.compile(
    r"""
    (?:https?://)?                        # optional scheme
    (?:                                    # domain part
        (?:[a-zA-Z0-9]                    # first char
        (?:[a-zA-Z0-9\-]{0,61}           # middle
        [a-zA-Z0-9])?                     # last char of label
        \.)+                              # dot
        [a-zA-Z]{2,63}                    # TLD
        |                                  # OR
        \d{1,3}(?:\.\d{1,3}){3}          # IPv4
    )
    (?::\d{1,5})?                         # optional port
    (?:/[^\s<>"')\]]*)?                   # optional path
    """,
    re.VERBOSE | re.IGNORECASE,
)


@dataclass
class ExtractedURL:
    """A URL found in the message text."""

    raw: str
    span: tuple[int, int]
    scheme: str
    domain: str  # registrable domain (e.g., "example.com")
    subdomain: str
    suffix: str  # TLD
    full_domain: str  # full FQDN
    is_ip: bool = False


def extract_urls(text: str) -> list[ExtractedURL]:
    """Extract URLs from text without fetching them."""
    results: list[ExtractedURL] = []
    seen: set[str] = set()

    for m in _URL_RE.finditer(text):
        raw = m.group()
        if raw in seen:
            continue
        seen.add(raw)

        # Add scheme for tldextract if missing
        url_for_parse = raw if "://" in raw else f"http://{raw}"

        # Use tldextract with bundled snapshot (no network)
        ext = tldextract.extract(url_for_parse)

        # Check for raw IP
        is_ip = False
        try:
            if not ext.suffix and ext.domain:
                # Might be raw IP
                ipaddress.ip_address(ext.domain)
                is_ip = True
        except ValueError:
            pass

        # Also check if the full netloc is an IP
        netloc_match = re.match(r"(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3})", raw)
        if netloc_match:
            is_ip = True

        reg_domain = (
            ext.top_domain_under_public_suffix
            if hasattr(ext, "top_domain_under_public_suffix")
            else ext.domain
        ) or ext.domain
        full_domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}".strip(".")

        scheme = "https" if raw.lower().startswith("https") else "http"
        if "://" not in raw:
            scheme = "none"

        results.append(
            ExtractedURL(
                raw=raw,
                span=(m.start(), m.end()),
                scheme=scheme,
                domain=reg_domain.lower(),
                subdomain=ext.subdomain.lower(),
                suffix=ext.suffix.lower(),
                full_domain=full_domain.lower(),
                is_ip=is_ip,
            )
        )

    return results


# ── Homoglyph detection ──────────────────────────────────────────────────────

# Common homoglyph characters that can fool users
_HOMOGLYPHS: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0501": "d",  # Cyrillic ԁ
    "\u050d": "h",  # Cyrillic Ԍ
    "\u0261": "g",  # Latin ɡ
    "\u1d00": "a",  # Latin ᴀ
    "\u0251": "a",  # Latin ɑ
    "\u025b": "e",  # Latin ɛ
}


def _has_homoglyphs(domain: str) -> bool:
    """Check if domain contains homoglyph characters."""
    for char in domain:
        if char in _HOMOGLYPHS:
            return True
        # Check for mixed scripts
        if ord(char) > 127 and unicodedata.category(char).startswith("L"):
            return True
    return False


# ── Edit distance ─────────────────────────────────────────────────────────────


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(
                min(
                    curr_row[j] + 1,
                    prev_row[j + 1] + 1,
                    prev_row[j] + cost,
                )
            )
        prev_row = curr_row

    return prev_row[-1]


# ── Odd TLD list ──────────────────────────────────────────────────────────────

_ODD_TLDS: set[str] = {
    "xyz",
    "top",
    "click",
    "loan",
    "work",
    "gq",
    "cf",
    "tk",
    "ml",
    "ga",
    "buzz",
    "icu",
    "cam",
    "rest",
    "surf",
    "monster",
    "sbs",
    "cfd",
    "lol",
    "bond",
    "quest",
}


# ── Main link analysis ───────────────────────────────────────────────────────


def analyse_links(
    text: str,
    *,
    link_rule_id: str = "ask_link",
    link_points: int = 25,
) -> list[Finding]:
    """Analyse all URLs in text and produce link findings.

    This is pure offline analysis — no URLs are ever fetched.

    Args:
        text: Normalised message text.
        link_rule_id: Rule ID to assign to link findings.
        link_points: Base points for a risky link finding.

    Returns:
        List of Finding objects for risky links.
    """
    urls = extract_urls(text)
    if not urls:
        return []

    official_domains, brand_tokens = _load_official_domains()
    shorteners = _load_shorteners()

    findings: list[Finding] = []

    for url in urls:
        reasons: list[str] = []

        # 1. Is it a shortener?
        if url.domain in shorteners or url.full_domain in shorteners:
            reasons.append("Shortened URL — hides the real destination")

        # 2. Raw IP address?
        if url.is_ip:
            reasons.append("Raw IP address — legitimate services use domain names")

        # 3. HTTP without TLS?
        if url.scheme == "http":
            reasons.append("Uses HTTP without encryption (no HTTPS)")

        # 4. Homoglyph characters?
        if _has_homoglyphs(url.full_domain):
            reasons.append("Contains look-alike (homoglyph) characters in domain")

        # 5. Is it an official domain?
        if url.domain in official_domains:
            # This is an official domain — not risky
            continue

        # 6. Brand impersonation?
        for brand_token, off_domains in brand_tokens.items():
            if brand_token in url.full_domain.replace(".", "").replace("-", ""):
                if url.domain not in official_domains:
                    reasons.append(
                        f"Contains '{brand_token}' but is not an official domain "
                        f"(official: {', '.join(off_domains[:2])})"
                    )
                    break

        # 7. Edit distance from official domain?
        for off_domain in official_domains:
            if _levenshtein(url.domain, off_domain) <= 2 and url.domain != off_domain:
                reasons.append(
                    f"Very similar to official domain '{off_domain}' (possible typosquatting)"
                )
                break

        # 8. Odd TLD?
        if url.suffix in _ODD_TLDS:
            reasons.append(f"Unusual TLD '.{url.suffix}' — commonly abused")

        # 9. Mixed-script IDN?
        try:
            url.full_domain.encode("ascii")
        except UnicodeEncodeError:
            reasons.append("Internationalised domain — may be a look-alike attack")

        # If we found any reason, it's risky
        if reasons:
            findings.append(
                Finding(
                    rule_id=link_rule_id,
                    category="ask",
                    label="Risky link",
                    label_hi="संदिग्ध लिंक",
                    points=link_points,
                    matched_text=url.raw,
                    span=url.span,
                    reason="; ".join(reasons),
                )
            )

    # Deduplicate — one link finding per unique domain
    seen_domains: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        # Extract domain from the matched text
        ext = tldextract.extract(
            f.matched_text if "://" in f.matched_text else f"http://{f.matched_text}"
        )
        dom = (
            ext.top_domain_under_public_suffix
            if hasattr(ext, "top_domain_under_public_suffix")
            else ext.domain
        ) or ext.domain
        if dom not in seen_domains:
            seen_domains.add(dom)
            deduped.append(f)

    return deduped

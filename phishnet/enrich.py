"""PhishNet online enrichment — optional external API checks.

Each enrichment source is behind its own env key, has a 3-second timeout,
caches results, and NEVER breaks core analysis on failure.  Findings from
enrichment are labelled separately.

Supported sources:
- Google Safe Browsing v4  (GSB_API_KEY)
- VirusTotal v3            (VT_API_KEY)
- URLhaus by abuse.ch      (URLHAUS_AUTH_KEY)
- RDAP for domain age      (no key required)

A confirmed-malicious result from any source adds +10 to the link finding.
A domain under 30 days old (via RDAP) adds +10.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache

import requests

logger = logging.getLogger(__name__)

TIMEOUT = 3  # seconds


@dataclass
class EnrichmentResult:
    """Result from an enrichment source."""

    source: str
    url: str
    is_malicious: bool
    detail: str
    extra_points: int = 0


# ── Google Safe Browsing v4 ───────────────────────────────────────────────────


@lru_cache(maxsize=256)
def check_safe_browsing(url: str) -> EnrichmentResult | None:
    """Check URL against Google Safe Browsing v4.

    Requires GSB_API_KEY env variable.
    Free for non-commercial use; Web Risk API is the commercial equivalent.
    """
    api_key = os.environ.get("GSB_API_KEY")
    if not api_key:
        return None

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishnet", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            threat_type = matches[0].get("threatType", "UNKNOWN")
            return EnrichmentResult(
                source="Google Safe Browsing",
                url=url,
                is_malicious=True,
                detail=f"Flagged as {threat_type}",
                extra_points=10,
            )
        return EnrichmentResult(
            source="Google Safe Browsing",
            url=url,
            is_malicious=False,
            detail="Not flagged",
        )
    except Exception as exc:
        logger.warning("Safe Browsing check failed for %s: %s", url, exc)
        return None


# ── VirusTotal v3 ─────────────────────────────────────────────────────────────


@lru_cache(maxsize=256)
def check_virustotal(url: str) -> EnrichmentResult | None:
    """Check URL against VirusTotal v3.

    Requires VT_API_KEY env variable.
    Free tier is rate-limited (4 lookups/min, 500/day).
    """
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return None

    import base64

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(endpoint, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 404:
            return EnrichmentResult(
                source="VirusTotal",
                url=url,
                is_malicious=False,
                detail="URL not in database",
            )
        resp.raise_for_status()
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0 or suspicious > 2:
            return EnrichmentResult(
                source="VirusTotal",
                url=url,
                is_malicious=True,
                detail=f"{malicious} engines flagged as malicious, {suspicious} suspicious",
                extra_points=10,
            )
        return EnrichmentResult(
            source="VirusTotal",
            url=url,
            is_malicious=False,
            detail=f"{malicious} malicious, {suspicious} suspicious",
        )
    except Exception as exc:
        logger.warning("VirusTotal check failed for %s: %s", url, exc)
        return None


# ── URLhaus (abuse.ch) ────────────────────────────────────────────────────────


@lru_cache(maxsize=256)
def check_urlhaus(url: str) -> EnrichmentResult | None:
    """Check URL against URLhaus by abuse.ch.

    Requires URLHAUS_AUTH_KEY env variable.
    Free; see https://urlhaus-api.abuse.ch for current terms.
    """
    auth_key = os.environ.get("URLHAUS_AUTH_KEY")
    if not auth_key:
        return None

    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        resp = requests.post(
            endpoint,
            data={"url": url},
            headers={"Auth-Key": auth_key},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")
        if status == "ok":
            threat = data.get("threat", "unknown")
            return EnrichmentResult(
                source="URLhaus",
                url=url,
                is_malicious=True,
                detail=f"Known malicious — threat: {threat}",
                extra_points=10,
            )
        return EnrichmentResult(
            source="URLhaus",
            url=url,
            is_malicious=False,
            detail="Not in URLhaus database",
        )
    except Exception as exc:
        logger.warning("URLhaus check failed for %s: %s", url, exc)
        return None


# ── RDAP domain age ───────────────────────────────────────────────────────────


@lru_cache(maxsize=256)
def check_domain_age(domain: str) -> EnrichmentResult | None:
    """Check domain registration age via RDAP (no API key needed).

    A domain under 30 days old adds +10 points.
    """
    endpoint = f"https://rdap.org/domain/{domain}"
    try:
        resp = requests.get(endpoint, timeout=TIMEOUT)
        if resp.status_code != 200:
            return None
        data = resp.json()

        # Find registration event
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                reg_date_str = event.get("eventDate", "")
                reg_date = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - reg_date).days
                is_new = age_days < 30
                return EnrichmentResult(
                    source="RDAP Domain Age",
                    url=domain,
                    is_malicious=is_new,
                    detail=f"Domain registered {age_days} days ago"
                    + (" — very new, higher risk" if is_new else ""),
                    extra_points=10 if is_new else 0,
                )
        return None
    except Exception as exc:
        logger.warning("RDAP check failed for %s: %s", domain, exc)
        return None


# ── Orchestrator ──────────────────────────────────────────────────────────────


def enrich_urls(urls: list[str]) -> list[EnrichmentResult]:
    """Run all enabled enrichment checks on a list of URLs.

    Each check is independent; failures are logged but never break analysis.
    Results are cached via lru_cache.

    Args:
        urls: List of raw URL strings extracted from the message.

    Returns:
        List of EnrichmentResult objects.
    """
    results: list[EnrichmentResult] = []

    for url in urls:
        # Normalise URL for checks
        check_url = url if "://" in url else f"http://{url}"

        for checker in (check_safe_browsing, check_virustotal, check_urlhaus):
            result = checker(check_url)
            if result is not None:
                results.append(result)

        # RDAP check uses just the domain
        # pyrefly: ignore[missing-import]
        import tldextract

        ext = tldextract.extract(check_url)
        domain = (
            ext.top_domain_under_public_suffix
            if hasattr(ext, "top_domain_under_public_suffix")
            else ext.domain
        ) or ext.domain
        if domain:
            result = check_domain_age(domain)
            if result is not None:
                results.append(result)

    return results

"""PhishNet link analysis tests."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path when running script directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phishnet.links import (  # noqa: E402
    _has_homoglyphs,
    _levenshtein,
    analyse_links,
    extract_urls,
)


class TestURLExtraction:
    """Test URL extraction from text."""

    def test_http_url(self):
        urls = extract_urls("Visit http://example.com/page")
        assert len(urls) >= 1
        assert any("example.com" in u.domain for u in urls)

    def test_https_url(self):
        urls = extract_urls("Visit https://secure.example.com/path?q=1")
        assert len(urls) >= 1

    def test_schemeless_url(self):
        urls = extract_urls("Check example.com/page")
        assert len(urls) >= 1

    def test_shortener(self):
        urls = extract_urls("Click bit.ly/abc123")
        assert len(urls) >= 1
        assert any("bit.ly" in u.full_domain for u in urls)

    def test_ip_address(self):
        urls = extract_urls("Visit http://192.168.1.1/admin")
        assert len(urls) >= 1
        assert any(u.is_ip for u in urls)

    def test_no_url(self):
        urls = extract_urls("Hello, this is a normal message")
        assert len(urls) == 0


class TestLinkAnalysis:
    """Test link finding generation."""

    def test_shortener_finding(self):
        findings = analyse_links("Check bit.ly/xyz")
        assert len(findings) >= 1
        assert findings[0].category == "ask"
        assert findings[0].points == 25

    def test_official_domain_no_finding(self):
        findings = analyse_links("Visit https://sbi.co.in/personal-banking")
        assert len(findings) == 0

    def test_brand_impersonation(self):
        findings = analyse_links("Visit http://sbi-kyc-update.example/verify")
        assert len(findings) >= 1
        # Should flag brand impersonation
        assert any("sbi" in f.reason.lower() for f in findings)

    def test_http_without_tls(self):
        findings = analyse_links("Go to http://suspicious-site.com/login")
        assert len(findings) >= 1
        assert any("HTTP" in f.reason or "http" in f.reason.lower() for f in findings)

    def test_odd_tld(self):
        findings = analyse_links("Visit https://free-prize.xyz/claim")
        assert len(findings) >= 1

    def test_no_links_no_findings(self):
        findings = analyse_links("This is just text")
        assert len(findings) == 0


class TestHomoglyphs:
    """Test homoglyph detection."""

    def test_cyrillic_a(self):
        # Cyrillic а looks like Latin a
        assert _has_homoglyphs("g\u0430ogle.com")

    def test_normal_domain(self):
        assert not _has_homoglyphs("google.com")


class TestLevenshtein:
    """Test edit distance calculation."""

    def test_same_string(self):
        assert _levenshtein("test", "test") == 0

    def test_one_edit(self):
        assert _levenshtein("test", "tset") == 2  # transposition = 2 edits
        assert _levenshtein("test", "tests") == 1

    def test_completely_different(self):
        assert _levenshtein("abc", "xyz") == 3

    def test_typosquat(self):
        # sbi.co.in vs sbi.co.ln — edit distance 1
        assert _levenshtein("sbi.co.in", "sbi.co.ln") == 1


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([str(Path(__file__))]))


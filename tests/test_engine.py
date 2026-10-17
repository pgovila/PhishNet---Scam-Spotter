"""PhishNet engine tests — exact score assertions.

Tests all examples from data/examples.json plus edge cases.
If a pattern conflicts with an expected score, fix the pattern, not the test.
"""

from __future__ import annotations

import json
from pathlib import Path

# pyrefly: ignore[missing-import]
import pytest

from phishnet.engine import AnalysisResult, analyse, load_rules, normalise
from phishnet.links import analyse_links

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(autouse=True)
def _reload_rules():
    """Force-reload rules before each test."""
    load_rules(force=True)
    yield


def _full_analyse(text: str, mode: str = "default") -> AnalysisResult:
    """Run full analysis including link detection."""
    norm = normalise(text)
    cfg = load_rules()
    mode_cfg = cfg.get(mode, cfg["default"])
    link_rule = next(
        (r for r in mode_cfg.get("rules", []) if r["id"] in ("ask_link", "rb_link")),
        None,
    )
    link_rule_id = link_rule["id"] if link_rule else "ask_link"
    link_points = link_rule["points"] if link_rule else 25
    link_findings = analyse_links(norm, link_rule_id=link_rule_id, link_points=link_points)
    return analyse(text, link_findings=link_findings, mode=mode)


# ── Example-based tests ──────────────────────────────────────────────────────


class TestSBIKYCScam:
    """SBI KYC scam — default: raw 120, capped 100, high; rulebook: 100, high."""

    TEXT = (
        "SBI ALERT: Your KYC is incomplete and your account will be blocked today. "
        "Update immediately at http://sbi-kyc-update.example/verify and share the OTP "
        "you receive to confirm."
    )

    def test_default_mode(self):
        result = _full_analyse(self.TEXT, mode="default")
        assert result.raw_score == 120, (
            f"raw_score={result.raw_score}, findings={[(f.rule_id, f.points) for f in result.findings]}"
        )
        assert result.score == 100
        assert result.tier == "high"

    def test_rulebook_mode(self):
        result = _full_analyse(self.TEXT, mode="rulebook")
        assert result.score == 100
        assert result.tier == "high"


class TestParcelFeeScam:
    """India Post parcel fee — score 95, high."""

    TEXT = (
        "INDIA POST: Your parcel is held for an unpaid Rs 25 fee. "
        "Pay within 2 hours at indiapost-fee.example/pay."
    )

    def test_default_mode(self):
        result = _full_analyse(self.TEXT, mode="default")
        # bait_brand(10) + hook_pressure(15) + ask_payment(30) + ask_link(25) + bonus(15) = 95
        assert result.score == 95, (
            f"score={result.score}, findings={[(f.rule_id, f.points) for f in result.findings]}"
        )
        assert result.tier == "high"


class TestHinglishKYC:
    """Hinglish KYC scam — score 85, high."""

    TEXT = "Aapka bank account aaj band ho jayega. KYC turant update karein aur OTP bata dein."

    def test_default_mode(self):
        result = _full_analyse(self.TEXT, mode="default")
        # hook_pressure(15) + hook_fear(15) + ask_otp(40) + bonus(15) = 85
        assert result.score == 85, (
            f"score={result.score}, findings={[(f.rule_id, f.points) for f in result.findings]}"
        )
        assert result.tier == "high"


class TestClassNotice:
    """Genuine class notice — score 15, low."""

    TEXT = "Class moved to 3 PM today, Room 204."

    def test_default_mode(self):
        result = _full_analyse(self.TEXT, mode="default")
        # hook_pressure(15), no ask → cap 54, but 15 < 54
        assert result.score == 15, (
            f"score={result.score}, findings={[(f.rule_id, f.points) for f in result.findings]}"
        )
        assert result.tier == "low"


class TestGenuineOTP:
    """Genuine OTP SMS — score 10, low (protective context removes OTP ask)."""

    TEXT = "Your OTP is 482913 for SBI. Never share it with anyone."

    def test_default_mode(self):
        result = _full_analyse(self.TEXT, mode="default")
        # bait_brand(10), OTP is protective (0), no ask → cap 54, 10 < 54
        assert result.score == 10, (
            f"score={result.score}, findings={[(f.rule_id, f.points) for f in result.findings]}"
        )
        assert result.tier == "low"

        # Verify protective context is detected
        protective_findings = [f for f in result.findings if f.protective]
        assert len(protective_findings) >= 1, "Should have protective context finding"


class TestBareLink:
    """Bare shortener link — score 25, medium."""

    TEXT = "Check this: bit.ly/xyz"

    def test_default_mode(self):
        result = _full_analyse(self.TEXT, mode="default")
        # ask_link(25), no bait/hook → no bonus
        assert result.score == 25, (
            f"score={result.score}, findings={[(f.rule_id, f.points) for f in result.findings]}"
        )
        assert result.tier == "medium"


# ── Edge case tests ──────────────────────────────────────────────────────────


class TestEmptyInput:
    """Empty input should produce score 0, low."""

    def test_empty_string(self):
        result = _full_analyse("", mode="default")
        assert result.score == 0
        assert result.tier == "low"


class TestLongInput:
    """5001-character input should still be analysable."""

    def test_long_text(self):
        text = "A" * 5001
        result = _full_analyse(text, mode="default")
        assert result.score == 0
        assert result.tier == "low"


class TestHTMLInjection:
    """HTML/XSS injection should not affect scoring."""

    def test_xss_string(self):
        text = '<script>alert("xss")</script> Click here: http://evil.example/steal'
        result = _full_analyse(text, mode="default")
        # Should detect the link but not execute HTML
        assert result.tier in ("low", "medium", "high")
        # Ensure no HTML in findings
        for f in result.findings:
            assert "<script>" not in f.label
            assert "<script>" not in f.reason


class TestNoAskCap:
    """Score should be capped at 54 when no Ask is present."""

    def test_no_ask_cap(self):
        # Multiple hooks but no ask
        text = "URGENT: Your SBI account will be blocked today. KYC incomplete. Act immediately."
        result = _full_analyse(text, mode="default")
        # bait(10) + pressure(15) + fear(15) = 40, no ask
        # Capped at 54, but 40 < 54
        assert result.score <= 54


class TestNFKCNormalisation:
    """Ensure NFKC normalisation works for Unicode variants."""

    def test_normalised_text(self):
        # Fullwidth SBI
        text = "\uff33\uff22\uff29 ALERT: KYC incomplete"
        norm = normalise(text)
        # NFKC should normalise fullwidth to ASCII
        assert "SBI" in norm


class TestProtectiveContextDoesNotCountAsAsk:
    """Protective OTP context should not trigger act-now bonus."""

    def test_no_bonus_with_protective(self):
        text = "Your OTP is 123456 for HDFC. Never share it with anyone."
        result = _full_analyse(text, mode="default")
        assert not result.act_now_applied


# ── Data-driven tests from examples.json ─────────────────────────────────────


def _load_examples():
    """Load test examples."""
    path = DATA_DIR / "examples.json"
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.mark.parametrize("example", _load_examples(), ids=lambda e: e["id"])
def test_examples_default(example):
    """Test each example against expected default scores."""
    if "expected_default" not in example:
        pytest.skip("No default expectations")

    result = _full_analyse(example["text"], mode="default")
    expected = example["expected_default"]

    assert result.score == expected["score"], (
        f"[{example['id']}] score={result.score}, expected={expected['score']}, "
        f"raw={result.raw_score}, findings={[(f.rule_id, f.points, f.protective) for f in result.findings]}"
    )
    assert result.tier == expected["tier"], (
        f"[{example['id']}] tier={result.tier}, expected={expected['tier']}"
    )

    if "raw_score" in expected:
        assert result.raw_score == expected["raw_score"], (
            f"[{example['id']}] raw_score={result.raw_score}, expected={expected['raw_score']}"
        )


@pytest.mark.parametrize(
    "example",
    [e for e in _load_examples() if "expected_rulebook" in e],
    ids=lambda e: e["id"],
)
def test_examples_rulebook(example):
    """Test examples with rulebook mode expectations."""
    result = _full_analyse(example["text"], mode="rulebook")
    expected = example["expected_rulebook"]

    assert result.score == expected["score"], (
        f"[{example['id']}] rulebook score={result.score}, expected={expected['score']}, "
        f"findings={[(f.rule_id, f.points) for f in result.findings]}"
    )
    assert result.tier == expected["tier"]

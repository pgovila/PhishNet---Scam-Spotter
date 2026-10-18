"""PhishNet engine tests — exact score assertions.

Tests all examples from data/examples.json plus edge cases.
If a pattern conflicts with an expected score, fix the pattern, not the test.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure project root is in sys.path when running script directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# pyrefly: ignore[missing-import]
import pytest  # noqa: E402

from phishnet.engine import AnalysisResult, analyse, load_rules, normalise  # noqa: E402
from phishnet.links import analyse_links  # noqa: E402

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


class TestBankDebitAlert:
    """Authentic bank debit alert with dispute advisory should remain Low risk."""

    TEXT = (
        "Dear Customer, your a/c 1234 is debited by Rs 500 on 18-Oct-26. "
        "If not done by you, call 1800112211 immediately. -SBI"
    )

    def test_debit_alert_protective_urgency(self):
        result = _full_analyse(self.TEXT, mode="default")
        assert result.score <= 15
        assert result.tier == "low"
        # Check that urgency is recognized as protective
        pressure_findings = [f for f in result.findings if f.rule_id == "hook_pressure"]
        assert len(pressure_findings) >= 1
        assert pressure_findings[0].protective is True


class TestFreshScamDetections:
    """Verify previously missed scam patterns are properly detected."""

    def test_electricity_power_cut_tonight(self):
        text = "Your electricity power supply will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer immediately."
        result = _full_analyse(text, mode="default")
        assert result.score >= 30
        assert result.tier in ("medium", "high")

    def test_hotel_rating_work_from_home(self):
        text = (
            "Work from home job: Rate hotels on google and earn Rs 3000 daily. Contact on Telegram."
        )
        result = _full_analyse(text, mode="default")
        assert result.score >= 30
        assert result.tier in ("medium", "high")

    def test_sim_kyc_6_digit_code(self):
        text = "Dear customer your SIM KYC is pending. Please share the 6-digit code sent to your number to prevent SIM deactivation."
        result = _full_analyse(text, mode="default")
        assert result.score >= 60
        assert result.tier == "high"

    def test_netflix_card_update(self):
        text = "Netflix: Your membership is on hold. Please update your card immediately to avoid cancellation: http://netflix-billing.example"
        result = _full_analyse(text, mode="default")
        assert result.score >= 60
        assert result.tier == "high"


class TestMultipleSpanHighlighting:
    """Ensure all matching phrases are preserved in findings for highlighting."""

    def test_sbi_multiple_spans_preserved(self):
        result = _full_analyse(TestSBIKYCScam.TEXT, mode="default")
        matched_texts = [f.matched_text for f in result.findings]
        # In SBI sample, both 'account will be blocked' and 'KYC is incomplete' should be present
        assert any("blocked" in t for t in matched_texts)
        assert any("incomplete" in t for t in matched_texts)
        # Both 'today' and 'immediately' should be present
        assert any("today" in t for t in matched_texts)
        assert any("immediately" in t for t in matched_texts)
        # But points are only awarded once per rule
        assert result.raw_score == 120
        assert result.score == 100


def test_fake_lpg_subsidy_with_lookalike_link():
    """LPG subsidy scam with unbranded deceptive link must score High."""
    from phishnet.links import analyse_links

    text = "LPG Subsidy credited of Rs 400. Claim your subsidy now at http://lpg-subsidy-claim.xyz/portal"
    link_findings = analyse_links(normalise(text))
    result = analyse(text, link_findings=link_findings)
    assert result.score >= 55
    assert result.tier == "high"
    assert "LPG" in result.scam_type


def test_police_video_call_digital_arrest():
    """Police alert video call arrest scam must score High."""
    text = "Police alert: Your Aadhaar was used in money laundering. Join the video call immediately or you'll be arrested."
    result = analyse(text)
    assert result.score >= 50
    assert result.tier in ("medium", "high")
    assert "Digital Arrest" in result.scam_type


def test_part_time_job_whatsapp_group():
    """Part-time job with WhatsApp group invite must score Medium/High."""
    text = "Part-time job offer: Earn Rs 3000 to Rs 5000 daily from home. Join our WhatsApp group to start tasks now."
    result = analyse(text)
    assert result.score >= 50
    assert result.tier in ("medium", "high")
    assert "Job" in result.scam_type


def test_trai_number_disconnection_notice():
    """TRAI number disconnection threat must score Medium/High."""
    text = "TRAI notice: Your mobile number will be disconnected in 2 hours due to illegal activity. Contact authority immediately."
    result = analyse(text)
    assert result.score >= 45
    assert result.tier in ("medium", "high")


def test_fake_debit_alert_callback_scam():
    """Fake debit alert with callback number must score Medium/High."""
    text = "Alert: Rs 14,999 debited from your card. If not you, call 9876543210 immediately to cancel this transaction."
    result = analyse(text)
    assert result.score >= 50
    assert result.tier in ("medium", "high")
    assert "Callback" in result.scam_type


def test_genuine_hackathon_fee_reminder():
    """Genuine hackathon registration fee with deadline must stay Low (safe)."""
    text = "Reminder: Your hackathon registration fee of Rs 250 is due by tonight. See you at the auditorium."
    result = analyse(text)
    assert result.score <= 25
    assert result.tier == "low"


def test_genuine_library_overdue_notice():
    """Library overdue notice with fine must stay Low (safe)."""
    text = (
        "Library Notice: Book returned late. Please pay fine of Rs 10 at the circulation counter."
    )
    result = analyse(text)
    assert result.score <= 25
    assert result.tier == "low"


if __name__ == "__main__":
    sys.exit(pytest.main([str(Path(__file__))]))


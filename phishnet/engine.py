"""PhishNet core analysis engine — pure functions, no side-effects.

Loads rules from config/rules.yaml once, then applies them to arbitrary
message text.  Every score is computed deterministically from the rule
definitions; AI never sets or changes a score.
"""

from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ── Types ─────────────────────────────────────────────────────────────────────

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


@dataclass
class Finding:
    """A single matched rule finding."""

    rule_id: str
    category: str  # bait | hook | ask
    label: str
    label_hi: str
    points: int
    matched_text: str
    span: tuple[int, int]  # (start, end) in the *normalised* text
    reason: str = ""
    protective: bool = False  # True ⇒ protective context, points zeroed


@dataclass
class AnalysisResult:
    """Complete analysis output for a message."""

    findings: list[Finding] = field(default_factory=list)
    raw_score: int = 0
    score: int = 0
    tier: str = "low"
    next_steps: list[str] = field(default_factory=list)
    mode: str = "default"
    act_now_applied: bool = False


# ── Config loader ─────────────────────────────────────────────────────────────

_cached_config: dict[str, Any] | None = None


def load_rules(force: bool = False) -> dict[str, Any]:
    """Load and cache rules.yaml.  Thread-safe enough for Streamlit."""
    global _cached_config
    if _cached_config is not None and not force:
        return _cached_config
    rules_path = CONFIG_DIR / "rules.yaml"
    with open(rules_path, encoding="utf-8") as fh:
        _cached_config = yaml.safe_load(fh)
    return _cached_config


def _mode_config(cfg: dict[str, Any], mode: str) -> dict[str, Any]:
    """Return the sub-config for the given mode."""
    return cfg.get(mode, cfg["default"])


# ── Normalisation ─────────────────────────────────────────────────────────────


def normalise(text: str) -> str:
    """NFKC-normalise text for consistent matching."""
    return unicodedata.normalize("NFKC", text)


# ── Pattern matching ─────────────────────────────────────────────────────────


def _compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    """Compile a list of regex strings (case-insensitive)."""
    compiled: list[re.Pattern[str]] = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE | re.UNICODE))
        except re.error:
            continue
    return compiled


def _match_rule(
    rule: dict[str, Any],
    text: str,
) -> list[Finding]:
    """Match a single rule against text, returning all findings."""
    findings: list[Finding] = []
    patterns = _compile_patterns(rule.get("patterns", []))
    seen_spans: set[tuple[int, int]] = set()

    for pat in patterns:
        for m in pat.finditer(text):
            span = (m.start(), m.end())
            if span in seen_spans:
                continue
            seen_spans.add(span)
            findings.append(
                Finding(
                    rule_id=rule["id"],
                    category=rule["category"],
                    label=rule.get("label", rule["id"]),
                    label_hi=rule.get("label_hi", rule.get("label", rule["id"])),
                    points=rule["points"],
                    matched_text=m.group(),
                    span=span,
                )
            )

    return findings


# ── Protective context ────────────────────────────────────────────────────────


def _check_protective_context(
    text: str,
    otp_findings: list[Finding],
    protective_patterns: list[str],
) -> list[Finding]:
    """Mark OTP/PIN findings as protective if context says 'never share'."""
    if not otp_findings or not protective_patterns:
        return otp_findings

    compiled = _compile_patterns(protective_patterns)
    has_protective = any(pat.search(text) for pat in compiled)

    if has_protective:
        for f in otp_findings:
            f.protective = True
            f.points = 0
            f.reason = "Protective context — advises not to share"

    return otp_findings


# ── Score calculation ─────────────────────────────────────────────────────────


def _compute_score(
    findings: list[Finding],
    mode_cfg: dict[str, Any],
) -> tuple[int, int, bool]:
    """Compute raw_score, capped score, and whether act-now bonus applied.

    Returns (raw_score, score, act_now_applied).
    """
    active_findings = [f for f in findings if not f.protective]

    raw = sum(f.points for f in active_findings)

    categories = {f.category for f in active_findings}
    has_ask = "ask" in categories
    has_bait_or_hook = bool(categories & {"bait", "hook"})
    act_now = False

    if has_ask and has_bait_or_hook and mode_cfg.get("act_now_bonus", 0) > 0:
        raw += mode_cfg["act_now_bonus"]
        act_now = True

    capped = min(raw, mode_cfg.get("max_score", 100))

    no_ask_cap = mode_cfg.get("no_ask_cap", 100)
    if not has_ask and capped > no_ask_cap:
        capped = no_ask_cap

    return raw, capped, act_now


def _tier_for_score(score: int, mode_cfg: dict[str, Any]) -> str:
    """Determine tier label from score."""
    tiers = mode_cfg.get("tiers", {})
    for tier_name in ("high", "medium", "low"):
        bounds = tiers.get(tier_name)
        if bounds and bounds[0] <= score <= bounds[1]:
            return tier_name
    if score >= tiers.get("high", [55, 100])[0]:
        return "high"
    return "low"


# ── Next steps ────────────────────────────────────────────────────────────────

NEXT_STEPS: dict[str, list[str]] = {
    "high": [
        "🚫 Do NOT click any link in this message.",
        "🔒 Do NOT share OTP, PIN, CVV or passwords with anyone.",
        "📞 Contact your bank ONLY through its official app or the number on your card.",
        "🆘 If money is lost, call the cyber-crime helpline 1930 immediately.",
        "🌐 Report at https://cybercrime.gov.in",
        "📱 Report the sender via DoT Sanchar Saathi Chakshu: https://sancharsaathi.gov.in/sfc/Home/sfc-complaint.jsp",
    ],
    "medium": [
        "⚠️ Verify this message through an official channel before acting.",
        "🔍 Search for the sender's number or domain on the official website.",
        "📱 Report suspicious messages via DoT Sanchar Saathi Chakshu: https://sancharsaathi.gov.in/sfc/Home/sfc-complaint.jsp",
    ],
    "low": [
        "✅ This looks safe, but always stay alert.",
        "💡 Never share OTP, PIN or passwords — no legitimate service will ask.",
    ],
}

NEXT_STEPS_HI: dict[str, list[str]] = {
    "high": [
        "🚫 इस संदेश में किसी भी लिंक पर क्लिक न करें।",
        "🔒 OTP, PIN, CVV या पासवर्ड किसी को न बताएं।",
        "📞 बैंक से संपर्क केवल उसके आधिकारिक ऐप या कार्ड पर छपे नंबर से करें।",
        "🆘 अगर पैसे गए हैं तो तुरंत 1930 पर कॉल करें।",
        "🌐 शिकायत दर्ज करें: https://cybercrime.gov.in",
        "📱 DoT संचार साथी चक्षु पर रिपोर्ट करें: https://sancharsaathi.gov.in/sfc/Home/sfc-complaint.jsp",
    ],
    "medium": [
        "⚠️ कार्रवाई से पहले आधिकारिक चैनल से सत्यापित करें।",
        "🔍 भेजने वाले का नंबर या डोमेन आधिकारिक वेबसाइट पर खोजें।",
        "📱 संदिग्ध संदेश DoT संचार साथी चक्षु पर रिपोर्ट करें: https://sancharsaathi.gov.in/sfc/Home/sfc-complaint.jsp",
    ],
    "low": [
        "✅ यह सुरक्षित दिखता है, लेकिन सतर्क रहें।",
        "💡 OTP, PIN या पासवर्ड कभी किसी को न बताएं — कोई भी असली सेवा नहीं माँगती।",
    ],
}


# ── Main analysis ─────────────────────────────────────────────────────────────


def analyse(
    text: str,
    *,
    link_findings: list[Finding] | None = None,
    mode: str | None = None,
) -> AnalysisResult:
    """Analyse a message and return scored findings.

    Args:
        text: Raw user-submitted message text.
        link_findings: Pre-computed link findings from links.py.
        mode: "default" or "rulebook".  None reads RULEBOOK_MODE env.

    Returns:
        AnalysisResult with findings, score, tier, and next steps.
    """
    if mode is None:
        mode = "rulebook" if os.environ.get("RULEBOOK_MODE") == "1" else "default"

    cfg = load_rules()
    mode_cfg = _mode_config(cfg, mode)
    norm_text = normalise(text)

    all_findings: list[Finding] = []
    otp_findings: list[Finding] = []

    for rule in mode_cfg.get("rules", []):
        if not rule.get("patterns"):
            continue
        matched = _match_rule(rule, norm_text)
        if rule["id"] in ("ask_otp", "rb_otp"):
            otp_findings.extend(matched)
        else:
            all_findings.extend(matched)

    # De-duplicate: keep one finding per rule ID (highest-point span)
    deduped: dict[str, Finding] = {}
    for f in all_findings:
        if f.rule_id not in deduped or f.points > deduped[f.rule_id].points:
            deduped[f.rule_id] = f
    all_findings = list(deduped.values())

    # Check protective context for OTP findings
    protective_cfg = mode_cfg.get("protective_context", {})
    otp_findings = _check_protective_context(
        norm_text,
        otp_findings,
        protective_cfg.get("patterns", []),
    )

    # De-duplicate OTP findings too
    if otp_findings:
        # Keep one representative OTP finding
        best_otp = max(otp_findings, key=lambda f: f.points)
        # If protective, keep all as protective markers
        if best_otp.protective:
            all_findings.append(best_otp)
        else:
            deduped_otp: dict[str, Finding] = {}
            for f in otp_findings:
                if f.rule_id not in deduped_otp or f.points > deduped_otp[f.rule_id].points:
                    deduped_otp[f.rule_id] = f
            all_findings.extend(deduped_otp.values())

    # Add link findings (computed externally by links.py)
    if link_findings:
        all_findings.extend(link_findings)

    # Compute score
    raw_score, score, act_now = _compute_score(all_findings, mode_cfg)
    tier = _tier_for_score(score, mode_cfg)

    return AnalysisResult(
        findings=sorted(all_findings, key=lambda f: _cat_order(f.category)),
        raw_score=raw_score,
        score=score,
        tier=tier,
        next_steps=NEXT_STEPS.get(tier, []),
        mode=mode,
        act_now_applied=act_now,
    )


def _cat_order(cat: str) -> int:
    """Sort order for categories: bait → hook → ask."""
    return {"bait": 0, "hook": 1, "ask": 2}.get(cat, 3)

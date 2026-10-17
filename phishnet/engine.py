"""PhishNet core analysis engine — pure functions, no side-effects.

Loads rules from config/rules.yaml once, then applies them to arbitrary
message text. Every score is computed deterministically from the rule
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

# Strip zero-width and invisible control characters used in obfuscation/evasion
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\ufeff\u00ad\u2060\u200e\u200f]")

# Word character class including ASCII alphanumeric and Devanagari letters/marks,
# explicitly excluding danda (\u0964) and double danda (\u0965)
_WORD_CHAR = r"[a-zA-Z0-9\u0900-\u0963\u0970-\u097F]"
_CUSTOM_BOUNDARY = rf"(?:(?<={_WORD_CHAR})(?!{_WORD_CHAR})|(?<!{_WORD_CHAR})(?={_WORD_CHAR}))"

# Sentence delimiters for sentence-scoped protective context
_SENTENCE_DELIM_RE = re.compile(r"(?:[\r\n]+|(?<=[.!?;\u0964\u0965])\s+)")


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
    reason_hi: str = ""
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
    """Load and cache rules.yaml. Thread-safe enough for Streamlit."""
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
    """NFKC-normalise text and strip invisible zero-width evasion characters."""
    if not text:
        return ""
    # Strip invisible zero-width characters (e.g. \u200b, \ufeff)
    stripped = _ZERO_WIDTH_RE.sub("", text)
    return unicodedata.normalize("NFKC", stripped)


# ── Pattern matching ─────────────────────────────────────────────────────────


def _compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    """Compile a list of regex strings with script-aware boundary adaptation."""
    compiled: list[re.Pattern[str]] = []
    for p in patterns:
        try:
            # Replace \b with custom boundary to correctly handle Devanagari vowel marks & dandas
            adapted = p.replace(r"\b", _CUSTOM_BOUNDARY)
            compiled.append(re.compile(adapted, re.IGNORECASE | re.UNICODE))
        except re.error:
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

    default_reason = rule.get("reason", "")
    default_reason_hi = rule.get("reason_hi", "")

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
                    reason=default_reason,
                    reason_hi=default_reason_hi,
                )
            )

    return findings


# ── Protective context ────────────────────────────────────────────────────────


def _extract_sentence_for_span(text: str, span: tuple[int, int]) -> str:
    """Find the specific sentence or clause containing the given span."""
    delims = list(_SENTENCE_DELIM_RE.finditer(text))
    bounds = [0] + [m.end() for m in delims] + [len(text)]
    start, end = span
    for i in range(len(bounds) - 1):
        if bounds[i] <= start and end <= bounds[i + 1]:
            return text[bounds[i] : bounds[i + 1]]
    # Fallback to entire text if boundaries are ambiguous
    return text


def _check_protective_context(
    text: str,
    otp_findings: list[Finding],
    protective_patterns: list[str],
) -> list[Finding]:
    """Mark OTP/PIN findings as protective if context says 'never share' in the same sentence."""
    if not protective_patterns:
        return otp_findings

    compiled = _compile_patterns(protective_patterns)

    if otp_findings:
        for f in otp_findings:
            sentence = _extract_sentence_for_span(text, f.span)
            if any(pat.search(sentence) for pat in compiled):
                f.protective = True
                f.points = 0
                f.reason = (
                    "Protective advisory — warns never to share credentials (safe banking notice)."
                )
                f.reason_hi = "सुरक्षा चेतावनी — कभी भी पासवर्ड/OTP साझा न करने की सलाह (वैध बैंक सूचना)।"
        return otp_findings

    # Check for genuine informational OTP notification with protective advice
    # e.g. 'Your OTP is 482913 for SBI. Never share it with anyone.'
    otp_mention = re.search(r"\b(?:OTP|one[- ]time\s*password|passcode)\b", text, re.I)
    has_protective = any(pat.search(text) for pat in compiled)
    if otp_mention and has_protective:
        span = otp_mention.span()
        return [
            Finding(
                rule_id="ask_otp",
                category="ask",
                label="Protective advisory (Never share OTP)",
                label_hi="सुरक्षा चेतावनी (OTP साझा न करें)",
                points=0,
                matched_text=otp_mention.group(),
                span=span,
                reason="Protective context — advises not to share OTP.",
                reason_hi="सुरक्षा चेतावनी — OTP साझा न करने की सलाह।",
                protective=True,
            )
        ]

    return otp_findings


# ── Institutional / Official domain context ───────────────────────────────────


def _check_institutional_context(
    findings: list[Finding],
    norm_text: str,
) -> None:
    """Neutralize false urgency and payment requests when linked strictly to official domains.

    E.g., college fee reminder with an official .ac.in / .edu.in link, or electricity bill
    on a .gov.in portal.
    """
    from phishnet.links import extract_urls

    urls = extract_urls(norm_text)
    if not urls:
        return

    # Check if there are any risky link findings
    has_risky_link = any(
        f.rule_id in ("ask_link", "rb_link") and not f.protective and f.points >= 20
        for f in findings
    )
    if has_risky_link:
        return

    # Check if all links in the text are official/institutional
    official_suffixes = ("gov.in", "nic.in", "ac.in", "edu.in", "res.in")
    all_official = True
    for u in urls:
        is_official = (
            any(
                u.full_domain.endswith("." + sfx) or u.full_domain == sfx
                for sfx in official_suffixes
            )
            or u.suffix in official_suffixes
        )
        if not is_official:
            all_official = False
            break

    if all_official and urls:
        # All URLs are verified government or academic institutional domains
        for f in findings:
            if f.rule_id in ("ask_payment", "hook_pressure"):
                f.points = 0
                f.protective = True
                f.reason = (
                    f"Institutional notice: Verified official portal ({urls[0].full_domain})."
                )
                f.reason_hi = f"आधिकारिक संस्थागत सूचना: सत्यापित पोर्टल ({urls[0].full_domain})।"


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
    enrichment_results: list[Any] | None = None,
    mode: str | None = None,
) -> AnalysisResult:
    """Analyse a message and return scored findings.

    Args:
        text: Raw user-submitted message text.
        link_findings: Pre-computed link findings from links.py.
        enrichment_results: Optional online threat enrichment results.
        mode: "default" or "rulebook". None reads RULEBOOK_MODE env.

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

    # Check protective context for OTP findings (sentence-scoped)
    protective_cfg = mode_cfg.get("protective_context", {})
    otp_findings = _check_protective_context(
        norm_text,
        otp_findings,
        protective_cfg.get("patterns", []),
    )

    # De-duplicate OTP findings
    if otp_findings:
        best_otp = max(otp_findings, key=lambda f: f.points)
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

    # Neutralize payment and urgency if all links point strictly to official/institutional portals
    _check_institutional_context(all_findings, norm_text)

    # Compute base score
    raw_score, score, act_now = _compute_score(all_findings, mode_cfg)

    # Incorporate online enrichment points uniformly (if provided)
    if enrichment_results:
        for er in enrichment_results:
            extra = getattr(er, "extra_points", 0)
            if extra > 0:
                raw_score += extra
                score = min(score + extra, mode_cfg.get("max_score", 100))

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

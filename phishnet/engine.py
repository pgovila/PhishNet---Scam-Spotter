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
    scam_type: str = ""
    scam_type_hi: str = ""
    scam_advice: str = ""
    scam_advice_hi: str = ""


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


def _check_transaction_context(
    findings: list[Finding],
    norm_text: str,
) -> None:
    """Neutralize false urgency in authentic bank debit/credit dispute notifications.

    E.g.: 'Rs 1500 debited from SBI a/c 1234 on 18-Oct. If not done by you, call 1800112211 immediately. -SBI'
    The 'call ... immediately' is an RBI-mandated dispute instruction, not a scam pressure hook.
    """
    # Only applies if there is NO malicious ask (no link, no OTP/credential ask, no payment ask)
    has_ask = any(f.category == "ask" and not f.protective and f.points > 0 for f in findings)
    if has_ask:
        return

    # Check for authentic transaction markers
    tx_pattern = re.search(
        r"\b(?:debited|credited|withdrawn|spent|transferred|a/c\s*(?:no\.?|\*+|x+)?\s*\d+)\b",
        norm_text,
        re.I,
    )
    # Check for dispute advisory phrases
    dispute_pattern = re.search(
        r"\b(?:if\s*not\s*(?:done\s*)?(?:by\s*)?you|if\s*not\s*you|if\s*unauthorized|report\s*(?:fraud|unauthorized))\b",
        norm_text,
        re.I,
    )

    if tx_pattern and dispute_pattern:
        for f in findings:
            if f.rule_id in ("hook_pressure", "rb_urgency"):
                f.points = 0
                f.protective = True
                f.reason = "Protective bank advisory — instructions to report unauthorized transactions immediately (RBI customer safety mandate)."
                f.reason_hi = (
                    "सुरक्षा बैंक सलाह — अनधिकृत लेनदेन की तुरंत शिकायत करने के निर्देश (RBI सुरक्षा निर्देश)।"
                )


def _deduplicate_findings_keep_spans(findings: list[Finding]) -> list[Finding]:
    """Keep all matched spans for highlighting, but award points only once per rule."""
    if not findings:
        return []

    # Filter exact duplicate spans within the same rule
    seen_spans_per_rule: dict[str, set[tuple[int, int]]] = {}
    awarded_rules: set[str] = set()
    result: list[Finding] = []

    # Sort so that highest-point finding per rule comes first
    sorted_f = sorted(findings, key=lambda f: -f.points)

    for f in sorted_f:
        rule_seen = seen_spans_per_rule.setdefault(f.rule_id, set())
        if f.span in rule_seen:
            continue
        rule_seen.add(f.span)

        if f.rule_id not in awarded_rules:
            awarded_rules.add(f.rule_id)
            result.append(f)
        else:
            # Additional phrase for this rule: keep for highlighting with points=0
            dup_f = Finding(
                rule_id=f.rule_id,
                category=f.category,
                label=f.label,
                label_hi=f.label_hi,
                points=0,
                matched_text=f.matched_text,
                span=f.span,
                reason=f.reason,
                reason_hi=f.reason_hi,
                protective=f.protective,
            )
            result.append(dup_f)

    # Sort by span position ascending
    result.sort(key=lambda f: f.span[0])
    return result


# ── Score calculation ─────────────────────────────────────────────────────────


def _compute_score(
    findings: list[Finding],
    mode_cfg: dict[str, Any],
) -> tuple[int, int, bool]:
    """Compute raw_score, capped score, and whether act-now bonus applied.

    Returns (raw_score, score, act_now_applied).
    """
    active_findings = [f for f in findings if not f.protective]

    # Deceptive context signals: bait, fear hook, or dangerous ask (link, otp, remote, callback, apk, collect)
    active_rule_ids = {f.rule_id for f in active_findings if f.points > 0}
    has_bait = any(f.category == "bait" and f.points > 0 for f in active_findings)
    has_fear = any(
        f.rule_id in ("hook_fear", "rb_account_threat") and f.points > 0 for f in active_findings
    )
    has_critical_ask = bool(
        active_rule_ids
        & {
            "ask_link",
            "rb_link",
            "ask_otp",
            "rb_otp",
            "ask_remote_access",
            "ask_apk_install",
            "ask_collect_request",
            "ask_callback",
        }
    )

    # If the only ask is a bare payment/fee request with NO bait, NO fear, and NO critical ask (e.g. hackathon registration fee, library overdue fine),
    # scale the fee finding down to 10 points and urgency down to 5 points so benign notices stay in Low (<= 24).
    if "ask_payment" in active_rule_ids and not (has_bait or has_fear or has_critical_ask):
        for f in findings:
            if f.rule_id == "ask_payment":
                f.points = 10
                f.reason = "Mentions payment or administrative fee without deceptive links or brand impersonation."
                f.reason_hi = "बिना किसी धोखाधड़ी वाले लिंक या फर्जी ब्रांड के प्रशासनिक शुल्क/भुगतान का उल्लेख।"
            elif f.rule_id in ("hook_pressure", "rb_urgency"):
                f.points = 5
                f.reason = "Informational deadline on an administrative notice."
                f.reason_hi = "प्रशासनिक सूचना पर समय-सीमा का उल्लेख।"

    raw = sum(f.points for f in active_findings)

    categories = {f.category for f in active_findings if f.points > 0}
    has_ask = "ask" in categories
    has_bait_or_hook = bool(categories & {"bait", "hook"})
    act_now = False

    # Act-now bonus applies ONLY when an Ask combines with genuine deceptive indicators (Bait or Fear or Critical Ask)
    is_deceptive_combination = (has_bait or has_fear or has_critical_ask) and has_bait_or_hook
    if has_ask and is_deceptive_combination and mode_cfg.get("act_now_bonus", 0) > 0:
        raw += mode_cfg["act_now_bonus"]
        act_now = True

    capped = min(raw, mode_cfg.get("max_score", 100))

    no_ask_cap = mode_cfg.get("no_ask_cap", 100)
    if not has_ask and capped > no_ask_cap:
        capped = no_ask_cap

    return raw, capped, act_now


# ── Scam Type Classification & Advice ─────────────────────────────────────────

_SCAM_TYPES: list[dict[str, Any]] = [
    {
        "id": "digital_arrest",
        "label": "Digital Arrest / Law Enforcement Impersonation",
        "label_hi": "डिजिटल अरेस्ट / पुलिस का नाम लेकर ठगी",
        "advice": "Police, CBI, Customs or Judges never hold trials, arrest suspects, or demand money via video call.",
        "advice_hi": "पुलिस, सीबीआई या अदालत कभी भी वीडियो कॉल पर पूछताछ या 'डिजिटल अरेस्ट' नहीं करती। तुरंत कॉल काटें।",
        "primary_rules": {"bait_authority"},
        "keywords": [
            r"video\s*call",
            r"arrest",
            r"digital\s*arrest",
            r"cbi",
            r"police",
            r"customs",
            r"contraband",
            r"skype",
            r"court\s*notice",
            r"warrant",
        ],
    },
    {
        "id": "kyc_suspension",
        "label": "Bank / SIM KYC Deactivation Scam",
        "label_hi": "बैंक / सिम केवाईसी बंद होने का झांसा",
        "advice": "Banks and telecom operators never deactivate accounts over SMS links or ask for OTPs to update KYC.",
        "advice_hi": "बैंक या सिम कंपनियां कभी भी एसएमएस लिंक से केवाईसी अपडेट करने या ओटीपी मांगने को नहीं कहतीं।",
        "primary_rules": set(),
        "keywords": [
            r"kyc",
            r"account\b.{0,20}?\b(?:block|suspend|deactivat|clos|band)",
            r"netbanking",
            r"pan\s*card",
            r"sim\b.{0,20}?\b(?:deactivat|block|suspend|5g)",
        ],
    },
    {
        "id": "parcel_delivery",
        "label": "Fake Parcel / Courier Delivery Fee Scam",
        "label_hi": "फर्जी पार्सल / कूरियर डिलीवरी शुल्क धोखा",
        "advice": "Postal services and couriers never hold packages demanding immediate online payment via SMS links.",
        "advice_hi": "डाक विभाग या कूरियर कंपनियां कभी भी एसएमएस लिंक से तत्काल पार्सल शुल्क भुगतान की मांग नहीं करतीं।",
        "primary_rules": set(),
        "keywords": [
            r"parcel",
            r"india\s*post",
            r"courier",
            r"shipment",
            r"delivery\s*(?:fee|charge|attempt)",
            r"redelivery",
            r"package",
        ],
    },
    {
        "id": "callback_scam",
        "label": "Fake Debit Alert / Callback Trap",
        "label_hi": "फर्जी डेबिट अलर्ट / कॉल बैक झांसा",
        "advice": "Never call the cancellation number given in an SMS. Check your bank statement via your official banking app.",
        "advice_hi": "एसएमएस में दिए गए नंबर पर कभी कॉल न करें। अपने आधिकारिक बैंक ऐप में जाकर स्टेटमेंट चेक करें।",
        "primary_rules": {"ask_callback"},
        "keywords": [
            r"to\s*cancel\s*(?:call|contact)",
            r"call\b.{0,40}?\b(?:cancel|stop|dispute)",
            r"call\s*this\s*number",
        ],
    },
    {
        "id": "electricity_cutoff",
        "label": "Electricity Bill Disconnection Scam",
        "label_hi": "बिजली बिल बकाया / कनेक्शन कटने की धमकी",
        "advice": "Power discoms do not send personal mobile numbers for bill payments or disconnect power within hours.",
        "advice_hi": "बिजली विभाग कभी व्यक्तिगत मोबाइल नंबर भेजकर बिल भुगतान या कनेक्शन काटने की धमकी नहीं देता।",
        "primary_rules": set(),
        "keywords": [
            r"electricity",
            r"power\s*cut",
            r"power\b.{0,25}?\bdisconnect",
            r"bijli",
            r"discom",
            r"previous\s*month\s*bill",
        ],
    },
    {
        "id": "lpg_subsidy",
        "label": "LPG / Government Subsidy Phishing",
        "label_hi": "एलपीजी / सरकारी योजना सब्सिडी फ्रॉड",
        "advice": "Government subsidies are credited automatically via Direct Benefit Transfer (DBT); no form link is required.",
        "advice_hi": "सरकारी सब्सिडी सीधे बैंक खाते में (डीबीटी) आती है। किसी भी लिंक पर जाकर फॉर्म भरने की जरूरत नहीं होती।",
        "primary_rules": {"bait_subsidy"},
        "keywords": [
            r"subsidy",
            r"lpg",
            r"ujjwala",
            r"cylinder",
            r"kisan\s*samman",
            r"gas\s*subsidy",
        ],
    },
    {
        "id": "part_time_job",
        "label": "Part-Time Job / Telegram Task Scam",
        "label_hi": "पार्ट-टाइम नौकरी / टेलीग्राम टास्क घोटाला",
        "advice": "Offers paying ₹2,000–₹5,000 daily for liking videos or rating hotels are advance-fee fraud traps.",
        "advice_hi": "यूट्यूब वीडियो लाइक करने या होटल रेटिंग पर रोजाना हजारों रुपये देने का वादा 100% फर्जी टास्क फ्रॉड है।",
        "primary_rules": {"ask_group_join"},
        "keywords": [
            r"part[- ]time",
            r"telegram\s*(?:task|group|channel)",
            r"whatsapp\s*group",
            r"like\s*youtube",
            r"rate\s*hotel",
            r"earn\s*(?:from\s*home|daily)",
        ],
    },
    {
        "id": "apk_malware",
        "label": "Malicious APK Sideloading",
        "label_hi": "खतरनाक APK फाइल / मोबाइल मैलवेयर",
        "advice": "Never install .apk files received over SMS or WhatsApp; they are banking trojans designed to steal OTPs.",
        "advice_hi": "एसएमएस या वॉट्सऐप पर आई .apk फाइल कभी इंस्टॉल न करें; यह बैंकिंग ओटीपी चुराने वाला वायरस है।",
        "primary_rules": {"ask_apk_install"},
        "keywords": [r"\.apk\b", r"apk\s*file"],
    },
    {
        "id": "remote_access",
        "label": "Remote Desktop Screen-Sharing Trap",
        "label_hi": "स्क्रीन-शेयरिंग ऐप (AnyDesk/TeamViewer) फ्रॉड",
        "advice": "Installing remote desktop apps allows scammers to view your screen and empty your bank account.",
        "advice_hi": "AnyDesk या TeamViewer जैसे ऐप डाउनलोड करने से जालसाज आपके पूरे फोन और बैंक खाते पर कब्जा कर लेते हैं।",
        "primary_rules": {"ask_remote_access"},
        "keywords": [r"anydesk", r"teamviewer", r"quicksupport", r"rustdesk", r"screen\s*share"],
    },
    {
        "id": "upi_collect",
        "label": "Fraudulent UPI Collect / Refund Trick",
        "label_hi": "फर्जी यूपीआई पिन / कलेक्ट रिक्वेस्ट धोखा",
        "advice": "UPI PIN is required ONLY to send money, NEVER to receive refunds, cashbacks, or lottery payouts.",
        "advice_hi": "यूपीआई पिन केवल पैसे भेजने के लिए होता है, रिफंड या पैसे पाने के लिए कभी पिन नहीं डाला जाता।",
        "primary_rules": {"ask_collect_request"},
        "keywords": [
            r"enter\s*(?:upi\s*)?pin\s*to\s*(?:receive|credit|get)",
            r"approve\s*(?:upi\s*)?collect",
        ],
    },
]


def classify_scam_type(
    findings: list[Finding],
    text: str,
    tier: str,
) -> tuple[str, str, str, str]:
    """Classify the primary scam tactic and provide one-line protection advice.

    Uses weighted scoring across primary rule hits and explicit thematic keywords.
    Returns (label_en, label_hi, advice_en, advice_hi).
    """
    if tier == "low":
        return "", "", "", ""

    rule_ids = {f.rule_id for f in findings if not f.protective}
    text_lower = text.lower()

    best_type: dict[str, Any] | None = None
    best_score = 0

    for st_item in _SCAM_TYPES:
        score = 0

        # Primary rule match gives high confidence weight (+10)
        if st_item["primary_rules"] and (rule_ids & st_item["primary_rules"]):
            score += 10

        # Explicit keywords matched in text
        for kw_pat in st_item["keywords"]:
            if re.search(kw_pat, text_lower):
                score += 5

        if score > best_score:
            best_score = score
            best_type = st_item

    if best_type and best_score >= 5:
        return (
            best_type["label"],
            best_type["label_hi"],
            best_type["advice"],
            best_type["advice_hi"],
        )

    # Fallback for general phishing/scams
    return (
        "Suspicious Social Engineering",
        "संदिग्ध डिजिटल झांसा (फ़िशिंग)",
        "Do not click unverified links, call unverified numbers, or share any OTP or personal information.",
        "किसी भी अज्ञात लिंक पर क्लिक न करें, अज्ञात नंबर पर कॉल न करें और कोई भी ओटीपी साझा न करें।",
    )


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

    # Check protective context for OTP findings (sentence-scoped)
    protective_cfg = mode_cfg.get("protective_context", {})
    otp_findings = _check_protective_context(
        norm_text,
        otp_findings,
        protective_cfg.get("patterns", []),
    )
    all_findings.extend(otp_findings)

    # Add link findings (computed externally by links.py)
    if link_findings:
        all_findings.extend(link_findings)

    # Neutralize payment and urgency if all links point strictly to official/institutional portals
    _check_institutional_context(all_findings, norm_text)

    # Neutralize urgency if authentic bank transaction alert with dispute advisory
    _check_transaction_context(all_findings, norm_text)

    # Keep all non-overlapping matched spans for highlighting, while deduplicating points per rule
    all_findings = _deduplicate_findings_keep_spans(all_findings)

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

    scam_type, scam_type_hi, scam_advice, scam_advice_hi = classify_scam_type(
        all_findings, norm_text, tier
    )

    return AnalysisResult(
        findings=sorted(all_findings, key=lambda f: _cat_order(f.category)),
        raw_score=raw_score,
        score=score,
        tier=tier,
        next_steps=NEXT_STEPS.get(tier, []),
        mode=mode,
        act_now_applied=act_now,
        scam_type=scam_type,
        scam_type_hi=scam_type_hi,
        scam_advice=scam_advice,
        scam_advice_hi=scam_advice_hi,
    )


def _cat_order(cat: str) -> int:
    """Sort order for categories: bait → hook → ask."""
    return {"bait": 0, "hook": 1, "ask": 2}.get(cat, 3)

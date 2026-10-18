"""PhishNet i18n — English / Hindi text strings.

Simple key-value approach.  No external dependency.
"""

from __future__ import annotations

STRINGS: dict[str, dict[str, str]] = {
    "app_title": {
        "en": "🎣 PhishNet — Scam Message Analyser",
        "hi": "🎣 फ़िशनेट — स्कैम संदेश विश्लेषक",
    },
    "tagline": {
        "en": "Spot the bait. See the hook. Skip the ask.",
        "hi": "चारा पहचानो। हुक देखो। माँग टालो।",
    },
    "input_label": {
        "en": "Paste a suspicious message below",
        "hi": "संदिग्ध संदेश नीचे पेस्ट करें",
    },
    "upload_label": {
        "en": "Or upload a screenshot",
        "hi": "या स्क्रीनशॉट अपलोड करें",
    },
    "analyse_btn": {
        "en": "🔍 Analyse",
        "hi": "🔍 जाँच करें",
    },
    "score_label": {
        "en": "Risk Score",
        "hi": "जोखिम स्कोर",
    },
    "tier_high": {
        "en": "⛔ HIGH RISK — Likely a scam",
        "hi": "⛔ उच्च जोखिम — संभावित धोखाधड़ी",
    },
    "tier_medium": {
        "en": "⚠️ MEDIUM RISK — Suspicious, verify first",
        "hi": "⚠️ मध्यम जोखिम — संदिग्ध, पहले सत्यापित करें",
    },
    "tier_low": {
        "en": "✅ LOW RISK — Looks safe",
        "hi": "✅ कम जोखिम — सुरक्षित दिखता है",
    },
    "findings_header": {
        "en": "Findings",
        "hi": "निष्कर्ष",
    },
    "category_bait": {
        "en": "🪤 Bait — Borrowed Trust",
        "hi": "🪤 चारा — उधार का भरोसा",
    },
    "category_hook": {
        "en": "🪝 Hook — Pressure & Fear",
        "hi": "🪝 हुक — दबाव और डर",
    },
    "category_ask": {
        "en": "🎯 Ask — Risky Action",
        "hi": "🎯 माँग — जोखिम भरी कार्रवाई",
    },
    "next_steps_header": {
        "en": "What to do now",
        "hi": "अब क्या करें",
    },
    "copy_report": {
        "en": "📋 Copy Report",
        "hi": "📋 रिपोर्ट कॉपी करें",
    },
    "empty_msg": {
        "en": "Please paste a message or upload a screenshot to analyse.",
        "hi": "कृपया जाँच के लिए कोई संदेश पेस्ट करें या स्क्रीनशॉट अपलोड करें।",
    },
    "too_short": {
        "en": "Message is too short (minimum 10 characters). Please paste the full message.",
        "hi": "संदेश बहुत छोटा है (कम से कम 10 अक्षर)। कृपया पूरा संदेश पेस्ट करें।",
    },
    "too_long": {
        "en": "Message is too long (maximum 5000 characters). Please shorten it.",
        "hi": "संदेश बहुत लंबा है (अधिकतम 5000 अक्षर)। कृपया छोटा करें।",
    },
    "try_examples": {
        "en": "Try an example",
        "hi": "एक उदाहरण आज़माएं",
    },
    "ai_consent_label": {
        "en": "Enable AI simplification (text is sent to an external API)",
        "hi": "AI सरलीकरण चालू करें (पाठ बाहरी API को भेजा जाएगा)",
    },
    "ai_simplified": {
        "en": "AI-simplified explanation",
        "hi": "AI-सरलीकृत व्याख्या",
    },
    "protective_label": {
        "en": "Protective context (no points)",
        "hi": "सुरक्षात्मक संदर्भ (कोई अंक नहीं)",
    },
    "act_now_bonus": {
        "en": "Act-now bonus: Bait/Hook + Ask co-occur",
        "hi": "तुरंत-कार्रवाई बोनस: चारा/हुक + माँग एक साथ",
    },
    "enrichment_header": {
        "en": "🌐 Online Enrichment Results",
        "hi": "🌐 ऑनलाइन संवर्धन परिणाम",
    },
    "include_message_label": {
        "en": "Include message text in report",
        "hi": "रिपोर्ट में संदेश पाठ शामिल करें",
    },
    "mode_label": {
        "en": "Scoring mode",
        "hi": "स्कोरिंग मोड",
    },
    "dpdp_notice": {
        "en": "Designed around DPDP principles (data minimisation, no message retention). Core analysis runs locally without storing message content. (If optional AI or threat lookups are turned on, anonymized queries are sent externally).",
        "hi": "DPDP सिद्धांतों (डेटा न्यूनीकरण, शून्य संदेश प्रतिधारण) पर आधारित। मुख्य विश्लेषण स्थानीय रूप से चलता है और संदेश संग्रहीत नहीं होते। (यदि वैकल्पिक AI या थ्रेट लुकअप सक्षम हैं, तो अनामीकृत विवरण बाहर भेजे जाते हैं)।",
    },
    "footer_privacy": {
        "en": "Designed around DPDP Principles · Data Minimisation & Zero Retention · Core analysis runs in ephemeral memory",
        "hi": "DPDP सिद्धांतों पर आधारित · डेटा न्यूनीकरण एवं शून्य प्रतिधारण · मुख्य विश्लेषण अल्पकालिक मेमोरी में चलता है",
    },
}


def t(key: str, lang: str = "en") -> str:
    """Get translated string.

    Args:
        key: Translation key.
        lang: Language code ("en" or "hi").

    Returns:
        Translated string, or English fallback, or the key itself.
    """
    entry = STRINGS.get(key, {})
    return entry.get(lang, entry.get("en", key))

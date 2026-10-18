"""Build PhishNet submission PDF from submission.yaml.

Usage:
    python scripts/build_submission_pdf.py

Reads submission.yaml from the project root and produces PhishNet_Submission.pdf.
Validates that all URLs (demo_video_url, live_url, github_url) are reachable.
Stops with a clear error if any URL is missing or unreachable.
"""

from __future__ import annotations

import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import qrcode
import requests
import yaml
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Image as RLImage,
)
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PDF = PROJECT_ROOT / "PhishNet_Submission.pdf"

# ── Colours ───────────────────────────────────────────────────────────────────

BG_DARK = colors.HexColor("#14171C")
CARD_BG = colors.HexColor("#1E232B")
TEXT_WHITE = colors.white
CRIMSON = colors.HexColor("#EF4444")
AMBER = colors.HexColor("#F5A524")
EMERALD = colors.HexColor("#10B981")
ACCENT = colors.HexColor("#3B82F6")


# ── Helpers ───────────────────────────────────────────────────────────────────


def validate_url(url: str, label: str) -> None:
    """Check that a URL is reachable. Exit with error if not."""
    if not url or not url.strip():
        print(f"ERROR: {label} is empty in submission.yaml. Fill it in before building the PDF.")
        sys.exit(1)
    clean_url = url.strip()
    try:
        resp = requests.head(clean_url, timeout=10, allow_redirects=True)
        if resp.status_code >= 400:
            resp = requests.get(clean_url, timeout=10, stream=True)
        if resp.status_code >= 400:
            print(f"ERROR: {label} ({clean_url}) returned HTTP {resp.status_code}.")
            sys.exit(1)
        print(f"  ✓ {label}: {clean_url}")
    except requests.RequestException as e:
        print(f"ERROR: {label} ({clean_url}) is not reachable: {e}")
        sys.exit(1)


def make_qr(url: str, path: Path) -> Path:
    """Generate a QR code image for a URL."""
    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="white", back_color="#14171C")
    img.save(str(path))
    return path


def load_config() -> dict:
    """Load submission.yaml."""
    config_path = PROJECT_ROOT / "submission.yaml"
    if not config_path.exists():
        print("ERROR: submission.yaml not found in project root.")
        sys.exit(1)
    with open(config_path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ── PDF Builder ───────────────────────────────────────────────────────────────


def build_pdf() -> None:
    """Build the submission PDF."""
    config = load_config()
    team = config.get("team", {})

    print("Validating URLs…")
    validate_url(config.get("demo_video_url", ""), "demo_video_url")
    validate_url(config.get("live_url", ""), "live_url")
    validate_url(config.get("github_url", ""), "github_url")
    print()

    # Generate QR codes
    qr_dir = PROJECT_ROOT / "screenshots"
    qr_dir.mkdir(parents=True, exist_ok=True)
    qr_live = make_qr(config["live_url"], qr_dir / "qr_live.png")
    qr_github = make_qr(config["github_url"], qr_dir / "qr_github.png")
    qr_video = make_qr(config["demo_video_url"], qr_dir / "qr_video.png")

    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "PhishNetTitle",
        parent=styles["Title"],
        fontSize=28,
        textColor=TEXT_WHITE,
        spaceAfter=6,
        alignment=1,
    )
    heading_style = ParagraphStyle(
        "PhishNetHeading",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=ACCENT,
        spaceAfter=12,
        spaceBefore=20,
    )
    body_style = ParagraphStyle(
        "PhishNetBody",
        parent=styles["Normal"],
        fontSize=11,
        textColor=TEXT_WHITE,
        leading=16,
        spaceAfter=8,
    )
    small_style = ParagraphStyle(
        "PhishNetSmall",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#9CA3AF"),
        leading=12,
    )
    tagline_style = ParagraphStyle(
        "Tagline",
        parent=styles["Normal"],
        fontSize=14,
        textColor=AMBER,
        alignment=1,
        spaceAfter=20,
        fontName="Helvetica-Oblique",
    )

    # Build document
    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    story: list = []

    # ── Page 1: Cover ─────────────────────────────────────────────────────
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("🎣 PhishNet", title_style))
    story.append(Paragraph("Spot the bait. See the hook. Skip the ask.", tagline_style))
    story.append(Spacer(1, 1 * cm))

    story.append(Paragraph(f"Team: {team.get('name', 'N/A')}", body_style))
    story.append(Paragraph(f"Hackathon: {team.get('hackathon', 'N/A')}", body_style))
    story.append(Paragraph(f"Problem: {team.get('problem_statement', 'N/A')}", body_style))
    story.append(Spacer(1, 0.5 * cm))

    members = team.get("members", [])
    if members:
        member_data = [["Name", "Role"]]
        for m in members:
            member_data.append([m.get("name", ""), m.get("role", "")])
        member_table = Table(member_data, colWidths=[8 * cm, 8 * cm])
        member_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                    ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_WHITE),
                    ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_WHITE),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333")),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(member_table)

    story.append(Spacer(1, 1 * cm))

    # QR codes row
    qr_data = [
        [
            RLImage(str(qr_live), 3 * cm, 3 * cm),
            RLImage(str(qr_github), 3 * cm, 3 * cm),
            RLImage(str(qr_video), 3 * cm, 3 * cm),
        ],
        ["Live App", "GitHub", "Demo Video"],
    ]
    qr_table = Table(qr_data, colWidths=[5 * cm, 5 * cm, 5 * cm])
    qr_table.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TEXTCOLOR", (0, 0), (-1, -1), TEXT_WHITE),
                ("FONTSIZE", (0, 1), (-1, 1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(qr_table)

    story.append(PageBreak())

    # ── Page 2: Project Description ───────────────────────────────────────
    story.append(Paragraph("Project Description", heading_style))

    story.append(Paragraph("<b>The Problem</b>", body_style))
    story.append(
        Paragraph(
            "India sees over 30 lakh cyber-fraud complaints annually. "
            "Students, parents, and first-time UPI users are the most vulnerable. "
            "Scam messages exploit trust in brands, create urgency, and demand "
            "OTPs or payments — yet most people cannot recognise these tactics.",
            body_style,
        )
    )

    story.append(Paragraph("<b>Our Solution</b>", body_style))
    story.append(
        Paragraph(
            "PhishNet is a web app that analyses suspicious SMS, WhatsApp, and email "
            "text using a transparent, rules-based engine. It highlights each warning "
            "sign, explains it in plain language, and provides actionable next steps — "
            "including direct links to cybercrime.gov.in and the DoT Chakshu portal.",
            body_style,
        )
    )

    story.append(Paragraph("<b>How It Works</b>", body_style))
    story.append(
        Paragraph(
            "Every message is decomposed into three layers: <b>Bait</b> (borrowed trust "
            "from named brands), <b>Hook</b> (urgency and fear), and <b>Ask</b> (risky "
            "actions like link clicks, payments, or credential sharing). Each layer "
            "contributes deterministic points. The score is always transparent and "
            "reproducible — AI never sets it.",
            body_style,
        )
    )

    # Scoring table
    story.append(Paragraph("<b>Scoring Table</b>", body_style))
    scoring_data = [
        ["Category", "Signal", "Points"],
        ["Bait", "Named brand / authority", "+10"],
        ["Bait", "Too-good lure (prize, refund)", "+20"],
        ["Hook", "Urgency / pressure", "+15"],
        ["Hook", "Fear / threat", "+15"],
        ["Ask", "Risky link", "+25"],
        ["Ask", "Payment request", "+30"],
        ["Ask", "OTP / PIN / credential request", "+40"],
        ["Bonus", "Ask + Bait/Hook co-occur", "+15"],
    ]
    score_table = Table(scoring_data, colWidths=[3 * cm, 8 * cm, 3 * cm])
    score_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_WHITE),
                ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333")),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(score_table)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("<b>Tech Stack</b>", body_style))
    story.append(
        Paragraph(
            "Python 3.11+ · Streamlit · FastAPI · tldextract · pytesseract · "
            "Optional: Anthropic Claude API · Google Safe Browsing · VirusTotal · URLhaus · RDAP",
            body_style,
        )
    )

    story.append(Paragraph("<b>Privacy</b>", body_style))
    story.append(
        Paragraph(
            "PhishNet never stores or logs message content. Only anonymous aggregate "
            "counters are kept. The AI layer is off by default and requires explicit "
            "user consent. No trackers.",
            body_style,
        )
    )

    story.append(PageBreak())

    # ── Page 3: Architecture ──────────────────────────────────────────────
    story.append(Paragraph("Architecture", heading_style))

    arch_text = """
    <b>Component Overview:</b><br/><br/>
    <b>1. Streamlit UI (app.py)</b> — User-facing interface with dark theme, risk gauge,
    highlighted message view, findings table, and report generator.<br/><br/>
    <b>2. FastAPI API (api.py)</b> — RESTful endpoint for programmatic access with
    API key auth and rate limiting.<br/><br/>
    <b>3. Engine (phishnet/engine.py)</b> — Pure-function scoring engine loaded from
    config/rules.yaml. Handles NFKC normalisation, regex matching, protective context,
    score calculation with caps and bonuses.<br/><br/>
    <b>4. Link Analyser (phishnet/links.py)</b> — SSRF-safe URL extraction and offline
    classification. Uses tldextract with bundled snapshot.<br/><br/>
    <b>5. Enrichment (phishnet/enrich.py)</b> — Optional online checks via Safe Browsing,
    VirusTotal, URLhaus, and RDAP. Each behind its own env key with timeout and caching.<br/><br/>
    <b>6. i18n (phishnet/i18n.py)</b> — English/Hindi string translations.<br/><br/>
    <b>7. Report (phishnet/report.py)</b> — Plain-text report for police/cybercrime filing.
    """
    story.append(Paragraph(arch_text, body_style))

    story.append(Paragraph("<b>Business Model (Pilot Assumptions)</b>", body_style))
    biz_data = [
        ["Tier", "Price (Pilot Assumption)", "Features"],
        ["Free", "₹0", "Unlimited personal analysis, all rules"],
        ["Family (Roadmap)", "₹99/mo", "WhatsApp bot, family dashboard, alerts"],
        [
            "Institution (Pilot)",
            "₹4,999/mo",
            "API access, threat telemetry dashboard, custom rules",
        ],
    ]
    biz_table = Table(biz_data, colWidths=[3.2 * cm, 4.0 * cm, 7.8 * cm])
    biz_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_WHITE),
                ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(biz_table)
    story.append(
        Paragraph(
            "<font size=8 color='#888888'>*Pricing tiers reflect pilot design assumptions and are subject to commercial validation during campus/institutional beta trials.</font>",
            body_style,
        )
    )

    story.append(Paragraph("<b>Roadmap</b>", body_style))
    story.append(
        Paragraph(
            "• WhatsApp bot integration<br/>"
            "• Regional language expansion (Tamil, Telugu, Bengali, Marathi)<br/>"
            "• Browser extension for email scanning<br/>"
            "• Community-sourced scam database<br/>"
            "• Real-time threat intelligence dashboard for banks",
            body_style,
        )
    )

    story.append(PageBreak())

    # ── Page 4: Screenshots ───────────────────────────────────────────────
    story.append(Paragraph("Screenshots", heading_style))

    screenshot_paths = config.get("screenshots", [])
    for ss_path in screenshot_paths:
        full_path = PROJECT_ROOT / ss_path
        if full_path.exists():
            try:
                img = RLImage(str(full_path), width=15 * cm, height=10 * cm)
                img.hAlign = "CENTER"
                story.append(img)
                story.append(Paragraph(full_path.stem.replace("_", " ").title(), small_style))
                story.append(Spacer(1, 0.5 * cm))
            except Exception as e:
                story.append(Paragraph(f"Could not load {ss_path}: {e}", body_style))
        else:
            story.append(
                Paragraph(
                    f"Screenshot not found: {ss_path} — run scripts/capture_screenshots.py first",
                    body_style,
                )
            )

    story.append(PageBreak())

    # ── Page 5: Demo Video ────────────────────────────────────────────────
    story.append(Paragraph("Demo Video", heading_style))

    story.append(
        Paragraph(
            f'<b>Watch the demo:</b> <a href="{config["demo_video_url"]}" color="#3B82F6">'
            f"{config['demo_video_url']}</a>",
            body_style,
        )
    )

    story.append(Spacer(1, 0.5 * cm))
    qr_vid_img = RLImage(str(qr_video), 5 * cm, 5 * cm)
    qr_vid_img.hAlign = "CENTER"
    story.append(qr_vid_img)
    story.append(Paragraph("Scan to watch", small_style))

    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("<b>Demo Timestamps</b>", body_style))
    timestamps = [
        ["Timestamp", "Scene"],
        ["0:00–0:10", "App intro + tagline"],
        ["0:10–0:25", "SBI KYC scam → HIGH risk analysis"],
        ["0:25–0:35", "India Post parcel fee scam"],
        ["0:35–0:45", "Hinglish KYC scam"],
        ["0:45–0:55", "Class notice (no false alarm) + Genuine OTP"],
        ["0:55–1:05", "Hindi toggle + report generation"],
        ["1:05–1:15", "API demo with curl"],
        ["1:15–1:30", "Summary + next steps"],
    ]
    ts_table = Table(timestamps, colWidths=[3 * cm, 11 * cm])
    ts_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_WHITE),
                ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333")),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(ts_table)

    story.append(PageBreak())

    # ── Page 6: Links ─────────────────────────────────────────────────────
    story.append(Paragraph("Links", heading_style))

    links_data = [
        ["Resource", "URL"],
        ["Live App", config.get("live_url", "")],
        ["GitHub", config.get("github_url", "")],
        ["Demo Video", config.get("demo_video_url", "")],
        ["Cybercrime Portal", "https://cybercrime.gov.in"],
        ["Helpline", "1930"],
        ["DoT Chakshu", "https://sancharsaathi.gov.in/sfc/Home/sfc-complaint.jsp"],
    ]
    links_table = Table(links_data, colWidths=[4 * cm, 10 * cm])
    links_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_WHITE),
                ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333")),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(links_table)

    story.append(Spacer(1, 2 * cm))
    story.append(
        Paragraph(
            "Built with ❤️ for SETU 2026 — Forge Realm",
            tagline_style,
        )
    )

    # Build with dark background
    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(BG_DARK)
        canvas.rect(0, 0, A4[0], A4[1], fill=True, stroke=False)
        canvas.restoreState()

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f"\n✅ PDF generated: {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf()

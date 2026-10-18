"""Capture PhishNet screenshots using Playwright.

Usage:
    python scripts/capture_screenshots.py [--base-url http://127.0.0.1:8501]

Requires: playwright (uses system Google Chrome or Microsoft Edge automatically).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from playwright.sync_api import sync_playwright
except ModuleNotFoundError:
    venv_py = Path(__file__).resolve().parent.parent / ".venv" / "Scripts" / "python.exe"
    if venv_py.exists() and sys.executable.lower() != str(venv_py).lower():
        res = subprocess.run([str(venv_py), str(__file__)] + sys.argv[1:])
        sys.exit(res.returncode)
    raise

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCREENSHOTS_DIR = PROJECT_ROOT / "screenshots"


def is_server_running(url: str) -> bool:
    try:
        req = urllib.request.Request(f"{url}/_stcore/health")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def capture(base_url: str = "http://127.0.0.1:8501") -> None:
    """Capture all 5 screenshots."""
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    server_proc = None

    if not is_server_running(base_url):
        print("Local Streamlit not running on port 8501. Starting local Streamlit instance...")
        server_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(PROJECT_ROOT / "app.py"),
                "--server.headless",
                "true",
                "--server.port",
                "8501",
            ],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print("Waiting for Streamlit server to initialize...")
        for _ in range(25):
            time.sleep(1)
            if is_server_running(base_url):
                print("Streamlit server is ready on 127.0.0.1:8501!")
                break
        else:
            print("Failed to start Streamlit server.")
            if server_proc:
                server_proc.terminate()
            return

    try:
        print("Launching browser with system Chrome/Edge...")
        with sync_playwright() as pw:
            browser = None
            try:
                browser = pw.chromium.launch(channel="chrome", headless=True)
            except Exception:
                try:
                    browser = pw.chromium.launch(channel="msedge", headless=True)
                except Exception:
                    browser = pw.chromium.launch(headless=True)

            context = browser.new_context(viewport={"width": 1280, "height": 950})
            page = context.new_page()

            # 1. 01_home.png (Welcome Overview)
            print("1. Capturing 01_home.png (Welcome & Overview)...")
            page.goto(base_url, timeout=30000)
            page.wait_for_selector("button[data-baseweb='tab']", timeout=15000)
            time.sleep(2)
            page.screenshot(path=str(SCREENSHOTS_DIR / "01_home.png"))
            print("   ✓ Saved screenshots/01_home.png")

            # 2. 02_analysis_high.png (Scam Inspector - SBI KYC)
            print("2. Capturing 02_analysis_high.png (High Risk Analysis)...")
            tabs = page.locator("button[data-baseweb='tab']")
            tabs.nth(1).click()
            time.sleep(1.5)

            sample_btn = page.locator("button:has-text('SBI KYC')").first
            if sample_btn.is_visible():
                sample_btn.click()
                time.sleep(1.5)

            analyse_btn = page.locator("button:has-text('Analyse')").first
            if analyse_btn.is_visible():
                analyse_btn.click()
                time.sleep(3)

            page.screenshot(path=str(SCREENSHOTS_DIR / "02_analysis_high.png"))
            print("   ✓ Saved screenshots/02_analysis_high.png")

            # 3. 03_analysis_low.png (Low Risk Genuine Notice)
            print("3. Capturing 03_analysis_low.png (Low Risk Analysis)...")
            page.evaluate("window.scrollTo(0, 0)")
            time.sleep(1)
            textarea = page.locator("textarea").first
            textarea.scroll_into_view_if_needed()
            textarea.fill("Class moved to 3 PM today, Room 204. Please bring your notebooks.")
            time.sleep(1)
            analyse_btn = page.locator("button:has-text('Analyse')").first
            analyse_btn.scroll_into_view_if_needed()
            analyse_btn.click()
            time.sleep(3)
            page.screenshot(path=str(SCREENSHOTS_DIR / "03_analysis_low.png"))
            print("   ✓ Saved screenshots/03_analysis_low.png")

            # 4. 04_hindi.png (Hindi Home & Overview View)
            print("4. Capturing 04_hindi.png (Hindi UI)...")
            page.goto(f"{base_url}/?lang=hi", timeout=30000)
            page.wait_for_selector("button[data-baseweb='tab']", timeout=15000)
            time.sleep(2.5)
            page.screenshot(path=str(SCREENSHOTS_DIR / "04_hindi.png"))
            print("   ✓ Saved screenshots/04_hindi.png")

            # 5. 05_report.png (Official Pre-Filled Incident Report View)
            print("5. Capturing 05_report.png (Complaint Report View)...")
            page.goto(base_url, timeout=30000)
            page.wait_for_selector("button[data-baseweb='tab']", timeout=15000)
            page.locator("button[data-baseweb='tab']").nth(1).click()
            time.sleep(1.5)
            sample_btn = page.locator("button:has-text('SBI KYC')").first
            if sample_btn.is_visible():
                sample_btn.click()
                time.sleep(1.5)
            analyse_btn = page.locator("button:has-text('Analyse')").first
            analyse_btn.scroll_into_view_if_needed()
            analyse_btn.click()
            time.sleep(3)

            # Scroll directly to the code block containing the incident report
            report_block = page.locator("div[data-testid='stCodeBlock'], pre").first
            if report_block.is_visible():
                report_block.scroll_into_view_if_needed()
            else:
                page.evaluate("window.scrollTo(0, 1400)")
            time.sleep(1.5)
            page.screenshot(path=str(SCREENSHOTS_DIR / "05_report.png"))
            print("   ✓ Saved screenshots/05_report.png")

            browser.close()
            print(f"\n🎉 All screenshots saved to {SCREENSHOTS_DIR}/")

    finally:
        if server_proc:
            print("Stopping local Streamlit server...")
            server_proc.terminate()
            server_proc.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture PhishNet screenshots")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8501",
        help="Base URL of the running PhishNet app",
    )
    args = parser.parse_args()
    capture(args.base_url)

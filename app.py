"""
Public URL Checker — paste a link, get a phishing-risk verdict.
Reuses the same detection logic as the Telegram bot.

Run locally:
  cd checker
  python app.py
Then visit http://localhost:5002
"""

import os
import sys
import time
from urllib.parse import urlparse

from flask import Flask, render_template, request

# Import detectors.py from the parent folder
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from detectors import (
    resolve_shortener,
    check_safe_browsing,
    check_lookalike_domain,
    check_suspicious_tld,
    check_page_content,
)

app = Flask(__name__)

SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# Very simple rate limiter: max 10 checks per IP per minute
request_log = {}


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    window = request_log.get(ip, [])
    window = [t for t in window if now - t < 60]
    window.append(now)
    request_log[ip] = window
    return len(window) > 10


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html", result=None, checked_url=None)


@app.route("/check", methods=["POST"])
def check():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if is_rate_limited(ip):
        return render_template(
            "index.html",
            result={"error": "Too many checks — please wait a minute and try again."},
            checked_url=None,
        )

    raw_url = request.form.get("url", "").strip()
    if not raw_url:
        return render_template("index.html", result=None, checked_url=None)

    url = raw_url if raw_url.startswith("http") else f"http://{raw_url}"
    final_url = resolve_shortener(url)
    domain = urlparse(final_url).netloc.lower()

    reasons = []

    if SAFE_BROWSING_API_KEY:
        if check_safe_browsing(final_url, SAFE_BROWSING_API_KEY):
            reasons.append("This URL is on Google's known-threat list.")

    lookalike = check_lookalike_domain(domain)
    if lookalike:
        reasons.append(f"This domain looks like a fake version of {lookalike}.")

    if check_suspicious_tld(domain):
        reasons.append("This domain uses a pattern common in scam links.")

    content_flag = check_page_content(final_url, domain)
    if content_flag:
        reasons.append(f"Page content is suspicious: {content_flag}")

    result = {
        "safe": len(reasons) == 0,
        "reasons": reasons,
        "final_url": final_url,
    }

    return render_template("index.html", result=result, checked_url=raw_url)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5002))
    app.run(host="0.0.0.0", port=port)
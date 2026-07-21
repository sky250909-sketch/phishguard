"""
Detection functions used by bot.py. Each function is self-contained so you
can unit test or tune it independently.
"""

import requests

# Brands commonly impersonated in these scams, plus a few known lookalike
# tricks (letter swaps, added words). Extend this list as needed.
PROTECTED_BRANDS = {
    "instagram.com": ["instagrarn", "1nstagram", "instagr4m", "instagram-help",
                       "instagram-verify", "insta-gram"],
    "snapchat.com": ["snapchcit", "snap-chat", "snapchat-verify", "snqpchat"],
    "facebook.com": ["faceb00k", "facebook-verify", "faceboook"],
    "telegram.org": ["telegrarn", "teleqram", "telegram-verify"],
    "tiktok.com": ["tikt0k", "tiktok-verify"],
}

# TLDs disproportionately abused by throwaway phishing kits.
SUSPICIOUS_TLDS = {".xyz", ".tk", ".click", ".top", ".gq", ".ml", ".cf"}

# Known shortener domains worth resolving before judging the link.
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}

# Phrases that show up constantly in this exact bait ("who viewed your
# profile" style credential harvesters).
BAIT_PHRASES = [
    "who viewed your profile",
    "see who viewed you",
    "who's stalking your",
    "free followers",
    "verify your account now",
    "your account will be suspended",
    "claim your gift",
    "you've been selected",
]


def resolve_shortener(url: str) -> str:
    """Follow redirects for known shortener domains to find the real destination."""
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower()
        if any(s in domain for s in SHORTENERS):
            resp = requests.head(url, allow_redirects=True, timeout=5)
            return resp.url
    except requests.RequestException:
        pass
    return url


def check_safe_browsing(url: str, api_key: str) -> bool:
    """Returns True if Google Safe Browsing flags this URL as a known threat."""
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishguard-bot", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=5)
        resp.raise_for_status()
        return bool(resp.json())
    except requests.RequestException:
        return False


def check_lookalike_domain(domain: str) -> str | None:
    """Returns the real brand name being impersonated, if a lookalike is detected."""
    for real_brand, fakes in PROTECTED_BRANDS.items():
        for fake in fakes:
            if fake in domain:
                return real_brand
    return None


def check_suspicious_tld(domain: str) -> bool:
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)


def check_bait_phrases(text: str) -> str | None:
    lowered = text.lower()
    for phrase in BAIT_PHRASES:
        if phrase in lowered:
            return phrase
    return None


def check_page_content(url: str, domain: str) -> str | None:
    """
    Fetches the actual page and looks for the classic phishing signature:
    a password input field on a page whose visible branding (title/body
    text) names a real platform that doesn't match the domain it's hosted
    on. This catches brand-new phishing domains that aren't on any
    blocklist yet and don't match a known lookalike spelling.

    Returns a description string if suspicious, else None.
    """
    try:
        resp = requests.get(
            url,
            timeout=6,
            headers={"User-Agent": "Mozilla/5.0 (PhishGuardBot)"},
            allow_redirects=True,
        )
    except requests.RequestException:
        return None

    if resp.status_code != 200 or "text/html" not in resp.headers.get("Content-Type", ""):
        return None

    html = resp.text.lower()

    has_password_field = 'type="password"' in html or "type='password'" in html
    if not has_password_field:
        return None  # no login form, nothing to flag here

    for real_brand in PROTECTED_BRANDS:
        brand_name = real_brand.split(".")[0]  # e.g. "instagram"
        if brand_name in html and brand_name not in domain:
            return (
                f"page has a password field and mentions '{brand_name}' "
                f"but isn't hosted on {real_brand}"
            )

    return None
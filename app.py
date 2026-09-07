from flask import Flask, render_template, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "within 24 hours", "final warning",
    "account suspended", "account locked", "verify now", "limited time",
    "failure to respond", "action required"
]

CREDENTIAL_WORDS = [
    "password", "login", "log in", "sign in", "verify your account",
    "confirm your identity", "security code", "one-time code", "otp",
    "username", "credentials"
]

MONEY_WORDS = [
    "gift card", "wire transfer", "bank transfer", "payment required",
    "refund", "invoice", "crypto", "bitcoin", "prize", "winner",
    "claim your reward", "processing fee"
]

PERSONAL_INFO_WORDS = [
    "social security", "ssn", "date of birth", "bank account",
    "credit card", "debit card", "routing number", "personal information"
]

SUSPICIOUS_TLDS = {".zip", ".top", ".click", ".xyz", ".rest", ".work", ".gq", ".tk"}
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "facebook": "facebook.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
}

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def clean_domain(url):
    try:
        domain = urlparse(url).netloc.lower().split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""


def analyze_email(text):
    lowered = text.lower()
    findings = []
    score = 0

    def add_finding(points, title, detail, severity):
        nonlocal score
        score += points
        findings.append({
            "title": title,
            "detail": detail,
            "severity": severity,
            "points": points,
        })

    urgency_hits = [w for w in URGENCY_WORDS if w in lowered]
    if urgency_hits:
        add_finding(18, "Urgency or pressure language",
                    f"Detected phrases such as: {', '.join(urgency_hits[:3])}. Phishing messages often pressure people into acting quickly.",
                    "medium")

    credential_hits = [w for w in CREDENTIAL_WORDS if w in lowered]
    if credential_hits:
        add_finding(22, "Login or credential request",
                    f"Detected account-access language such as: {', '.join(credential_hits[:3])}. Be careful with requests for passwords or verification codes.",
                    "high")

    money_hits = [w for w in MONEY_WORDS if w in lowered]
    if money_hits:
        add_finding(20, "Money or payment language",
                    f"Detected financial language such as: {', '.join(money_hits[:3])}. Unexpected payment requests are a common scam indicator.",
                    "high")

    personal_hits = [w for w in PERSONAL_INFO_WORDS if w in lowered]
    if personal_hits:
        add_finding(25, "Sensitive information request",
                    f"Detected requests related to: {', '.join(personal_hits[:3])}. Legitimate organizations rarely request highly sensitive data by email.",
                    "high")

    if text.count("!") >= 3:
        add_finding(8, "Excessive punctuation",
                    f"The message contains {text.count('!')} exclamation marks, which can be associated with pressure or emotional manipulation.",
                    "low")

    if re.search(r'\b(dear customer|dear user|valued customer|account holder)\b', lowered):
        add_finding(8, "Generic greeting",
                    "The message uses a generic greeting instead of identifying the recipient personally.",
                    "low")

    urls = URL_PATTERN.findall(text)
    suspicious_urls = []
    for url in urls:
        domain = clean_domain(url)
        if not domain:
            continue
        reasons = []
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', domain):
            reasons.append("uses an IP address instead of a normal domain")
        if domain.count("-") >= 3:
            reasons.append("contains many hyphens")
        if len(domain) > 35:
            reasons.append("has an unusually long domain")
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            reasons.append("uses a higher-risk top-level domain")
        if domain in SHORTENER_DOMAINS:
            reasons.append("uses a URL shortener")
        if "xn--" in domain:
            reasons.append("uses punycode, which can hide lookalike characters")
        if reasons:
            suspicious_urls.append((domain, reasons))

    if suspicious_urls:
        domain, reasons = suspicious_urls[0]
        add_finding(20, "Suspicious link structure",
                    f"{domain} {', '.join(reasons)}. Inspect links carefully before opening them.",
                    "high")

    domains = [clean_domain(url) for url in urls if clean_domain(url)]
    for brand, official_domain in BRAND_DOMAINS.items():
        if brand in lowered and domains:
            matching_official = any(
                d == official_domain or d.endswith("." + official_domain)
                for d in domains
            )
            if not matching_official:
                add_finding(25, "Possible brand/domain mismatch",
                            f"The message mentions {brand.title()}, but the detected link does not use the expected {official_domain} domain.",
                            "high")
                break

    score = min(score, 100)

    if score >= 70:
        level, key = "High Risk", "high"
        summary = "This message contains several strong phishing indicators. Do not click links or provide information until you verify the sender independently."
    elif score >= 40:
        level, key = "Suspicious", "medium"
        summary = "This message has multiple warning signs. Verify the sender and destination of any links before taking action."
    elif score >= 15:
        level, key = "Low to Moderate Risk", "low"
        summary = "A few warning signs were found. Use caution and verify anything unexpected."
    else:
        level, key = "Low Risk", "safe"
        summary = "Few common phishing indicators were detected. This does not guarantee the message is legitimate."

    if not findings:
        findings.append({
            "title": "No obvious rule-based indicators found",
            "detail": "PhishGuard did not match the message against its current warning rules. Sophisticated phishing can still avoid these patterns.",
            "severity": "safe",
            "points": 0,
        })

    return {
        "score": score,
        "level": level,
        "level_key": key,
        "summary": summary,
        "findings": findings,
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    email_text = ""
    if request.method == "POST":
        email_text = request.form.get("email_text", "").strip()
        if email_text:
            result = analyze_email(email_text)
    return render_template("index.html", result=result, email_text=email_text)


if __name__ == "__main__":
    app.run(debug=True)

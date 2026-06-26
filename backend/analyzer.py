from backend.url_checker import analyze_url
from backend.email_parser import analyze_email

DEMO_URLS = [
    {"url": "http://paypa1.com/login/verify-account", "label": "PayPal lookalike (homoglyph attack)"},
    {"url": "http://192.168.1.1/banking/secure/login.php", "label": "IP-based phishing URL"},
    {"url": "https://secure-login.microsoft.com.evil-site.xyz/auth", "label": "Subdomain impersonation"},
    {"url": "http://bit.ly/3xF8kQ2", "label": "Shortened URL hiding destination"},
    {"url": "https://www.google.com", "label": "Legitimate URL (safe)"},
]

DEMO_EMAIL = """From: "Apple Support" <security@apple-id-verify.xyz>
Reply-To: noreply@suspicious-domain.tk
To: victim@example.com
Subject: Your Apple ID has been suspended
Date: Mon, 1 Jan 2024 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

Dear Valued Customer,

We have detected unauthorized activity on your Apple ID account.
Your account will be suspended within 24 hours unless you verify your identity immediately.

Click here to verify your account: http://app1e.com/verify?id=12345

Act now to avoid losing access to all your purchases and data.

Urgent action required — this link expires tonight.

Best regards,
Apple Security Team
"""


def get_demos() -> dict:
    url_demos = []
    for item in DEMO_URLS:
        result = analyze_url(item["url"])
        result["label"] = item["label"]
        url_demos.append(result)

    email_demo = analyze_email(DEMO_EMAIL)

    return {
        "urls": url_demos,
        "email": email_demo,
        "raw_email": DEMO_EMAIL
    }

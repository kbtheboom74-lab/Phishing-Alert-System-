import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.url_checker import analyze_url
from backend.email_parser import analyze_email
from backend.analyzer import get_demos


class TestUrlChecker:
    def test_safe_url(self):
        result = analyze_url("https://www.google.com")
        assert result["threat_level"] == "safe"
        assert result["score"] < 30

    def test_known_phishing_domain(self):
        result = analyze_url("http://paypa1.com/login")
        assert result["threat_level"] == "dangerous"
        assert any(f["indicator"] == "Known phishing domain" for f in result["findings"])

    def test_ip_based_url(self):
        result = analyze_url("http://192.168.1.1/login")
        assert any(f["indicator"] == "IP-based URL" for f in result["findings"])

    def test_no_https(self):
        result = analyze_url("http://example.com")
        assert any(f["indicator"] == "No HTTPS" for f in result["findings"])

    def test_suspicious_tld(self):
        result = analyze_url("https://example.xyz")
        assert any(f["indicator"] == "Suspicious TLD" for f in result["findings"])

    def test_url_shortener(self):
        result = analyze_url("https://bit.ly/abc123")
        assert any(f["indicator"] == "URL shortener" for f in result["findings"])

    def test_excessive_subdomains(self):
        result = analyze_url("http://a.b.c.d.example.com")
        assert any(f["indicator"] == "Excessive subdomains" for f in result["findings"])

    def test_homoglyph_detection(self):
        result = analyze_url("http://g00gle.com")
        assert any(f["indicator"] == "Known phishing domain" for f in result["findings"])

    def test_long_domain(self):
        domain = "a" * 55 + ".com"
        result = analyze_url(f"http://{domain}")
        assert any(f["indicator"] == "Unusually long domain" for f in result["findings"])

    def test_score_capped_at_100(self):
        result = analyze_url("http://paypa1.com/login/verify/secure/account?x=%20%20%20%20")
        assert result["score"] <= 100


class TestEmailParser:
    def test_safe_email(self):
        email = "From: user@google.com\nTo: me@example.com\nSubject: Hello\n\nHi there, just checking in."
        result = analyze_email(email)
        assert result["threat_level"] == "safe"

    def test_phishing_email(self):
        email = """From: "PayPal" <security@paypa1.com>
Reply-To: scam@evil.tk
To: victim@example.com
Subject: Account Suspended
Authentication-Results: mx.example.com; spf=fail; dkim=fail

Dear Valued Customer,

Your account will be closed within 24 hours. Verify your account immediately.
Click here: http://paypa1.com/verify

Act now or lose access. Urgent action required."""
        result = analyze_email(email)
        assert result["threat_level"] in ("suspicious", "dangerous")
        assert result["score"] >= 30

    def test_spf_failure(self):
        email = "From: x@test.com\nAuthentication-Results: spf=fail\n\nHello"
        result = analyze_email(email)
        assert any(f["indicator"] == "SPF failure" for f in result["findings"])

    def test_reply_to_mismatch(self):
        email = "From: user@company.com\nReply-To: scam@other.com\n\nHello"
        result = analyze_email(email)
        assert any(f["indicator"] == "From/Reply-To mismatch" for f in result["findings"])

    def test_suspicious_keywords(self):
        email = "From: x@test.com\n\nVerify your account immediately. Your account will be closed. Act now."
        result = analyze_email(email)
        assert any(f["indicator"] == "Phishing keywords detected" for f in result["findings"])


class TestDemos:
    def test_demos_load(self):
        demos = get_demos()
        assert "urls" in demos
        assert "email" in demos
        assert len(demos["urls"]) > 0

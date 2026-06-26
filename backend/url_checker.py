import json
import re
import os
from urllib.parse import urlparse

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "phishing_patterns.json")

with open(DATA_PATH) as f:
    PATTERNS = json.load(f)


def analyze_url(url: str) -> dict:
    findings = []
    score = 0

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    if not parsed.scheme == "https":
        findings.append({"indicator": "No HTTPS", "severity": "medium", "detail": "Connection is not encrypted"})
        score += 10

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        findings.append({"indicator": "IP-based URL", "severity": "high", "detail": f"Uses raw IP address: {hostname}"})
        score += 30

    subdomain_count = len(hostname.split(".")) - 2
    if subdomain_count > 2:
        findings.append({
            "indicator": "Excessive subdomains",
            "severity": "medium",
            "detail": f"Has {subdomain_count} subdomains"
        })
        score += 15

    if len(hostname) > 50:
        findings.append({"indicator": "Unusually long domain", "severity": "medium", "detail": f"Domain is {len(hostname)} characters"})
        score += 10

    for shortener in PATTERNS["url_shorteners"]:
        if hostname.endswith(shortener):
            findings.append({"indicator": "URL shortener", "severity": "medium", "detail": f"Uses shortener: {shortener}"})
            score += 15
            break

    for tld in PATTERNS["suspicious_tlds"]:
        if hostname.endswith(tld):
            findings.append({"indicator": "Suspicious TLD", "severity": "medium", "detail": f"Uses suspicious TLD: {tld}"})
            score += 15
            break

    for phishing_domain in PATTERNS["known_phishing_domains"]:
        if hostname == phishing_domain or hostname.endswith("." + phishing_domain):
            findings.append({"indicator": "Known phishing domain", "severity": "critical", "detail": f"Matches known phishing domain: {phishing_domain}"})
            score += 50
            break

    homoglyph_score = _check_homoglyphs(hostname)
    if homoglyph_score > 0:
        findings.append({"indicator": "Homoglyph/lookalike domain", "severity": "high", "detail": "Domain uses characters that mimic a trusted domain"})
        score += homoglyph_score

    if "@" in parsed.netloc.split("@")[0] if "@" in parsed.netloc else False:
        findings.append({"indicator": "Embedded credentials", "severity": "high", "detail": "URL contains embedded username/password"})
        score += 25

    if re.search(r"%[0-9a-fA-F]{2}", url):
        encoded_chars = len(re.findall(r"%[0-9a-fA-F]{2}", url))
        if encoded_chars > 3:
            findings.append({"indicator": "Excessive URL encoding", "severity": "medium", "detail": f"Contains {encoded_chars} encoded characters"})
            score += 10

    suspicious_path_keywords = ["login", "signin", "verify", "secure", "update", "confirm", "account", "banking"]
    for kw in suspicious_path_keywords:
        if kw in path.lower():
            findings.append({"indicator": "Suspicious path keyword", "severity": "low", "detail": f"Path contains '{kw}'"})
            score += 5
            break

    if parsed.netloc and "@" in parsed.netloc:
        findings.append({"indicator": "Embedded credentials in URL", "severity": "high", "detail": "URL contains @ sign which may hide the real destination"})
        score += 25

    score = min(score, 100)
    threat_level = _score_to_level(score)

    return {
        "url": url,
        "hostname": hostname,
        "score": score,
        "threat_level": threat_level,
        "findings": findings
    }


def _check_homoglyphs(hostname: str) -> int:
    homoglyph_map = PATTERNS["homoglyph_map"]
    normalized = hostname.lower()
    for fake, real in homoglyph_map.items():
        normalized = normalized.replace(fake, real)

    if normalized == hostname.lower():
        return 0

    for trusted in PATTERNS["trusted_domains"]:
        base_trusted = trusted.split(".")[0]
        base_normalized = normalized.split(".")[0]
        if base_trusted == base_normalized:
            return 30
    return 10


def _score_to_level(score: int) -> str:
    if score >= 60:
        return "dangerous"
    elif score >= 30:
        return "suspicious"
    return "safe"

import json
import os
import re
from email import policy
from email.parser import Parser

from backend.url_checker import analyze_url, PATTERNS

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "phishing_patterns.json")

with open(DATA_PATH) as f:
    EMAIL_PATTERNS = json.load(f)


def analyze_email(raw_email: str) -> dict:
    findings = []
    score = 0

    parsed = Parser(policy=policy.default).parsestr(raw_email)

    header_result = _analyze_headers(parsed)
    findings.extend(header_result["findings"])
    score += header_result["score"]

    body = _extract_body(parsed)
    body_result = _analyze_body(body)
    findings.extend(body_result["findings"])
    score += body_result["score"]

    urls = _extract_urls(body)
    url_results = []
    for url in urls[:10]:
        result = analyze_url(url)
        url_results.append(result)
        if result["score"] > 30:
            findings.append({
                "indicator": "Suspicious embedded URL",
                "severity": "high",
                "detail": f"URL {url} scored {result['score']}/100"
            })
            score += min(result["score"] // 3, 20)

    attachment_result = _check_attachments(parsed)
    findings.extend(attachment_result["findings"])
    score += attachment_result["score"]

    score = min(score, 100)

    if score >= 60:
        threat_level = "dangerous"
    elif score >= 30:
        threat_level = "suspicious"
    else:
        threat_level = "safe"

    return {
        "score": score,
        "threat_level": threat_level,
        "findings": findings,
        "embedded_urls": url_results,
        "headers": {
            "from": str(parsed.get("From", "")),
            "to": str(parsed.get("To", "")),
            "subject": str(parsed.get("Subject", "")),
            "date": str(parsed.get("Date", "")),
        }
    }


def _analyze_headers(msg) -> dict:
    findings = []
    score = 0

    from_header = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))

    from_match = re.search(r"<([^>]+)>", from_header)
    from_email = from_match.group(1) if from_match else from_header.strip()
    from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""

    if reply_to:
        reply_match = re.search(r"<([^>]+)>", reply_to)
        reply_email = reply_match.group(1) if reply_match else reply_to.strip()
        reply_domain = reply_email.split("@")[-1].lower() if "@" in reply_email else ""

        if from_domain and reply_domain and from_domain != reply_domain:
            findings.append({
                "indicator": "From/Reply-To mismatch",
                "severity": "high",
                "detail": f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'"
            })
            score += 25

    received_headers = msg.get_all("Received") or []
    if not received_headers:
        findings.append({"indicator": "Missing Received headers", "severity": "medium", "detail": "No mail relay information found"})
        score += 10

    auth_results = str(msg.get("Authentication-Results", ""))
    if auth_results:
        if "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
            findings.append({"indicator": "SPF failure", "severity": "high", "detail": "SPF check failed — sender may be spoofed"})
            score += 20

        if "dkim=fail" in auth_results.lower():
            findings.append({"indicator": "DKIM failure", "severity": "high", "detail": "DKIM signature invalid — message may be tampered"})
            score += 20

        if "dmarc=fail" in auth_results.lower():
            findings.append({"indicator": "DMARC failure", "severity": "high", "detail": "DMARC policy check failed"})
            score += 20
    else:
        findings.append({"indicator": "No authentication results", "severity": "low", "detail": "No SPF/DKIM/DMARC info available"})
        score += 5

    display_name = from_header.split("<")[0].strip().strip('"').lower()
    if display_name and from_domain:
        for trusted in EMAIL_PATTERNS["trusted_domains"]:
            trusted_base = trusted.split(".")[0]
            if trusted_base in display_name and trusted not in from_domain:
                findings.append({
                    "indicator": "Display name spoofing",
                    "severity": "high",
                    "detail": f"Display name contains '{trusted_base}' but email is from '{from_domain}'"
                })
                score += 25
                break

    return {"findings": findings, "score": score}


def _analyze_body(body: str) -> dict:
    findings = []
    score = 0
    body_lower = body.lower()

    matched_keywords = []
    for keyword in EMAIL_PATTERNS["suspicious_keywords"]:
        if keyword.lower() in body_lower:
            matched_keywords.append(keyword)

    if matched_keywords:
        severity = "high" if len(matched_keywords) >= 3 else "medium"
        findings.append({
            "indicator": "Phishing keywords detected",
            "severity": severity,
            "detail": f"Found {len(matched_keywords)} suspicious phrases: {', '.join(matched_keywords[:5])}"
        })
        score += min(len(matched_keywords) * 5, 25)

    urgency_patterns = [
        r"within \d+ hours?",
        r"immediately",
        r"right away",
        r"act now",
        r"expires? (today|tonight|soon)",
        r"last chance",
        r"final warning"
    ]
    urgency_count = sum(1 for p in urgency_patterns if re.search(p, body_lower))
    if urgency_count > 0:
        findings.append({
            "indicator": "Urgency tactics",
            "severity": "medium",
            "detail": f"Found {urgency_count} urgency indicators"
        })
        score += min(urgency_count * 5, 15)

    if re.search(r"(dear (valued )?(customer|user|member|sir|madam))", body_lower):
        findings.append({"indicator": "Generic greeting", "severity": "low", "detail": "Uses a generic greeting instead of your name"})
        score += 5

    return {"findings": findings, "score": score}


def _extract_urls(body: str) -> list:
    return re.findall(r'https?://[^\s<>"\')\]]+', body)


def _extract_body(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode("utf-8", errors="replace")
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html = payload.decode("utf-8", errors="replace")
                    return re.sub(r"<[^>]+>", " ", html)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode("utf-8", errors="replace")
        return str(msg.get_payload())
    return ""


def _check_attachments(msg) -> dict:
    findings = []
    score = 0
    dangerous_extensions = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".com", ".pif", ".msi"]

    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                for ext in dangerous_extensions:
                    if filename.lower().endswith(ext):
                        findings.append({
                            "indicator": "Dangerous attachment",
                            "severity": "critical",
                            "detail": f"Attachment '{filename}' has executable extension '{ext}'"
                        })
                        score += 30
                        break
                if filename.lower().endswith(".zip") or filename.lower().endswith(".rar"):
                    findings.append({
                        "indicator": "Archive attachment",
                        "severity": "medium",
                        "detail": f"Compressed archive '{filename}' may contain malicious files"
                    })
                    score += 10

    return {"findings": findings, "score": score}

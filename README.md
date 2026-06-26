# Phishing Alert System

A browser-based phishing detection tool that analyzes URLs and emails for threat indicators.

## Features

- **URL Scanner** — Detects IP-based URLs, homoglyph/lookalike domains, suspicious TLDs, URL shorteners, excessive subdomains, and known phishing domains
- **Email Scanner** — Parses email headers (SPF/DKIM/DMARC), detects display name spoofing, From/Reply-To mismatches, phishing keywords, urgency tactics, and dangerous attachments
- **Risk Scoring** — Weighted scoring system (0–100) with Safe / Suspicious / Dangerous threat levels
- **Demo Mode** — Pre-loaded phishing examples to explore detection capabilities
- **REST API** — JSON endpoints for integration with other tools
- **Rate Limiting** — Built-in request throttling to prevent abuse
- **Scan Logging** — All scans logged for audit purposes

## Project Structure

```
├── backend/
│   ├── app.py              # Flask API server + static file serving
│   ├── analyzer.py          # Demo data and orchestration
│   ├── email_parser.py      # Email header/body/attachment analysis
│   └── url_checker.py       # URL threat detection engine
├── frontend/
│   ├── index.html           # Dashboard UI
│   ├── style.css            # Dark-themed responsive styles
│   └── script.js            # Frontend logic
├── data/
│   └── phishing_patterns.json  # Known patterns, keywords, and rules
├── tests/
│   └── test_analyzer.py     # Unit tests (16 tests)
└── requirements.txt
```

## Setup

```bash
pip install -r requirements.txt
python -m backend.app
```

Open http://localhost:5000 in your browser.

## API Endpoints

| Method | Endpoint             | Description                  |
|--------|----------------------|------------------------------|
| POST   | `/api/analyze/url`   | Analyze a URL for threats    |
| POST   | `/api/analyze/email` | Analyze raw email content    |
| GET    | `/api/stats`         | Get scan statistics          |
| GET    | `/api/demos`         | Load demo examples           |

### Example

```bash
curl -X POST http://localhost:5000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1.com/login"}'
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Detection Capabilities

### URL Analysis
- HTTPS check
- IP-based URL detection
- Homoglyph/lookalike domain detection
- Known phishing domain matching
- Suspicious TLD detection
- URL shortener detection
- Excessive subdomain detection
- URL encoding analysis
- Suspicious path keywords

### Email Analysis
- SPF/DKIM/DMARC authentication checks
- From/Reply-To domain mismatch
- Display name spoofing detection
- Phishing keyword detection
- Urgency tactic identification
- Generic greeting detection
- Dangerous attachment detection
- Embedded URL analysis

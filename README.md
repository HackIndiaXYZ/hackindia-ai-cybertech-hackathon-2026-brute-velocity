# Velbrix

> **Build fast. Verify before you ship.**
>
> Authorization-first security and deploy-readiness platform for AI-generated ("vibe-coded") apps.

---

## Team

- **Team:** BruteVelocity
- **Members:** Yogesh Kumar, Ravi Kumar, Prarthana Bhardwaj
- **Event:** HackIndia × Kanpur Institute of Technology AI & CyberTech Hackathon 2026
- **Date:** 28 October 2026, KIT Kanpur

---

## What is Velbrix?

Velbrix is an authorization-first security and deploy-readiness platform built for AI-generated ("vibe-coded") applications. As AI coding assistants produce code at unprecedented speed, the risk of shipping insecure, hallucinated, or prompt-injected code increases dramatically.

Velbrix scans your project, explains vulnerabilities in plain English, generates AI-powered secure patches, verifies them in an isolated sandbox, and produces a Trust Report with a deploy decision.

### Tagline
**Build fast. Verify before you ship.**

### Ethical Commitment
> **Authorized testing only | All scores and findings shown are synthetic demo data.**

---

## Features

### 1. Upload
- Upload ZIP projects or load the bundled VibeBank demo
- Isolated temporary workspace per scan
- Stack detection and file count

### 2. ShipScan — Multi-Layer Security Scanner
- **Secret Scanner:** Gitleaks-style regex detection (API keys, JWT secrets, DB URLs, GitHub tokens, Stripe keys, passwords)
- **Code Security Scanner:** SQL injection, XSS, unsafe eval/exec, shell injection, unsafe deserialization, wildcard CORS, debug mode, exposed admin routes
- **Dependency Scanner:** CVE database + outdated package detection
- **Prompt Injection Scanner:** README, comments, agent instruction files
- **Deploy Readiness Scanner:** Missing config, tests, CI/CD, .env.example
- **Bandit Integration:** Available but disabled by default for clean demo output

### 3. Explain
- Plain-English explanation of every finding
- Hinglish summary
- Shows: What it is, Why it matters, What must change, Evidence, Risk level, Recommended fix

### 4. FixMe Space
- AI-powered secure patch generation (NVIDIA NIM → Groq → Gemini → local heuristic)
- Before/after diff display
- Apply to isolated temp copy only (never touches original)
- Verification: rescan patched copy, check syntax validity, detect new findings
- Explicit Approve / Reject / Rollback workflow
- Before/after score comparison

### 5. AgentGuard
- Sandbox simulation for AI-agent actions
- Policy decisions: ALLOW, BLOCK, ASK HUMAN
- Action log with decision, reason, policy rule, evidence

### 6. SessionGuard
- Cookie flag audit: Secure, HttpOnly, SameSite
- Session expiry, logout invalidation, session fixation risk
- Uses synthetic tokens against authorized local test app only

### 7. Trust Report
- Overall security score out of 100
- 5 category scores: Secrets, Injection & Uploads, Access & Sessions, Supply Chain, AI-Agent Risk
- Critical/High/Medium/Low/Info counts
- Patch verification results
- Final decision: DEPLOY, REVIEW, or BLOCK
- Downloadable HTML and Markdown reports

---

## Multi-AI Provider Layer

Velbrix uses a multi-provider fallback chain:

1. **NVIDIA NIM** (primary) — via `build.nvidia.com`
2. **Groq** (fallback 1)
3. **Google Gemini** (fallback 2)
4. **Local heuristic mode** (always available)

### Security
- All secret values are **redacted** before sending to any AI provider
- UI note: "Secret values are redacted before AI processing."
- Works fully without any AI API keys using local heuristic mode

---

## Quick Start

### Replit (Recommended)

1. Import the repository into Replit
2. Add secrets in Replit Secrets tab:
   ```
   NVIDIA_API_KEY=nvapi-your-key
   NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
   NVIDIA_MODEL=meta/llama-3.1-8b-instruct
   ```
3. Click **Run** — runs `bash start.sh`
4. Open the webview at port 8000

### Local Development

```bash
# Clone
git clone <repo-url>
cd velbrix

# Install dependencies
pip install -r requirements.txt

# Copy env file and fill in keys (optional - works without AI keys)
cp .env.example .env

# Run
bash start.sh
# OR
python main.py
```

Open `http://localhost:8000` in your browser.

---

## Architecture

```
velbrix/
├── main.py                    # FastAPI entry point
├── start.sh                   # One-command starter
├── requirements.txt
├── .env.example
├── .replit                    # Replit config
├── replit.nix
├── backend/
│   ├── config.py              # Settings (env vars)
│   ├── database.py             # SQLite layer
│   ├── models.py               # Pydantic models
│   ├── ai_providers.py         # Multi-AI with fallback + redaction
│   ├── scoring.py              # Evidence-based scoring engine
│   ├── patch_engine.py         # AI patch generation, diff, verify
│   ├── agent_guard.py          # AgentGuard sandbox simulation
│   ├── session_guard.py        # SessionGuard synthetic audit
│   ├── report_generator.py     # HTML/Markdown Trust Report
│   ├── scanners/
│   │   ├── secret_scanner.py
│   │   ├── code_scanner.py
│   │   ├── dependency_scanner.py
│   │   ├── prompt_injection_scanner.py
│   │   └── deploy_readiness_scanner.py
│   └── routes/
│       ├── upload.py
│       ├── scan.py
│       ├── findings.py
│       ├── fixme.py
│       ├── agent_guard.py
│       ├── session_guard.py
│       └── report.py
├── static/
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
├── demo/
│   └── vibebank/               # Bundled vulnerable demo project
│       ├── app.py
│       ├── README.md
│       ├── requirements.txt
│       ├── .gitignore
│       ├── Dockerfile
│       └── docker-compose.yml
├── README.md
├── DEMO_SCRIPT.md
└── PRESENTATION_NOTES.md
```

---

## Scoring System

Velbrix uses a transparent, evidence-based scoring engine:

- Start at 100 points
- Subtract points based on finding severity (deduplicated by title):
  - Critical: 11.5 points
  - High: 5 points
  - Medium: 3 points
  - Low: 1 point
  - Info: 0 points

### Decision Logic
| Score | Decision | Condition |
|-------|----------|-----------|
| 0–49 | **BLOCK** | Any Critical finding present OR score < 50 |
| 50–84 | **REVIEW** | No Critical, but score below 85 |
| 85–100 | **DEPLOY** | No Critical, score ≥ 85 |

### VibeBank Demo Scores (Verified)
- **Before fixes:** 38/100, BLOCK (2 Critical, 5 High, 1 exposed secret, High prompt-injection risk)
- **After 6 verified patches:** 81/100, REVIEW (0 Critical, 1 High remaining, 0 exposed secrets, patch verification Passed)

---

## Ethical Scope

### Allowed
- Analyze user-uploaded ZIP projects
- Analyze the bundled authorized VibeBank demo project
- Use synthetic tokens for session testing
- Simulate AI-agent actions in a sandbox

### NOT Allowed
- Scanning arbitrary public websites
- Real cookie theft, token theft, credential extraction
- Browser profile access or unauthorized reconnaissance
- Automatically modifying the user's original uploaded project

### Safeguards
- Every AI-generated patch is applied **only** to an isolated temporary copy
- Human approval is **required** before any patch is accepted
- All secret values are **redacted** before sending to external AI providers
- The original project is **never** modified without explicit export/approval

---

## Limitations

- Automated scanners may produce false positives or miss context-specific vulnerabilities
- AI-generated patches require human review before production deployment
- Session tests use synthetic tokens against an authorized local test app only
- Supply chain checks use a known-vulnerability database and may miss very recent CVEs
- **Automated assessment, not a guarantee**

---

## Demo

See [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md) for the live demo script and [`PRESENTATION_NOTES.md`](PRESENTATION_NOTES.md) for presentation talking points.

---

## License

MIT

---

> Build fast. Verify before you ship. — Team BruteVelocity

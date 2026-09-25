# Vanguard — Autonomous Agent Shield

Vanguard is a Flask-based web security gateway for AI agents. It inspects a URL before an agent can interact with it, combines static HTML analysis with optional browser-based inspection, and returns an explainable `ALLOW`, `WARN`, or `BLOCK` decision.

The project is designed for defensive security research, hackathon demonstrations, and controlled testing of safeguards around autonomous web agents.

> **Important:** Vanguard is an analysis and policy layer, not a universal website-safety oracle or a hardened browser sandbox. Only scan systems and pages that you own or are authorized to assess.

## Highlights

- Flask web application with a login/signup flow and multi-chat interface
- Shared URL safety checks designed to reduce SSRF risk
- Static HTML inspection using `requests` and BeautifulSoup
- Optional dynamic inspection using Playwright and Chromium
- Detection of suspicious redirects, cross-domain actions, sensitive forms, JavaScript navigation, and intent/destination mismatches
- Weighted risk scoring with `ALLOW`, `WARN`, and `BLOCK` outcomes
- Action plans that prevent automatic execution of blocked actions and require confirmation for warnings
- OpenAI-powered contextual review for warning cases
- AI web explorer that must ask Bodyguard to inspect a URL before accessing it
- SQLite persistence for users, chats, messages, and scan results
- Live scan progress in the browser UI
- Recursive investigation with depth and total-investigation limits

## Architecture

```text
User / AI agent
      |
      v
Flask application (app.py)
  |       |        |
  |       |        +--> SQLite: users, chats, messages, scan_results
  |       |
  |       +--> AI_Searcher/explorer1.py
  |                    |
  |                    +--> POST /scan before visiting a URL
  |
  +--> Bodyguard pipeline
          |
          +--> URL safety / SSRF checks
          +--> Static scanner
          +--> Dynamic scanner when heuristics require it
          +--> Detector: extracts security signals
          +--> Analyser: scores signals and decides ALLOW/WARN/BLOCK
          +--> Actions: converts findings into an execution plan
          +--> Investigator / AI analyser for contextual review
```

The main entry point is `app.py`. A request to `/scan` first passes through `url_safety.is_safe_url()`, then through the static scanner. If the static result contains scripts or inline JavaScript handlers, `Bodyguard.heuristics.should_use_dynamic()` enables the Playwright path. The resulting evidence is analysed and converted into a response containing the decision, score, findings, reasons, and actions.

For chat requests, the Flask app starts a background explorer job. `AI_Searcher/explorer1.py` uses OpenAI tool calling, but its only web-access tool is `ask_bodyguard`; `BLOCK` results must not be bypassed. Completed scan results are linked to the active chat in SQLite.

## Repository layout

```text
app.py                    Flask server, authentication, chat APIs, scan jobs
url_safety.py             HTTP(S) validation and DNS/IP-based SSRF protection
requirements.txt          Python dependencies
vanguard.db               SQLite database file included in the repository

Bodyguard/
  __init__.py              Public package exports and pipeline version
  detector.py              Extracts suspicious signals from scanner output
  analyser.py              Weights signals and produces risk decisions
  actions.py               Builds ALLOW/WARN/BLOCK action plans
  heuristics.py            Decides when dynamic scanning is needed
  investigator.py          Safe, bounded recursive investigation
  ai_analyser.py           Structured OpenAI contextual analysis

Static/
  scanner.py               Bounded HTTP fetching and static HTML inspection

Dynamic/
  fetcher.py               Playwright browser fetch with request interception
  extractor.py              Extracts evidence from rendered HTML
  prettifier.py             Optional HTML formatting helper

AI_Searcher/
  explorer1.py              OpenAI-powered guarded web explorer

templates/
  index.html                Authentication and three-panel chat/security UI
```

## Requirements

- Python 3.10+ recommended
- A working internet connection for URL scanning and OpenAI requests
- Chromium installed for dynamic scans
- An OpenAI API key for Explorer1 and AI-assisted review

## Installation

```bash
git clone https://github.com/daiwik2009/hackathon_repo_Aws.git
cd hackathon_repo_Aws

python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
# .\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
python -m playwright install chromium
```

Create a `.env` file in the repository root:

```dotenv
OPENAI_API_KEY=your_openai_api_key
VANGUARD_SECRET_KEY=replace_with_a_long_random_secret
BODYGUARD_URL=http://127.0.0.1:5000
# Set to 0 to disable AI review for WARN results
VANGUARD_AI_REVIEW=1
```

`BODYGUARD_URL` is used by `AI_Searcher/explorer1.py` when it calls the Flask scan endpoint. When Explorer1 runs inside the same application, the default `http://127.0.0.1:5000` is normally sufficient.

## Run the application

```bash
python app.py
```

Open <http://127.0.0.1:5000> and create an account. The application initializes `vanguard.db` on startup.

The application listens on `0.0.0.0` and uses port `5000` by default. Override the port with:

```bash
PORT=8000 python app.py
```

On Windows PowerShell:

```powershell
$env:PORT = "8000"
python app.py
```

## Scan API

`POST /scan` is the machine-to-machine endpoint used by Explorer1 and can also be called directly.

```bash
curl -X POST http://127.0.0.1:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Example response shape:

```json
{
  "status": "success",
  "url": "https://example.com",
  "scan_mode": "static",
  "security": {
    "decision": "ALLOW",
    "risk_score": 0,
    "confidence": null
  },
  "findings": [],
  "reason": "No significant security finding was reported by the scanner.",
  "actions": [],
  "page_action": {}
}
```

The response can also include page metadata, dynamic scan output, and `ai_review` data when AI review is enabled and the deterministic result is `WARN`.

### Scan decisions

| Decision | Meaning |
| --- | --- |
| `ALLOW` | No implemented rule currently justifies warning or blocking the page. |
| `WARN` | Suspicious or ambiguous signals require caution or confirmation. |
| `BLOCK` | The implemented analysis identified conditions that should stop the action. |

A decision is based on the evidence available to the implemented scanners. `ALLOW` does not prove that a site is trustworthy, and `BLOCK` is not a mathematical proof that every possible page behaviour is malicious.

## Chat and Explorer flow

After signing in:

1. Create or select a chat.
2. Send a question or paste one or more URLs.
3. Flask creates a background Explorer job.
4. Explicit URLs are scanned and shown in the security monitor.
5. Explorer1 requests Bodyguard checks before navigating to discovered URLs.
6. Scan progress, risk, confidence, findings, and depth are displayed live.
7. Messages and successful scan results are persisted to the active chat.

Relevant routes include:

- `GET /login`, `POST /login`
- `GET /signup`, `POST /signup`
- `POST /logout`
- `POST /api/chats`
- `GET /api/chats/<chat_id>`
- `DELETE /api/chats/<chat_id>`
- `POST /api/chats/<chat_id>/messages`
- `GET /api/jobs/<job_id>`

Browser state-changing requests use the CSRF token supplied by the Flask template. `/scan` preserves its JSON machine-to-machine contract and relies on URL safety validation.

## Command-line pipeline tools

The core components can also be exercised independently with JSON files:

```bash
# Static scan a page and write scan.json
python Static/scanner.py https://example.com

# Detect signals and write analysis.json
python Bodyguard/detector.py scan.json

# Score findings and write analyser.json
python Bodyguard/analyser.py analysis.json analyser.json

# Build an action plan and write actions.json
python Bodyguard/actions.py analyser.json actions.json

# Run bounded recursive investigation
python -m Bodyguard.investigator https://example.com
```

For direct Explorer testing:

```bash
python AI_Searcher/explorer1.py
```

This requires `OPENAI_API_KEY` and a running Vanguard server if Explorer1 needs to call the default Bodyguard URL.

## Security controls

### URL and SSRF protection

`url_safety.py` only permits `http` and `https`, rejects blocked hostnames, resolves DNS, and refuses private, loopback, link-local, multicast, reserved, and unspecified IP addresses. The static scanner re-checks every redirect hop, while the dynamic scanner intercepts every browser request, including redirects and subresources.

### Static inspection

`Static/scanner.py` limits redirects to five hops and response bodies to 5 MB. It extracts:

- Links and destinations
- Buttons and button-like elements
- Forms, methods, and input controls
- Inline JavaScript event handlers
- Inline and external scripts
- Page title, status, content type, requested URL, and final URL

### Detection and scoring

`Bodyguard/detector.py` identifies signals such as:

- Cross-domain navigation
- Login, payment, download, and redirect destinations
- `javascript:`, `data:`, and `vbscript:` URLs
- JavaScript-driven navigation and dynamic execution patterns
- Password, identity, and payment inputs
- Credential or payment submission to another domain
- Sensitive data sent through GET
- Actions whose visible intent does not match their destination

`Bodyguard/analyser.py` applies weighted signals, overlap groups, combination bonuses, and thresholds:

- `0–29`: `ALLOW`
- `30–69`: `WARN`
- `70–100`: `BLOCK`

### Bounded investigation

`Bodyguard/investigator.py` prevents loops, normalizes URLs, limits recursion to depth 3 by default, and caps the complete investigation tree at 25 URLs. AI-requested targets must already have been discovered by a trusted scanner and must pass the shared URL safety guard.

## Development notes and limitations

- There is no test suite or CI workflow in the current repository; validate changes with the manual flows and CLI commands above.
- The dynamic-scan heuristic currently enables Playwright whenever a page contains any script or inline JavaScript handler, so many modern pages will use the browser path.
- `url_safety.is_safe_url()` performs resolve-then-check validation. It does not pin the validated IP through the subsequent HTTP request, so DNS rebinding remains a known limitation.
- The Flask app stores background jobs in process memory; jobs are lost on restart and are not suitable for multi-worker coordination without a shared job system.
- The included SQLite database is local development state. Do not use it as a production database without reviewing deployment and data-isolation requirements.
- The built-in Flask server is for local development and demonstrations. Public deployments should use a production WSGI server, HTTPS, secure secret management, rate limiting, hardened authentication, network isolation, and an appropriately isolated browser environment.
- Do not commit `.env`, API keys, generated scan output, virtual environments, or database files. Review the existing `.gitignore` before committing changes.

## Responsible use

Use Vanguard only for authorized defensive testing and research. Do not use it to probe private networks, cloud metadata endpoints, third-party systems, or websites without permission. Treat scan results as security evidence for a decision—not as a guarantee of safety.

## License

No license file is currently included. Until a license is added, all rights remain with the repository owner.

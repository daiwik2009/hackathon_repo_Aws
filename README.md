# AI Bodyguard — Vanguard

AI Bodyguard is a security middleware for AI web agents. It places a defensive security layer between an AI explorer and the web.

The goal is to inspect web destinations before an AI agent accesses or interacts with them and return a structured security decision.

## Architecture

The current pipeline is:

```text
User
  ↓
OpenAI Explorer
  ↓
ask_bodyguard(url)
  ↓
app.py — Flask API
  ↓
Static Scanner
  ↓
Detector
  ↓
Analyser
  ↓
Actions
  ↓
Security Decision
  ↓
Explorer
```

For pages containing JavaScript-related activity, the API can additionally use the Dynamic scanner:

```text
                    ┌─────────────────┐
                    │   Static Scan   │
                    │ requests + BS4  │
                    └────────┬────────┘
                             │
                    scripts / JS handlers?
                       ┌─────┴─────┐
                       │           │
                      No          Yes
                       │           │
                       │    ┌──────▼──────┐
                       │    │ Dynamic Scan│
                       │    │  Playwright │
                       │    └──────┬──────┘
                       │           │
                       └─────┬─────┘
                             ↓
                         Detector
                             ↓
                          Analyser
                             ↓
                           Actions
                             ↓
                     Security Decision
```

## Project Structure

```text
project/
├── app.py
├── requirements.txt
├── README.md
│
├── Bodyguard/
│   ├── __init__.py
│   ├── detector.py
│   ├── analyser.py
│   └── actions.py
│
├── Static/
│   ├── __init__.py
│   └── scanner.py
│
├── Dynamic/
│   ├── __init__.py
│   ├── fetcher.py
│   ├── prettifier.py
│   └── extractor.py
│
└── Explorer/
    └── explorer1.py
```

`Bodyguard/__init__.py` exposes the detector, analyser, and action stages so that `app.py` can run the security pipeline.

---

# How It Works

## 1. Static Scanner

The Static scanner uses `requests` and `BeautifulSoup` to retrieve and inspect a webpage.

It extracts information such as:

* Page metadata
* Links
* Buttons
* Forms and form controls
* Inline JavaScript event handlers
* Script information
* Destinations and URLs

The Static scanner is fast and is used as the first inspection layer.

---

## 2. Dynamic Scanner

The Dynamic scanner is used when the static result contains JavaScript-related activity such as scripts or JavaScript event handlers.

It uses:

* Playwright
* Chromium
* HTML extraction
* Page metadata extraction

The Dynamic scanner can load a page in a real browser environment rather than relying only on the original HTTP response.

Its pipeline is:

```text
URL
 ↓
Playwright / Chromium
 ↓
Rendered HTML
 ↓
Prettifier
 ↓
Extractor
 ↓
Structured page data
```

The Dynamic scanner is integrated into `app.py` and is selected when the static scan indicates that dynamic inspection may be useful.

---

# 3. Detector

`detector.py` receives the structured scanner output and searches for security signals.

Examples include:

* Suspicious intent/destination mismatches
* Cross-domain destinations
* Suspicious redirect parameters
* JavaScript navigation
* Password inputs
* Payment-related inputs
* Suspicious download destinations
* Login-related destinations

The detector provides evidence and signals. It does not make the final security decision.

---

# 4. Analyser

`analyser.py` converts detector signals into risk scores and security decisions.

### Risk thresholds

```text
0–29    → ALLOW
30–69   → WARN
70–100  → BLOCK
```

### Signal weights

High-risk signals contribute:

```text
+50 points
```

Medium-risk signals contribute:

```text
+30 points
```

The final finding score is capped at `100`.

At page level:

```text
Any BLOCK finding
        ↓
      BLOCK

Otherwise, any WARN finding
        ↓
       WARN

Otherwise
        ↓
      ALLOW
```

This allows multiple independent security signals to increase the overall risk score.

---

# 5. Action Engine

`actions.py` converts the analyser output into an action plan.

It produces information such as:

* Page-level action
* Individual finding actions
* Reasons
* Risk scores
* Destinations
* Detected signals
* Confirmation requirements
* Whether an action can be executed

The current action engine does not automatically execute BLOCK actions.

WARN actions require confirmation under the default configuration.

---

# Flask API

`app.py` provides the main Bodyguard API.

Start the server with:

```bash
python app.py
```

The API runs on:

```text
http://127.0.0.1:5000
```

## Scan Endpoint

```text
POST /scan
Content-Type: application/json
```

Example request:

```json
{
  "url": "https://example.com"
}
```

Example using Python:

```python
import requests

response = requests.post(
    "http://127.0.0.1:5000/scan",
    json={"url": "https://example.com"}
)

print(response.json())
```

The API returns structured security information, including:

```json
{
  "status": "success",
  "scan_mode": "static",
  "page": {},
  "security": {
    "decision": "ALLOW",
    "risk_score": 0
  },
  "findings": [],
  "actions": [],
  "page_action": {}
}
```

When dynamic inspection is required, `scan_mode` can indicate the Dynamic path.

---

# Explorer

`Explorer/explorer1.py` is the AI-facing component.

It uses the OpenAI API and exposes a tool named:

```text
ask_bodyguard
```

Before accessing a website, Explorer is instructed to send the URL to the Bodyguard `/scan` endpoint.

The conceptual flow is:

```text
User Query
    ↓
OpenAI Explorer
    ↓
ask_bodyguard(url)
    ↓
Bodyguard /scan
    ↓
Static Scanner
    ↓
Dynamic Scanner when required
    ↓
Detector
    ↓
Analyser
    ↓
Actions
    ↓
Security Result
    ↓
Explorer continues according to the result
```

Explorer is instructed to respect the Bodyguard decision:

```text
ALLOW → action may proceed

WARN → action requires caution/confirmation

BLOCK → action must not proceed
```

Explorer must not bypass a BLOCK decision.

---

# Environment Variables

Create a `.env` file for Explorer:

```env
OPENAI_API_KEY=your_api_key_here
BODYGUARD_URL=http://127.0.0.1:5000
```

Do not commit `.env` or your API key to Git.

---

# Installation

## 1. Create a virtual environment

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

The requirements include:

```text
Flask
requests
beautifulsoup4
python-dotenv
openai
playwright
```

## 3. Install Chromium for Playwright

The Dynamic scanner requires a Playwright browser.

Run:

```bash
python -m playwright install chromium
```

This step is required even after installing the Python `playwright` package.

---

# Running the System

## Terminal 1 — Bodyguard

From the project root:

```bash
python app.py
```

The Flask security API will start on:

```text
http://127.0.0.1:5000
```

## Terminal 2 — Explorer

Run:

```bash
python Explorer/explorer1.py
```

Then enter the requested query.

Explorer will communicate with the Bodyguard API before attempting to access a web destination.

---

# Testing the API

You can test the Bodyguard directly without Explorer.

Example:

```python
import requests

url = "https://example.com"

response = requests.post(
    "http://127.0.0.1:5000/scan",
    json={"url": url}
)

print(response.json())
```

For development, use controlled test pages to verify:

* ALLOW behaviour
* WARN behaviour
* BLOCK behaviour
* Cross-domain detection
* Redirect detection
* Payment-related detection
* Password-input detection
* JavaScript-related detection
* Static-to-Dynamic scanner selection

---

# CLI Debugging

Individual pipeline components can also be tested independently when their corresponding JSON input/output files are available.

Example analyser usage:

```bash
python Bodyguard/analyser.py analysis.json analyser.json
```

Example actions usage:

```bash
python Bodyguard/actions.py analyser.json actions.json
```

These commands are useful for inspecting the intermediate pipeline results.

---

# Security Model

The intended architecture is:

```text
AI Agent
    ↓
AI Bodyguard / Security Middleware
    ↓
Web
```

rather than:

```text
AI Agent
    ↓
Web
```

The Bodyguard acts as a defensive analysis layer between the AI agent and web destinations.

An `ALLOW` result does **not** prove that a website is trustworthy.

It means that the currently implemented detection rules did not produce a WARN or BLOCK decision for the inspected page.

Similarly, a security decision is based on the signals available to the scanner and should not be interpreted as a guarantee of complete website safety.

---

# Current Capabilities

The current system provides:

* Static HTML inspection
* Dynamic browser-based inspection
* Playwright/Chromium support
* Security signal detection
* Risk scoring
* ALLOW/WARN/BLOCK decisions
* Action planning
* Flask API integration
* AI Explorer integration
* Structured JSON communication between pipeline stages

---

# Current Limitations

The Dynamic scanner improves inspection of JavaScript-enabled pages, but it is not a complete browser security sandbox.

The current system does not guarantee:

* Complete detection of all malicious websites
* Complete detection of all dynamically generated behaviour
* Full browser isolation
* Complete analysis of every user interaction
* Complete detection of malicious behaviour hidden behind complex application state
* Proof that an ALLOW result represents a trustworthy website

The Dynamic scanner also requires both the Python Playwright package and its Chromium browser installation.

The current `/scan` endpoint processes the scanning pipeline synchronously for an individual URL.

---

# Defensive Testing

For development and demonstrations, use controlled mock websites that contain known security signals.

Useful test categories include:

```text
Safe page
   ↓
Expected: ALLOW

Suspicious page
   ↓
Expected: WARN

Multiple/high-risk signals
   ↓
Expected: BLOCK
```

A page producing multiple high-risk signals can reach the `70+` threshold and therefore exercise the BLOCK path.

---

# Version

Current Bodyguard package version:

```text
0.2.0
```

Project name:

```text
Vanguard
```

**Vanguard — Autonomous Agent Shield**

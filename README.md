AI Bodyguard

AI Bodyguard is a security middleware for AI web agents. It places a security layer between an AI explorer and the web.

The current pipeline is:

Explorer
   |
   | POST /scan
   v
app.py (Flask API)
   |
   v
scanner.py
   |
   v
detector.py
   |
   v
analyser.py
   |
   v
actions.py
   |
   v
Security decision

Project structure

project/
├── app.py
├── requirements.txt
├── README.md
│
├── Bodyguard/
│   ├── __init__.py
│   ├── scanner.py
│   ├── detector.py
│   ├── analyser.py
│   └── actions.py
│
└── Explorer/
    └── explorer1.py

Bodyguard/__init__.py exposes the four pipeline stages so that app.py can import them directly.

How it works

1. Scanner

scanner.py fetches a URL using requests and parses the returned HTML with BeautifulSoup.

It extracts:

page metadata

links

buttons and button-like elements

forms and their controls

inline JavaScript event handlers

script information

The scanner does not execute JavaScript or interact with the page dynamically.

2. Detector

detector.py receives the scanner dictionary and looks for security signals.

Examples include:

suspicious intent/destination mismatches

cross-domain destinations

suspicious redirect parameters

JavaScript navigation

password inputs

payment-related inputs

The detector provides evidence only. It does not decide whether a page should be allowed or blocked.

3. Analyser

analyser.py converts detector signals into risk scores and decisions.

Current decision thresholds:

0–29   -> ALLOW
30–69  -> WARN
70–100 -> BLOCK

High-risk signals contribute 50 points and medium-risk signals contribute 20 points. The score is capped at 100.

At page level:

any BLOCK finding -> BLOCK

otherwise any WARN finding -> WARN

otherwise -> ALLOW

4. Action engine

actions.py converts the analyser result into an action plan.

It produces:

page-level action

individual actions for findings

reasons

risk scores

destinations

signals

confirmation requirements

BLOCK actions are never automatically executable by the current action engine. WARN actions require confirmation when the default configuration is used.

Flask API

Start the Bodyguard server:

python app.py

The API runs on:

http://127.0.0.1:5000

Scan endpoint

POST /scan
Content-Type: application/json

Example request:

{
  "url": "https://example.com"
}

Example with Python:

import requests

response = requests.post(
    "http://127.0.0.1:5000/scan",
    json={"url": "https://example.com"}
)

print(response.json())

The response contains:

{
  "status": "success",
  "page": {},
  "security": {
    "decision": "ALLOW",
    "risk_score": 0
  },
  "findings": [],
  "actions": [],
  "page_action": {}
}

Explorer

Explorer/explorer1.py is the AI-facing component.

It uses the OpenAI API and exposes a tool named ask_bodyguard. Before the explorer accesses a URL, the model is instructed to send that URL to the Bodyguard /scan endpoint.

The explorer therefore follows this conceptual flow:

User query
   ↓
OpenAI Explorer
   ↓
ask_bodyguard(url)
   ↓
Bodyguard /scan
   ↓
Scanner → Detector → Analyser → Actions
   ↓
Security result
   ↓
Explorer decides how to continue

Environment variables

Create a .env file for the Explorer:

OPENAI_API_KEY=your_api_key_here
BODYGUARD_URL=http://127.0.0.1:5000

Do not commit .env or your API key to Git.

Installation

Create and activate a virtual environment:

python -m venv .venv
source .venv/bin/activate

On Windows:

python -m venv .venv
.venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Running the system

Terminal 1 — Bodyguard

From the project root:

python app.py

Terminal 2 — Explorer

Run the Explorer from its directory or with the appropriate module path:

python Explorer/explorer1.py

Then enter a query when prompted.

CLI debugging

Each pipeline component also supports direct JSON-based testing.

Scanner:

python Bodyguard/scanner.py https://example.com

Detector:

python Bodyguard/detector.py scan.json

Analyser:

python Bodyguard/analyser.py analysis.json analyser.json

Actions:

python Bodyguard/actions.py analyser.json actions.json

These commands are useful for inspecting each stage independently.

Current limitations

This is a static HTML security scanner at the current stage.

It does not yet provide a full browser environment. In particular, it does not:

execute JavaScript

render modern client-side applications

observe dynamically created DOM elements

actually click buttons

follow JavaScript-driven navigation

inspect navigation that only appears after user interaction

provide a browser-level sandbox

The detector can identify some JavaScript navigation clues from inline handlers, but it does not execute the JavaScript.

The current /scan endpoint also performs the complete scanner → detector → analyser → actions pipeline synchronously for one URL.

Security model

The intended design is:

AI agent
   ↓
Security middleware
   ↓
Web

rather than allowing the AI agent to directly access arbitrary web destinations.

The Bodyguard should be treated as a defensive analysis layer, not as proof that a website is safe. A result such as ALLOW means that no currently implemented detector rule triggered a warning or block; it does not establish that a site is trustworthy.

Version

Current Bodyguard package version:

0.1.0

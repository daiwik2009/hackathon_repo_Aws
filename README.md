🛡️ Vanguard
Autonomous Agent Shield

Vanguard is an AI-powered defensive web-security layer designed to protect autonomous AI agents before they access, navigate, or interact with potentially deceptive web pages.

Instead of allowing an AI agent to directly interact with arbitrary websites:

AI Agent
   │
   ▼
Vanguard
   │
   ├── URL validation
   ├── Static inspection
   ├── Dynamic browser inspection
   ├── Security detection
   ├── Risk analysis
   ├── Confidence estimation
   ├── AI-assisted investigation
   ├── Action planning
   └── Exploration tracking
   │
   ▼
Web

Vanguard acts as the security boundary between an autonomous agent and the web.

✨ What Vanguard Does

Vanguard combines an AI web explorer with a security analysis pipeline.

When an agent wants to access a website, Vanguard can:

Inspect the requested URL
Fetch and analyze the page
Detect suspicious security signals
Determine whether dynamic inspection is necessary
Use Playwright/Chromium for JavaScript-enabled pages
Analyze redirects and navigation behaviour
Identify deceptive or suspicious page characteristics
Calculate a risk score
Provide a confidence value when available
Produce an ALLOW, WARN, or BLOCK decision
Generate security findings and recommended actions
Perform additional AI-assisted investigation for warning cases
Track exploration depth
Persist scan results
Display live scan progress inside the web interface
Keep scans associated with the current chat
Allow multiple independent conversations
Preserve chat and scan history

The result is a unified security interface rather than a collection of disconnected command-line tools.

🧠 Core Architecture

Vanguard consists of three major layers.

┌───────────────────────────────────────────────┐
│                Vanguard Web UI                │
│                                               │
│  Authentication • Chats • Live Scan Monitor  │
│  Scan Results • Risk • Confidence • Findings │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│                  Flask App                    │
│                                               │
│  Authentication                               │
│  Chat Management                              │
│  Message Persistence                          │
│  Scan Jobs                                    │
│  Live Progress                                │
│  Scan Result Persistence                      │
│  Explorer Integration                         │
└───────────────────────┬───────────────────────┘
                        │
            ┌───────────┴───────────┐
            ▼                       ▼
┌──────────────────────┐  ┌──────────────────────┐
│   Bodyguard Engine   │  │     Explorer1        │
│                      │  │                      │
│ Scanner              │  │ AI exploration       │
│ Detector             │  │ Tool calling         │
│ Analyser             │  │ Exploration depth    │
│ Actions              │  │ Bodyguard requests   │
│ Dynamic scanner      │  │ Guarded navigation   │
└──────────────────────┘  └──────────────────────┘
🔐 Security Pipeline

The underlying Bodyguard pipeline is:

URL
 │
 ▼
URL Safety Validation
 │
 ▼
Static Scanner
 │
 ▼
Should Dynamic Scan Run?
 │
 ├── No ───────────────┐
 │                     │
 └── Yes               │
       │               │
       ▼               │
 Playwright            │
 Chromium              │
 Dynamic Scan          │
       │               │
       └───────┬───────┘
               ▼
           Detector
               │
               ▼
            Analyser
               │
               ▼
          Risk Evaluation
               │
               ▼
          Action Planner
               │
               ▼
       ALLOW / WARN / BLOCK

For warning-level results, Vanguard can optionally invoke an additional AI investigation layer.

🔎 Static Inspection

The static scanner performs analysis without requiring a full browser session.

Depending on the detected page characteristics, Vanguard can inspect signals such as:

HTML structure
Links
Forms
Password inputs
Navigation targets
Suspicious redirects
Cross-domain behaviour
JavaScript-related indicators
Payment-related page signals
Other security-relevant page characteristics

Static inspection is intentionally lightweight and is used whenever a browser-based scan is unnecessary.

🌐 Dynamic Inspection

Some websites cannot be adequately understood from their initial HTML.

Vanguard can therefore switch to a Playwright/Chromium-based dynamic scanner when the static analysis indicates that additional browser-level inspection is useful.

Dynamic inspection is intended to expose behaviour that may only become visible after rendering.

This provides additional visibility into:

JavaScript-driven pages
Dynamically generated content
Client-side navigation
Runtime page behaviour
Browser-rendered elements
Dynamic security signals

Playwright requires a locally installed Chromium browser.

🤖 AI Explorer

Vanguard integrates the project's AI_Searcher/explorer1.py module directly into the Flask application.

The Explorer does not independently bypass the security layer.

Its intended flow is:

User Request
     │
     ▼
Explorer1
     │
     │ requests URL
     ▼
Vanguard Bodyguard
     │
     ├── ALLOW
     ├── WARN
     └── BLOCK
     │
     ▼
Explorer continues according to decision

Explorer is instructed to respect Bodyguard decisions.

In particular:

ALLOW permits the requested web action to proceed
WARN identifies the destination as requiring caution
BLOCK must not be overridden
Explorer should not claim to have visited a website without the corresponding guarded action
🧭 Exploration Depth

Explorer searches can involve multiple pages.

Vanguard tracks the exploration depth of these requests.

Conceptually:

Depth 1
└── Initial page

Depth 2
├── Linked page
├── Redirected page
└── Discovered destination

Depth 3
├── Further discovered page
└── Additional navigation

The live interface exposes this activity while the scan is running.

This makes it possible to understand not only the final answer, but also which destinations Vanguard inspected along the way.

📡 Live Scan Monitoring

Vanguard's current Flask architecture includes a live Explorer job system.

A scan job maintains information such as:

Job ID
Chat ID
Current status
Current scanning stage
Pages scanned
Scan IDs
Final answer
Errors, if any

The application updates the job while exploration is occurring.

Typical progress can include stages such as:

Starting Vanguard scan…
        ↓
Connecting to Explorer1…
        ↓
Deep scanning page 1
        ↓
Completed scan
        ↓
Deep scanning page 2
        ↓
Explorer1 is searching through guarded pages…
        ↓
Scan complete

This allows the frontend to display scanning progress instead of appearing frozen while the AI is working.

📊 Risk & Confidence

Each successful scan can expose:

Decision
Risk Score
Confidence
Reason
Findings
Recommended Actions
Scan Mode

Example conceptual result:

{
  "decision": "WARN",
  "risk_score": 62,
  "confidence": 0.91,
  "reason": "Suspicious cross-domain navigation detected.",
  "scan_mode": "dynamic"
}
Risk score

The risk score represents the severity calculated from the signals detected by the implemented analysis pipeline.

It is not a universal measurement of website maliciousness.

Confidence

Confidence indicates how strongly the available analysis supports the associated security assessment when a confidence value is available.

Vanguard does not invent a confidence value when the underlying analysis does not provide one.

🚦 Security Decisions

Vanguard uses three primary decisions:

Decision	Meaning
ALLOW	No currently implemented rule produced a warning or blocking condition
WARN	Security-relevant signals require additional caution or investigation
BLOCK	The implemented security pipeline identified conditions requiring the action to be blocked

These decisions are generated from the signals available to the implemented scanner and analysis pipeline.

An ALLOW result does not prove that a website is trustworthy or completely safe.

Likewise, BLOCK does not mean Vanguard has mathematically proven that every possible behaviour of the destination is malicious.

🧩 AI-Assisted Investigation

For warning-level results, Vanguard can optionally use the project's investigation layer for additional contextual analysis.

The application can pass:

URL
Static scan result
Dynamic scan result

to the investigation component.

This produces an additional ai_review field when AI review is enabled and available.

The deterministic security decision remains part of the core pipeline; the AI review provides additional context rather than replacing the underlying scanner result.

💬 Multi-Chat Interface

Vanguard is no longer only a command-line security API.

The Flask application provides a complete chat-oriented interface.

Users can:

Create multiple chats
Switch between chats
Continue previous conversations
Store messages
Associate scans with individual chats
View scan information belonging to the current conversation
Maintain separate investigation sessions

The database keeps the chat state separate for each authenticated user.

👤 Authentication

Vanguard includes application-level authentication.

Supported functionality includes:

Sign up
Login
Logout
Password hashing
Session-based authentication
Per-user chat ownership

Usernames are validated before account creation.

Passwords are stored as password hashes rather than plaintext values.

The application also creates a CSRF token when a user session is established.

🗃️ Persistence

The Flask application uses SQLite for local persistence.

The database stores information required by the application, including:

Users
Chats
Messages
Scan Results

Scan records can contain:

Chat association
URL
Decision
Risk score
Confidence
Reason
Detailed JSON result
Message association when available

This allows scan information to remain available after the live scan has completed.

🖥️ Vanguard Interface

The current interface is designed around an AI-security-console workflow.

The main experience contains:

┌──────────────┬──────────────────────┬──────────────────────┐
│              │                      │                      │
│ Chat History │      Conversation    │   Security Monitor   │
│              │                      │                      │
│ Chat 1       │  User message        │   Pages scanned      │
│ Chat 2       │                      │   Risk score         │
│ Chat 3       │  AI response         │   Confidence         │
│              │                      │   Decision            │
│              │  Scan in progress    │   Reason              │
│              │                      │   Depth               │
│              │                      │                      │
└──────────────┴──────────────────────┴──────────────────────┘

The security monitor is intended to update while exploration is happening instead of only appearing after the final response.

🔄 End-to-End Request Flow

A typical request follows this lifecycle:

1. User creates/selects a chat
              │
              ▼
2. User submits a request
              │
              ▼
3. Flask creates an Explorer job
              │
              ▼
4. Explicit URLs are detected
              │
              ▼
5. Vanguard begins scanning
              │
              ▼
6. Live scan state is updated
              │
              ▼
7. Explorer1 performs guarded exploration
              │
              ▼
8. Each requested destination reaches Bodyguard
              │
              ▼
9. Static/dynamic analysis runs
              │
              ▼
10. Risk + confidence + decision generated
              │
              ▼
11. Result persisted to database
              │
              ▼
12. Scan monitor receives the result
              │
              ▼
13. Explorer continues or stops according
    to the security decision
              │
              ▼
14. Final AI response generated
              │
              ▼
15. Assistant message persisted
              │
              ▼
16. Job becomes completed

The completed job remains associated with the current chat instead of automatically forcing the user into a new conversation.

🏗️ Project Structure

The repository is conceptually organized as:

Vanguard/
│
├── app.py
│
├── AI_Searcher/
│   ├── explorer1.py
│   └── ...
│
├── Bodyguard/
│   ├── scanner.py
│   ├── detector.py
│   ├── analyser.py
│   ├── actions.py
│   ├── investigator.py
│   ├── ai_analyser.py
│   └── __init__.py
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   └── js/
│
├── requirements.txt
├── .env
├── .gitignore
└── README.md

The exact directory names may vary between repository revisions, but the architectural roles remain the same.

🧱 Main Components
app.py

The main Flask application.

Responsible for:

Web server
Authentication
Sessions
Database access
Chat management
Messages
Scan API
Explorer integration
Background Explorer jobs
Live scan state
Scan persistence
Frontend rendering

The current architecture does not require a second Flask application for Explorer.

Bodyguard/scanner.py

Responsible for fetching and inspecting web destinations.

Provides the static and dynamic scanning foundations.

Bodyguard/detector.py

Processes scanner output and identifies security-relevant signals.

Bodyguard/analyser.py

Evaluates the detected signals and produces higher-level security assessment information such as risk and overall decision.

Bodyguard/actions.py

Converts the security assessment into an action plan.

Bodyguard/investigator.py

Provides contextual investigation capabilities used by the optional AI-review layer.

Bodyguard/ai_analyser.py

Supports AI-assisted analysis where enabled by the application.

AI_Searcher/explorer1.py

Provides the autonomous exploration layer.

Explorer uses an ask_bodyguard tool to request security inspection before accessing a destination.

The current integration supports scan callbacks so the Flask application can observe exploration progress while the Explorer is working.

⚙️ Installation
1. Clone the repository
git clone <your-repository-url>
cd Vanguard
2. Create a virtual environment
Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1

If PowerShell execution policy prevents activation, the environment can also be used directly through its Python executable.

Linux / macOS
python -m venv .venv
source .venv/bin/activate
3. Install dependencies
pip install -r requirements.txt

The current dependency set includes the main packages required by the application, including:

Flask
requests
beautifulsoup4
python-dotenv
openai
playwright
🌐 Install Playwright Chromium

Because Vanguard can perform dynamic browser-based inspection, install the Chromium browser used by Playwright:

python -m playwright install chromium

This is required in addition to installing the Python playwright package.

🔑 Environment Configuration

Create a .env file in the project root.

Example:

OPENAI_API_KEY=your_openai_api_key
BODYGUARD_URL=http://127.0.0.1:5000
SECRET_KEY=replace_with_a_random_secret

Do not commit API keys or other secrets to Git.

A .gitignore should exclude:

.env
venv/
.venv/
__pycache__/
*.pyc
*.db
▶️ Running Vanguard

The current architecture is designed around the Flask application.

From the project root:

python app.py

The application will normally be available at:

http://127.0.0.1:5000

Open that address in a browser.

The Flask application loads the Explorer module internally, so the current integrated architecture does not require running a separate Flask server for Explorer.

🔌 Bodyguard API

The primary backward-compatible scan endpoint is:

POST /scan

Example request:

import requests

response = requests.post(
    "http://127.0.0.1:5000/scan",
    json={
        "url": "https://example.com"
    },
    timeout=60
)

print(response.json())

A successful response can contain:

{
    "status": "success",
    "url": "https://example.com",
    "scan_mode": "static",
    "page": {},
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

The exact response fields can evolve as the analysis pipeline develops.

💬 Chat API

The Flask application also exposes chat-oriented routes.

The chat layer is responsible for:

Creating conversations
Loading conversations
Sending messages
Starting Explorer jobs
Polling job state
Returning scan information
Persisting assistant responses

The frontend uses these routes to maintain the multi-chat experience.

🔬 Defensive Testing

Vanguard is intended for defensive security research, controlled demonstrations, and testing of autonomous-agent safeguards.

Use controlled pages containing known signals rather than attempting to test against systems you do not own or have permission to assess.

Useful test cases include:

Safe page
Expected:
ALLOW
Suspicious page
Expected:
WARN
High-risk test page
Expected:
BLOCK

Useful security-test categories include:

Cross-domain navigation
Redirects
Suspicious payment flows
Password-input pages
Deceptive UI
JavaScript navigation
Dynamic page behaviour
Suspicious external links
Multiple combined security signals

A controlled test page containing enough high-risk signals can be used to exercise the higher-risk decision path.

🧪 Testing the Vanguard Stack

A good development test sequence is:

1. Start Flask
       ↓
2. Log in
       ↓
3. Create a chat
       ↓
4. Submit a known-safe URL
       ↓
5. Confirm scan progress appears
       ↓
6. Confirm scan result is persisted
       ↓
7. Submit a controlled suspicious page
       ↓
8. Confirm risk + confidence + reason appear
       ↓
9. Confirm Explorer respects the decision
       ↓
10. Switch chats
       ↓
11. Return to the original chat
       ↓
12. Confirm history remains intact
🛡️ Security Model

Vanguard follows a guarded-agent model:

                 ┌──────────────────┐
                 │    AI Explorer   │
                 └────────┬─────────┘
                          │
                    URL request
                          │
                          ▼
                 ┌──────────────────┐
                 │     Vanguard     │
                 │    Bodyguard     │
                 └────────┬─────────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
            ALLOW        WARN        BLOCK
              │           │           │
              ▼           ▼           X
            Proceed    Investigate    Stop

The fundamental security principle is:

The AI agent should not be allowed to bypass its security layer when interacting with the web.

⚠️ Limitations

Vanguard is a defensive analysis system, not a universal website-safety oracle.

It does not guarantee:

Detection of every malicious website
Detection of every deceptive page
Detection of every dynamically generated behaviour
Complete browser isolation
Complete coverage of every user interaction
Detection of malicious behaviour hidden behind complex application state
That an ALLOW decision means a website is trustworthy

Dynamic scanning improves visibility into JavaScript-enabled pages, but it is not equivalent to a fully isolated browser security sandbox.

AI-assisted analysis can also be affected by incomplete page information, model limitations, or unavailable investigation data.

🔐 Important Deployment Notes

The built-in Flask development server is suitable for local development and demonstrations.

For public deployment:

Use a production WSGI server
Use HTTPS
Store secrets outside the repository
Configure a secure session secret
Restrict database permissions
Apply appropriate network isolation
Add request rate limiting
Consider authentication hardening
Avoid exposing debugging information
Run browser-based scanning in an appropriately isolated environment

A publicly reachable Vanguard instance should not be treated as a hardened production security gateway merely because the application itself performs security analysis.

🌍 Public Demonstration / Tunneling

For demonstrations where an external service needs to reach the locally running Vanguard instance, a tunneling service such as ngrok can expose the local Flask server through a temporary public URL.

For example:

ngrok http 5000

The resulting public address can then be used where an externally reachable endpoint is required.

For production, use an appropriately configured hosting/deployment architecture instead of relying on a development tunnel.

🧹 Development Hygiene

Do not commit:

.env
*.db
__pycache__/
*.pyc
venv/
.venv/
temporary scan outputs
API keys

Python cache files such as __pycache__ and .pyc files are generated artifacts and normally do not need to be reviewed as application source code.

🧭 Design Principles

Vanguard is built around several principles:

1. Security before navigation

The agent should reach the web through the security layer.

2. Deterministic analysis first

The core scanner and analysis pipeline provides the primary security decision.

3. Dynamic analysis when required

Browser-based inspection is used when static inspection alone is insufficient.

4. Observable exploration

Users should be able to see what Vanguard is scanning instead of waiting blindly for a final answer.

5. Persistent evidence

Scan results should remain associated with the conversation that generated them.

6. Respect security decisions

Explorer should never silently bypass a BLOCK result.

7. Explainability

Risk scores should be accompanied by findings, reasons, and available confidence information.

8. Defensive operation

Vanguard is intended for authorized security testing, research, and protection of autonomous agents.

🚀 Roadmap

Potential future improvements include:

Stronger browser isolation
More comprehensive redirect-chain analysis
Improved cross-domain relationship tracking
More dynamic interaction analysis
Screenshot-based security inspection
Richer scan timelines
Persistent Explorer job storage
Distributed background workers
Redis/Celery-based job processing
Production database support
More granular permissions
Advanced authentication
Security event logging
Scan replay
Exportable security reports
Improved AI-assisted investigation
More comprehensive test coverage
Containerized deployment
📜 Version

Current project identity:

Project: Vanguard
Tagline: Autonomous Agent Shield
Architecture: Flask + AI Explorer + Bodyguard

The Bodyguard engine retains its own internal package versioning where applicable.

🛡️ Vanguard

Autonomous Agent Shield

                    VANGUARD
             Autonomous Agent Shield

                 AI Explorer
                      │
                      ▼
               ┌─────────────┐
               │  Bodyguard  │
               └──────┬──────┘
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
        ALLOW        WARN        BLOCK
          │           │           │
          ▼           ▼           X
        Proceed    Investigate    Stop

Vanguard's purpose is simple:

Give autonomous agents a security layer before they interact with the web.
import logging
import os
import re
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask, abort, flash, jsonify, redirect, render_template,
    request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from Bodyguard import (
    analyze_scan,
    evaluate_page,
    build_action_plan,
    should_use_dynamic,
    is_safe_url,
    Investigator,
)
from Static import scan_page as static_scan
from Dynamic import scan as dynamic_scan

# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "vanguard.db"

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("VANGUARD_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

logger = logging.getLogger(__name__)

ENABLE_AI_REVIEW = os.environ.get("VANGUARD_AI_REVIEW", "1") != "0"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL DEFAULT 'New chat',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'assistant', 'system')),
            content TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER NOT NULL,
            message_id INTEGER,
            url TEXT NOT NULL,
            decision TEXT,
            risk_score REAL DEFAULT 0,
            confidence REAL,
            reason TEXT,
            details_json TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
            FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_chats_user_updated
            ON chats(user_id, updated_at DESC);

        CREATE INDEX IF NOT EXISTS idx_messages_chat
            ON messages(chat_id, created_at);

        CREATE INDEX IF NOT EXISTS idx_scans_chat
            ON scan_results(chat_id, created_at);
        """
    )
    db.commit()
    db.close()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    db = get_db()
    user = db.execute(
        "SELECT id, username, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    db.close()
    return user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Login required"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def owned_chat(chat_id):
    user = current_user()
    if not user:
        return None

    db = get_db()
    chat = db.execute(
        "SELECT * FROM chats WHERE id = ? AND user_id = ?",
        (chat_id, user["id"]),
    ).fetchone()
    db.close()
    return chat


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

@app.before_request
def csrf_protect():
    # /scan is the existing machine-to-machine API used by explorer1.py.
    # Browser forms/API calls use CSRF protection; the scanner endpoint keeps
    # its existing JSON contract and relies on its URL safety guard.
    if request.path == "/scan":
        return None

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)

        supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if supplied != session["csrf_token"]:
            return jsonify({"status": "error", "message": "Invalid CSRF token"}), 403


@app.context_processor
def inject_globals():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {
        "current_user": current_user(),
        "csrf_token": session["csrf_token"],
    }


# ---------------------------------------------------------------------------
# Existing Bodyguard scan pipeline
# ---------------------------------------------------------------------------

def get_ai_review(url, static_result, dynamic_result):
    try:
        investigator = Investigator(max_depth=1)
        return investigator.investigate(
            url,
            precomputed_static=static_result,
            precomputed_dynamic=dynamic_result,
        )
    except Exception as error:
        logger.warning("AI review unavailable for %s: %s", url, error)
        return {"status": "ai_review_unavailable", "error": str(error)}


def scan_url(url):
    """Run the existing deterministic Bodyguard pipeline for one URL."""
    safe, reason = is_safe_url(url)
    if not safe:
        return {
            "status": "error",
            "url": url,
            "message": f"URL rejected: {reason}",
        }

    try:
        static_result = static_scan(url)
        dynamic_result = None

        if should_use_dynamic(static_result):
            dynamic_result = dynamic_scan(url)
            scan_result = dynamic_result
            scan_mode = "dynamic"
        else:
            scan_result = static_result
            scan_mode = "static"

        analysis = analyze_scan(scan_result)
        evaluated = evaluate_page(analysis)
        action_plan = build_action_plan(evaluated)

        ai_review = None
        if ENABLE_AI_REVIEW and evaluated.get("overall_decision") == "WARN":
            ai_review = get_ai_review(url, static_result, dynamic_result)

        page = evaluated.get("page") or {}
        findings = evaluated.get("findings") or []
        risk_score = evaluated.get("risk_score", 0)
        decision = evaluated.get("overall_decision", "WARN")

        # Try common confidence fields without changing the Bodyguard result.
        confidence = (
            evaluated.get("confidence")
            or page.get("confidence")
            or analysis.get("confidence")
        )

        reason_text = make_reason(findings, decision)

        response = {
            "status": "success",
            "url": url,
            "scan_mode": scan_mode,
            "page": page,
            "security": {
                "decision": decision,
                "risk_score": risk_score,
                "confidence": confidence,
            },
            "findings": findings,
            "reason": reason_text,
            "actions": action_plan.get("actions", []),
            "page_action": action_plan.get("page_action", {}),
        }

        if ai_review is not None:
            response["ai_review"] = ai_review

        return response

    except Exception:
        logger.exception("Scan failed for %s", url)
        return {
            "status": "error",
            "url": url,
            "message": "Internal scan error",
        }


def make_reason(findings, decision):
    if findings:
        first = findings[0]
        if isinstance(first, dict):
            for key in ("reason", "description", "message", "title", "name"):
                if first.get(key):
                    return str(first[key])[:240]
        return str(first)[:240]

    defaults = {
        "ALLOW": "No significant security finding was reported by the scanner.",
        "WARN": "The page contains signals that require additional review.",
        "BLOCK": "The scanner identified signals requiring the page to be blocked.",
    }
    return defaults.get(decision, "No concise reason was returned by the scanner.")


@app.post("/scan")
def scan():
    """Backward-compatible API used by explorer1.py and other clients."""
    data = request.get_json(silent=True) or {}
    url = data.get("url")
    if not url:
        return jsonify({"status": "error", "message": "URL is required"}), 400
    return jsonify(scan_url(url))


# ---------------------------------------------------------------------------
# Explorer / AI_Searcher adapter
# ---------------------------------------------------------------------------

def extract_urls(text):
    candidates = re.findall(
        r"https?://[^\s<>\"]+",
        text or "",
        flags=re.IGNORECASE,
    )
    clean = []
    for value in candidates:
        value = value.rstrip(".,);]}>")
        if value not in clean:
            clean.append(value)
    return clean


def run_explorer(message, chat_id):
    """
    Connect to the project's AI_Searcher/explorer1.py without creating
    another Flask application.

    Supported layouts:
      AI_Searcher/explorer1.py
      Explorer/explorer1.py

    If explorer1 exposes ask_bodyguard(message), it is used for the
    natural-language response. URL scanning still goes through this app's
    /scan pipeline so the same security decision is used everywhere.
    """
    explorer = None
    import_error = None

    for module_name in ("AI_Searcher.explorer1", "Explorer.explorer1"):
        try:
            explorer = __import__(module_name, fromlist=["*"])
            break
        except Exception as exc:
            import_error = exc

    urls = extract_urls(message)
    scans = [scan_url(url) for url in urls]

    # Persist scans so the sidebars remain available in chat history.
    db = get_db()
    for result in scans:
        if result.get("status") == "success":
            db.execute(
                """
                INSERT INTO scan_results
                (chat_id, message_id, url, decision, risk_score,
                 confidence, reason, details_json)
                VALUES (?, NULL, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chat_id,
                    result["url"],
                    result["security"].get("decision"),
                    result["security"].get("risk_score", 0),
                    result["security"].get("confidence"),
                    result.get("reason"),
                    __import__("json").dumps(result, default=str),
                ),
            )
    db.commit()
    db.close()

    # Preferred explorer interface.
    if explorer and hasattr(explorer, "explore"):
        try:
            answer = explorer.explore(message)
            if isinstance(answer, dict):
                answer_text = (
                    answer.get("response")
                    or answer.get("answer")
                    or answer.get("message")
                    or str(answer)
                )
            else:
                answer_text = str(answer)

            return answer_text, scans
        except Exception as exc:
            logger.exception("explorer1.ask_bodyguard failed: %s", exc)

    # A small, safe fallback if explorer1 has a different interface.
    if scans:
        lines = []
        for result in scans:
            if result.get("status") == "success":
                sec = result["security"]
                lines.append(
                    f"{result['url']} — {sec.get('decision', 'WARN')} "
                    f"(risk {sec.get('risk_score', 0)}) — {result.get('reason')}"
                )
            else:
                lines.append(f"{result['url']} — {result.get('message', 'Scan failed')}")
        return (
            "I scanned the URL(s) through Vanguard's Bodyguard pipeline:\n\n"
            + "\n".join(lines)
        ), scans

    if import_error:
        logger.warning("Could not import explorer1.py: %s", import_error)

    return (
        "I could not reach the AI searcher yet. The Flask application is running, "
        "and direct URL scanning is available. Check that AI_Searcher/explorer1.py "
        "is importable and exposes explore(query)."
    ), scans


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@app.get("/login")
def login():
    if current_user():
        return redirect(url_for("index"))
    return render_template("index.html", auth_mode="login")


@app.post("/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
        (username,),
    ).fetchone()
    db.close()

    if not user or not check_password_hash(user["password_hash"], password):
        flash("Invalid username or password.", "error")
        return redirect(url_for("login"))

    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("index"))


@app.get("/signup")
def signup():
    if current_user():
        return redirect(url_for("index"))
    return render_template("index.html", auth_mode="signup")


@app.post("/signup")
def signup_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if len(username) < 3 or len(username) > 64:
        flash("Username must be between 3 and 64 characters.", "error")
        return redirect(url_for("signup"))

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("signup"))

    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        db.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        db.close()
        flash("That username is already in use.", "error")
        return redirect(url_for("signup"))
    db.close()

    session.clear()
    session["user_id"] = user_id
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("index"))


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Chat UI/API
# ---------------------------------------------------------------------------

@app.get("/")
@login_required
def index():
    db = get_db()
    chats = db.execute(
        """
        SELECT id, title, created_at, updated_at
        FROM chats
        WHERE user_id = ?
        ORDER BY updated_at DESC
        """,
        (current_user()["id"],),
    ).fetchall()
    db.close()

    return render_template("index.html", chats=chats, auth_mode=None)


@app.post("/api/chats")
@login_required
def create_chat():
    user_id = current_user()["id"]
    title = (request.json or {}).get("title", "New chat").strip() or "New chat"

    db = get_db()
    cursor = db.execute(
        "INSERT INTO chats (user_id, title) VALUES (?, ?)",
        (user_id, title[:100]),
    )
    db.commit()
    chat_id = cursor.lastrowid
    db.close()

    return jsonify({"status": "success", "chat_id": chat_id, "title": title[:100]})


@app.get("/api/chats/<int:chat_id>")
@login_required
def get_chat(chat_id):
    chat = owned_chat(chat_id)
    if not chat:
        return jsonify({"status": "error", "message": "Chat not found"}), 404

    db = get_db()
    messages = db.execute(
        """
        SELECT id, role, content, created_at
        FROM messages
        WHERE chat_id = ?
        ORDER BY id
        """,
        (chat_id,),
    ).fetchall()

    scans = db.execute(
        """
        SELECT id, url, decision, risk_score, confidence, reason, created_at
        FROM scan_results
        WHERE chat_id = ?
        ORDER BY id
        """,
        (chat_id,),
    ).fetchall()
    db.close()

    return jsonify({
        "status": "success",
        "chat": dict(chat),
        "messages": [dict(row) for row in messages],
        "scans": [dict(row) for row in scans],
    })


@app.delete("/api/chats/<int:chat_id>")
@login_required
def delete_chat(chat_id):
    chat = owned_chat(chat_id)
    if not chat:
        return jsonify({"status": "error", "message": "Chat not found"}), 404

    db = get_db()
    db.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
    db.commit()
    db.close()
    return jsonify({"status": "success"})


@app.post("/api/chats/<int:chat_id>/messages")
@login_required
def send_message(chat_id):
    chat = owned_chat(chat_id)
    if not chat:
        return jsonify({"status": "error", "message": "Chat not found"}), 404

    data = request.get_json(silent=True) or {}
    content = str(data.get("message", "")).strip()
    if not content:
        return jsonify({"status": "error", "message": "Message is required"}), 400

    db = get_db()
    user_message = db.execute(
        "INSERT INTO messages (chat_id, role, content) VALUES (?, 'user', ?)",
        (chat_id, content),
    )
    user_message_id = user_message.lastrowid

    # Automatically name a fresh chat from the first message.
    if chat["title"] == "New chat":
        title = content[:60] + ("…" if len(content) > 60 else "")
        db.execute(
            "UPDATE chats SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (title, chat_id),
        )
    else:
        db.execute(
            "UPDATE chats SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (chat_id,),
        )
    db.commit()
    db.close()

    answer, scans = run_explorer(content, chat_id)

    db = get_db()
    assistant_message = db.execute(
        "INSERT INTO messages (chat_id, role, content) VALUES (?, 'assistant', ?)",
        (chat_id, answer),
    )
    assistant_message_id = assistant_message.lastrowid

    # Associate newly-created scan rows with the assistant message.
    if scans:
        db.execute(
            """
            UPDATE scan_results
            SET message_id = ?
            WHERE chat_id = ? AND message_id IS NULL
              AND id > COALESCE(
                  (SELECT MAX(id) FROM scan_results
                   WHERE chat_id = ? AND message_id IS NOT NULL), 0
              )
            """,
            (assistant_message_id, chat_id, chat_id),
        )

    db.execute(
        "UPDATE chats SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (chat_id,),
    )
    db.commit()
    db.close()

    return jsonify({
        "status": "success",
        "user_message_id": user_message_id,
        "assistant_message_id": assistant_message_id,
        "answer": answer,
        "scans": scans,
    })


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

init_db()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

import logging

from flask import Flask, request, jsonify

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

app = Flask(__name__)
logger = logging.getLogger(__name__)

# FIX: Investigator + ai_analyser.py existed in the repo but were never
# imported anywhere in app.py -- the live /scan endpoint only ever ran
# the deterministic pipeline. AI review is now attempted, but only for
# WARN pages (ambiguous cases the deterministic engine itself is unsure
# about), and it only ever adds *context* to the response -- per its
# own system prompt, the AI layer does not execute actions and never
# overrides the deterministic ALLOW/BLOCK decision. Set this to False,
# or leave OPENAI_API_KEY unset, to run Bodyguard as a purely
# deterministic engine with no outbound AI calls at all.
ENABLE_AI_REVIEW = True


def get_ai_review(url, static_result, dynamic_result):
    """
    Best-effort contextual AI review for an ambiguous (WARN) page.

    Never raises -- a failure here must not break the deterministic
    /scan response, which is already computed by this point.
    """

    try:
        investigator = Investigator(max_depth=1)

        return investigator.investigate(
            url,
            precomputed_static=static_result,
            precomputed_dynamic=dynamic_result,
        )

    except Exception as error:
        logger.warning("AI review unavailable for %s: %s", url, error)

        return {
            "status": "ai_review_unavailable",
            "error": str(error),
        }


@app.post("/scan")
def scan():
    data = request.get_json(silent=True)

    if not data or not data.get("url"):
        return jsonify({
            "status": "error",
            "message": "URL is required"
        }), 400

    url = data.get("url")

    # -----------------------------
    # 0. SSRF GUARD
    # -----------------------------
    # FIX: previously any string reaching here was passed straight
    # into static_scan()/dynamic_scan() with no restriction on scheme
    # or destination -- a classic SSRF hole in a tool whose entire job
    # is fetching caller-supplied URLs server-side. Reject before any
    # scanner touches the URL.
    safe, reason = is_safe_url(url)

    if not safe:
        return jsonify({
            "status": "error",
            "message": f"URL rejected: {reason}"
        }), 400

    try:
        # -----------------------------
        # 1. STATIC SCAN
        # -----------------------------
        static_result = static_scan(url)

        # -----------------------------
        # 2. DYNAMIC DECISION
        # -----------------------------
        dynamic_result = None

        if should_use_dynamic(static_result):
            dynamic_result = dynamic_scan(url)
            scan_result = dynamic_result
            scan_mode = "dynamic"
        else:
            scan_result = static_result
            scan_mode = "static"

        # -----------------------------
        # 3. BODYGUARD PIPELINE
        # -----------------------------
        analysis = analyze_scan(scan_result)
        evaluated = evaluate_page(analysis)
        action_plan = build_action_plan(evaluated)

        # -----------------------------
        # 4. AI REVIEW (WARN only)
        # -----------------------------
        # FIX: reuses the static/dynamic results already computed
        # above instead of re-scanning the same root URL a second
        # time inside the Investigator.
        ai_review = None

        if ENABLE_AI_REVIEW and evaluated.get("overall_decision") == "WARN":
            ai_review = get_ai_review(url, static_result, dynamic_result)

        # -----------------------------
        # 5. RESPONSE
        # -----------------------------
        response = {
            "status": "success",
            "scan_mode": scan_mode,
            "page": evaluated.get(
                "page",
                {}
            ),
            "security": {
                "decision": evaluated.get(
                    "overall_decision"
                ),
                "risk_score": evaluated.get(
                    "risk_score",
                    0
                ),
            },
            "findings": evaluated.get(
                "findings",
                []
            ),
            "actions": action_plan.get(
                "actions",
                []
            ),
            "page_action": action_plan.get(
                "page_action",
                {}
            )
        }

        if ai_review is not None:
            response["ai_review"] = ai_review

        return jsonify(response)

    except Exception as error:
        # FIX: previously returned str(error) directly to the caller,
        # which can leak internal paths/details. Log the real error
        # server-side, return a generic message to the client.
        logger.exception("Scan failed for %s", url)

        return jsonify({
            "status": "error",
            "message": "Internal scan error"
        }), 500


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # FIX: debug=True exposes the Werkzeug interactive debugger, which
    # allows arbitrary code execution if the port is ever reachable
    # beyond your own machine. Off by default now.
    app.run(debug=False)
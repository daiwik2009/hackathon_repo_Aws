from flask import Flask, request, jsonify

from Bodyguard import (
    analyze_scan,
    evaluate_page,
    build_action_plan,
)

from Static import scan_page as static_scan
from Dynamic import scan as dynamic_scan


app = Flask(__name__)


def should_use_dynamic(scan_result):
    """
    Decide whether the page should receive
    browser-based dynamic inspection.

    Temporary v0.2 heuristic.
    Improve this once the detection logic is tested.
    """

    scripts = scan_result.get("scripts", [])
    handlers = scan_result.get("javascript_handlers", [])

    return bool(scripts or handlers)


@app.post("/scan")
def scan():

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({
            "status": "error",
            "message": "URL is required"
        }), 400

    url = data.get("url")

    if not url:
        return jsonify({
            "status": "error",
            "message": "URL is required"
        }), 400

    try:

        # -----------------------------
        # 1. STATIC SCAN
        # -----------------------------

        static_result = static_scan(url)

        # -----------------------------
        # 2. DYNAMIC DECISION
        # -----------------------------

        if should_use_dynamic(static_result):

            scan_result = dynamic_scan(url)
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
        # 4. RESPONSE
        # -----------------------------

        return jsonify({
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
        })

    except Exception as error:

        return jsonify({
            "status": "error",
            "message": str(error)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)
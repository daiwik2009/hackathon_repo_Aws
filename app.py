from flask import Flask, request, jsonify

from Bodyguard import (
    scan_page,
    analyze_scan,
    evaluate_page,
    build_action_plan,
)

app = Flask(__name__)


@app.post("/scan")
def scan():
    data = request.get_json()

    url = data.get("url")

    if not url:
        return jsonify({
            "status": "error",
            "message": "URL is required"
        }), 400

    scan_result = scan_page(url)

    analysis = analyze_scan(scan_result)

    evaluated = evaluate_page(analysis)

    action_plan = build_action_plan(evaluated)

    return jsonify({
        "status": "success",
        "page": evaluated.get("page", {}),
        "security": {
            "decision": evaluated.get("overall_decision"),
            "risk_score": evaluated.get("highest_risk_score"),
        },
        "findings": evaluated.get("findings", []),
        "actions": action_plan.get("actions", []),
        "page_action": action_plan.get("page_action", {})
    })


if __name__ == "__main__":
    app.run(debug=True)

import os
import json
import requests
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

BODYGUARD_URL = os.getenv(
    "BODYGUARD_URL",
    "http://127.0.0.1:5000"
)

def ask_bodyguard(url, scan_callback=None, depth=1):
    """Ask Bodyguard to inspect a URL."""
    if scan_callback:
        try:
            scan_callback(url, {"status": "scanning", "url": url}, depth, "scanning")
        except Exception:
            pass

    try:
        response = requests.post(
            f"{BODYGUARD_URL}/scan",
            json={"url": url},
            timeout=30
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, ValueError) as exc:
        result = {"status": "error", "url": url, "error": str(exc)}
    if scan_callback:
        try:
            scan_callback(url, result, depth, "completed")
        except Exception:
            pass
    return result


def explore(query, scan_callback=None):
    instructions = """
You are Explorer1, an AI web explorer.

You do NOT have direct web access.

Before using or visiting a website, you MUST use the
Bodyguard API to inspect the URL.

Bodyguard is the security layer between you and the web.

You must respect Bodyguard's decision:

* ALLOW: the requested web action may proceed.
* WARN: treat the action as requiring caution/confirmation.
* BLOCK: do not proceed with that action.

Never bypass, ignore, or override a BLOCK decision.

If you need to visit a URL, first call the ask_bodyguard tool
with that URL.

Do not claim that you visited a website unless Bodyguard
has permitted the relevant action.
"""

    tools = [
        {
            "type": "function",
            "function": {
                "name": "ask_bodyguard",
                "description": (
                    "Ask the Bodyguard security API to inspect a URL "
                    "before accessing or interacting with it."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": (
                                "The URL that Explorer wants to access."
                            )
                        }
                    },
                    "required": ["url"],
                    "additionalProperties": False
                }
            }
        }
    ]

    messages = [
        {"role": "system", "content": instructions},
        {"role": "user", "content": query}
    ]

    exploration_depth = 0

    while True:
        exploration_depth += 1
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=tools
        )

        response_message = response.choices[0].message
        
        # FIX 1: Append response_message directly as a dict or handle tool_calls explicitly
        messages.append(response_message.model_dump(exclude_none=True))

        tool_calls = response_message.tool_calls

        if not tool_calls:
            return response_message.content

        for tool_call in tool_calls:
            if tool_call.function.name == "ask_bodyguard":
                arguments = json.loads(tool_call.function.arguments)
                url = arguments.get("url")

                try:
                    result = ask_bodyguard(
                        url,
                        scan_callback=scan_callback,
                        depth=exploration_depth,
                    )
                except Exception as e:
                    result = {
                        "status": "error",
                        "url": url,
                        "error": str(e)
                    }
                    if scan_callback:
                        try:
                            scan_callback(url, result, exploration_depth, "completed")
                        except Exception:
                            pass

                # FIX 2: Ensure tool_call_id uses the correct attribute
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result)
                })


if __name__ == "__main__":
    query = input("What should I search? ")
    result = explore(query)
    print("\nExplorer:")
    print(result)
import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def explore(query):
    response = client.responses.create(
        model="gpt-5.6-luna",
        tools=[
            {"type": "web_search"}
        ],
        input=query
    )

    return response.output_text


if __name__ == "__main__":
    query = input("What should I search? ")

    result = explore(query)

    print("\nExplorer:")
    print(result)
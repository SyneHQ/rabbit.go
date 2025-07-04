import json
import os
import urllib.request
import sys

def generate_release_notes(model):
    try:
        data = json.dumps({
            "model": model,
            "messages": [
                {
                    "role": "system", 
                    "content": """You are a helpful assistant that writes short, simple, and clear release notes for a FOSS TCP tunnel project. Summarize the main changes in plain language, grouped as 'New', 'Improved', or 'Fixed'. Only output the formatted release notes, nothing else. Add jokes, tcp nonsense, and other fun stuff."""
                },
                {
                    "role": "user",
                    "content": f"Generate detailed release notes with the following information:\n\nCommit History: {os.environ.get('COMMITS')}\nRepository: {os.environ.get('GITHUB_REPOSITORY')}\nRelease Name: {os.environ.get('DOCKERLIKE_RELEASE_NAME')}\nVersion: {os.environ.get('NEW_VERSION')}\n\nPlease analyze the commits and generate comprehensive release notes following the system guidelines."
                }
            ]
        })

        url = os.environ.get("OPENAI_BASE_URL") + "/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY')}"
        }

        req = urllib.request.Request(
            url,
            data=data.encode("utf-8"),
            headers=headers,
            method="POST"
        )

        with urllib.request.urlopen(req) as response:
            response_data = response.read()
            content = json.loads(response_data)["choices"][0]["message"]["content"]
            with open("release_notes.md", "w") as f:
                f.write(content)

    except Exception as error:
        print(f"Error: {error}")
        exit(1)

if __name__ == "__main__":
    # read from args
    model = sys.argv[1]
    generate_release_notes(model)

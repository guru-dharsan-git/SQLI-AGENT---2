import json
import re
import time

import requests

from agent.config import LLMConfig


class LLMClient:
    def __init__(self, config: LLMConfig):
        self.config = config
        self.client = None
        self.types = None

        if config.provider == "nvidia":
            return

        try:
            from google import genai
            from google.genai import types
        except ImportError as error:
            raise RuntimeError(
                "Install google-genai before running the LLM SQLi phase."
            ) from error

        self.client = genai.Client(api_key=config.api_key)
        self.types = types

    def ask_json(self, messages):
        if self.config.provider == "nvidia":
            return self.ask_nvidia_json(messages)

        return self.ask_gemini_json(messages)

    def ask_gemini_json(self, messages):
        system_instruction, contents = split_messages(messages)
        response = self.client.models.generate_content(
            model=self.config.model,
            contents=contents,
            config=self.types.GenerateContentConfig(
                system_instruction=system_instruction or None,
                temperature=self.config.temperature,
                response_mime_type="application/json",
            ),
        )
        content = response.text or ""

        return json.loads(extract_json_text(content))

    def ask_nvidia_json(self, messages):
        body = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": False,
            "response_format": {"type": "json_object"},
        }
        response = self.post_nvidia(body)

        if response.status_code in {400, 422}:
            body.pop("response_format", None)
            response = self.post_nvidia(body)

        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]

        return json.loads(extract_json_text(content))

    def post_nvidia(self, body):
        last_error = None

        for attempt in range(self.config.retries + 1):
            try:
                return requests.post(
                    nvidia_chat_url(self.config.base_url),
                    headers={
                        "Authorization": f"Bearer {self.config.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=body,
                    timeout=self.config.request_timeout,
                )
            except requests.RequestException as error:
                last_error = error

                if attempt >= self.config.retries:
                    raise RuntimeError(
                        f"NVIDIA LLM request failed after {attempt + 1} attempt(s): {error}"
                    ) from error

                time.sleep(1 + attempt)

        raise RuntimeError(f"NVIDIA LLM request failed: {last_error}")


def split_messages(messages):
    system_parts = []
    content_parts = []

    for message in messages:
        content = str(message.get("content", "")).strip()

        if not content:
            continue

        if message.get("role") == "system":
            system_parts.append(content)
        else:
            content_parts.append(content)

    return "\n\n".join(system_parts), "\n\n".join(content_parts)


def nvidia_chat_url(base_url):
    return base_url.rstrip("/") + "/chat/completions"


def extract_json_text(content):
    content = content.strip()

    if content.startswith("{") and content.endswith("}"):
        return content

    fenced = re.search(
        r"```(?:json)?\s*(\{.*?\})\s*```",
        content,
        flags=re.DOTALL | re.IGNORECASE,
    )

    if fenced:
        return fenced.group(1)

    start = content.find("{")
    end = content.rfind("}")

    if start != -1 and end != -1 and start < end:
        return content[start:end + 1]

    raise ValueError("LLM response did not contain a JSON object.")

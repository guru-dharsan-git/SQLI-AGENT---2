import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DEFAULT_TARGETS_FILE = "sqli_targets.json"
DEFAULT_RESULTS_FILE = "agent_results.json"
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_PAYLOADS = 6
MAX_RESPONSE_CHARS = 1600
LOCAL_HOSTS = {"localhost", "127.0.0.1"}
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NVIDIA_MODEL = "meta/llama-3.1-8b-instruct"
DEFAULT_MAX_OUTPUT_TOKENS = 2048
DEFAULT_LLM_REQUEST_TIMEOUT = 120
DEFAULT_LLM_RETRIES = 1


def load_project_env(file_name=".env"):
    env_path = Path(__file__).resolve().parents[1] / file_name

    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key or key in os.environ:
            continue

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        os.environ[key] = value


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    request_timeout: int = DEFAULT_LLM_REQUEST_TIMEOUT
    retries: int = DEFAULT_LLM_RETRIES

    @classmethod
    def from_env(cls):
        load_project_env()

        provider = os.getenv("LLM_PROVIDER", "").strip().lower()
        nvidia_key = (
            os.getenv("NVIDIA_API_KEY")
            or os.getenv("NVIDIA_INFERENCE_API_KEY")
            or os.getenv("NIM_API_KEY")
        )
        gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        temperature = float(os.getenv("LLM_TEMPERATURE", "0.2"))
        max_tokens = int(os.getenv("LLM_MAX_TOKENS", str(DEFAULT_MAX_OUTPUT_TOKENS)))
        request_timeout = int(os.getenv("LLM_REQUEST_TIMEOUT", str(DEFAULT_LLM_REQUEST_TIMEOUT)))
        retries = int(os.getenv("LLM_RETRIES", str(DEFAULT_LLM_RETRIES)))

        if not provider:
            provider = "nvidia" if nvidia_key else "gemini"

        if provider == "nvidia":
            if not nvidia_key:
                raise RuntimeError(
                    "Set NVIDIA_API_KEY before running the NVIDIA LLM phase."
                )

            return cls(
                provider="nvidia",
                model=(
                    os.getenv("NVIDIA_MODEL")
                    or os.getenv("LLM_MODEL")
                    or DEFAULT_NVIDIA_MODEL
                ),
                api_key=nvidia_key,
                base_url=(
                    os.getenv("NVIDIA_BASE_URL")
                    or os.getenv("LLM_BASE_URL")
                    or DEFAULT_NVIDIA_BASE_URL
                ),
                temperature=temperature,
                max_tokens=max_tokens,
                request_timeout=request_timeout,
                retries=retries,
            )

        if provider != "gemini":
            raise RuntimeError(
                f"Unsupported LLM_PROVIDER '{provider}'. Use 'nvidia' or 'gemini'."
            )

        if not gemini_key:
            raise RuntimeError(
                "Set GEMINI_API_KEY before running the LLM SQLi phase."
            )

        return cls(
            provider="gemini",
            model=os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
            api_key=gemini_key,
            temperature=temperature,
            max_tokens=max_tokens,
            request_timeout=request_timeout,
            retries=retries,
        )

"""Configure the local OpenAI-compatible model served by LM Studio."""

from __future__ import annotations

import importlib.util
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from langchain_core.language_models import BaseChatModel


DEFAULT_BASE_URL = "http://127.0.0.1:1234/v1"
DEFAULT_MODEL = "qwen/qwen3.6-35b-a3b"
DEFAULT_API_KEY = "lm-studio"
DEFAULT_TIMEOUT = 180
DEFAULT_MAX_TOKENS = 8192
DEFAULT_REASONING_EFFORT = "none"
DEFAULT_PLANNER_TIMEOUT = 300
DEFAULT_PLANNER_MAX_TOKENS = 16384
DEFAULT_PLANNER_REASONING_EFFORT = "medium"
DEFAULT_REPORTER_TIMEOUT = 180
DEFAULT_REPORTER_MAX_TOKENS = 8192
DEFAULT_REPORTER_REASONING_EFFORT = "none"
DEFAULT_ANALYSIS_SECONDS = 600


@dataclass(frozen=True)
class LMStudioConfig:
    """Connection details for one LM Studio chat model."""

    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    api_key: str = DEFAULT_API_KEY
    timeout: int = DEFAULT_TIMEOUT
    max_tokens: int = DEFAULT_MAX_TOKENS
    reasoning_effort: str = DEFAULT_REASONING_EFFORT

    def __post_init__(self) -> None:
        if not self.base_url.strip():
            raise ValueError("LM Studio base URL cannot be empty")
        if not self.model.strip():
            raise ValueError("LM Studio model cannot be empty")
        if self.timeout <= 0 or self.max_tokens <= 0:
            raise ValueError("LM Studio timeout and token limit must be positive")
        if not self.reasoning_effort.strip():
            raise ValueError("LM Studio reasoning effort cannot be empty")

    @property
    def models_url(self) -> str:
        return self.base_url.rstrip("/") + "/models"


def load_dotenv(path: Path) -> None:
    """Load simple KEY=VALUE lines without overriding the process environment."""

    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def config_from_env() -> LMStudioConfig:
    """Build LM Studio configuration from environment variables."""

    return LMStudioConfig(
        base_url=os.environ.get("LMSTUDIO_BASE_URL", DEFAULT_BASE_URL),
        model=os.environ.get("LMSTUDIO_MODEL", DEFAULT_MODEL),
        api_key=os.environ.get("LMSTUDIO_API_KEY", DEFAULT_API_KEY),
        timeout=int(os.environ.get("LMSTUDIO_TIMEOUT", DEFAULT_TIMEOUT)),
        max_tokens=int(os.environ.get("LMSTUDIO_MAX_TOKENS", DEFAULT_MAX_TOKENS)),
        reasoning_effort=os.environ.get(
            "LMSTUDIO_REASONING_EFFORT", DEFAULT_REASONING_EFFORT
        ),
    )


def role_config(config: LMStudioConfig, role: str) -> LMStudioConfig:
    """Return role-specific limits while retaining one local model endpoint."""

    if role == "planner":
        prefix = "LMSTUDIO_PLANNER"
        timeout = DEFAULT_PLANNER_TIMEOUT
        max_tokens = DEFAULT_PLANNER_MAX_TOKENS
        reasoning_effort = DEFAULT_PLANNER_REASONING_EFFORT
    elif role == "reporter":
        prefix = "LMSTUDIO_REPORTER"
        timeout = DEFAULT_REPORTER_TIMEOUT
        max_tokens = DEFAULT_REPORTER_MAX_TOKENS
        reasoning_effort = DEFAULT_REPORTER_REASONING_EFFORT
    else:
        raise ValueError("LM Studio role must be planner or reporter")
    return replace(
        config,
        timeout=int(os.environ.get(f"{prefix}_TIMEOUT", timeout)),
        max_tokens=int(os.environ.get(f"{prefix}_MAX_TOKENS", max_tokens)),
        reasoning_effort=os.environ.get(
            f"{prefix}_REASONING_EFFORT", reasoning_effort
        ),
    )


def analysis_seconds_from_env() -> int:
    """Return the total wall-clock budget for sandbox analysis."""

    value = int(os.environ.get("ONEMAIL_ANALYSIS_TIMEOUT", DEFAULT_ANALYSIS_SECONDS))
    if value <= 0:
        raise ValueError("analysis timeout must be positive")
    return value


def create_chat_model(
    config: LMStudioConfig,
    *,
    timeout: int | None = None,
    max_tokens: int | None = None,
) -> BaseChatModel:
    """Create the LangChain client for LM Studio's local API."""

    from langchain_openai import ChatOpenAI

    return ChatOpenAI(
        model=config.model,
        base_url=config.base_url,
        api_key=config.api_key,
        temperature=0,
        timeout=timeout or config.timeout,
        max_retries=2,
        max_tokens=max_tokens or config.max_tokens,
        reasoning_effort=config.reasoning_effort,
    )


def model_status(
    config: LMStudioConfig,
    *,
    timeout: float = 4,
) -> Tuple[bool, str]:
    """Check that LM Studio is reachable and the configured model is available."""

    if importlib.util.find_spec("langchain_openai") is None:
        return False, "langchain-openai is not installed. Install the project: pip install -e ."

    headers = {"Accept": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    try:
        with urlopen(Request(config.models_url, headers=headers), timeout=timeout) as response:
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        return (
            False,
            f"LM Studio is not reachable at {config.base_url} "
            f"({type(error).__name__}). Start its local server and retry.",
        )

    models = {
        str(item.get("id"))
        for item in payload.get("data", [])
        if isinstance(item, dict) and item.get("id")
    } if isinstance(payload, dict) else set()
    if config.model not in models:
        available = ", ".join(sorted(models)) or "none"
        return (
            False,
            f"LM Studio model '{config.model}' is unavailable. Available models: {available}",
        )
    return True, f"LM Studio ready (model: {config.model})."

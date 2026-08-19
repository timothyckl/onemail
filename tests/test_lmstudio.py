"""Tests for local LM Studio configuration and readiness checks."""

import io
import json
import unittest
from unittest.mock import patch
from urllib.error import URLError

from agentic.lmstudio import (
    LMStudioConfig,
    create_chat_model,
    model_status,
    role_config,
)


class LMStudioTests(unittest.TestCase):
    def test_chat_client_uses_native_reasoning_off_mode(self) -> None:
        config = LMStudioConfig(model="local/test-model")
        sentinel = object()
        with patch("langchain_openai.ChatOpenAI", return_value=sentinel) as chat:
            result = create_chat_model(config)

        self.assertIs(result, sentinel)
        self.assertEqual(chat.call_args.kwargs["reasoning_effort"], "none")
        self.assertEqual(chat.call_args.kwargs["base_url"], config.base_url)

    def test_planner_enables_reasoning_without_enabling_it_for_reports(self) -> None:
        config = LMStudioConfig(model="local/test-model")

        with patch.dict("os.environ", {}, clear=True):
            planner = role_config(config, "planner")
            reporter = role_config(config, "reporter")

        self.assertEqual(planner.reasoning_effort, "medium")
        self.assertGreater(planner.max_tokens, reporter.max_tokens)
        self.assertEqual(reporter.reasoning_effort, "none")

    def test_status_accepts_the_configured_available_model(self) -> None:
        config = LMStudioConfig(model="local/test-model")
        response = io.BytesIO(
            json.dumps({"data": [{"id": "local/test-model"}]}).encode("utf-8")
        )

        with patch("agentic.lmstudio.urlopen", return_value=response) as request:
            ready, detail = model_status(config)

        self.assertTrue(ready)
        self.assertIn("local/test-model", detail)
        self.assertEqual(request.call_args.args[0].full_url, config.models_url)

    def test_status_rejects_an_unavailable_model(self) -> None:
        config = LMStudioConfig(model="missing-model")
        response = io.BytesIO(
            json.dumps({"data": [{"id": "loaded-model"}]}).encode("utf-8")
        )

        with patch("agentic.lmstudio.urlopen", return_value=response):
            ready, detail = model_status(config)

        self.assertFalse(ready)
        self.assertIn("loaded-model", detail)

    def test_status_explains_when_the_local_server_is_down(self) -> None:
        config = LMStudioConfig()
        with patch(
            "agentic.lmstudio.urlopen",
            side_effect=URLError("connection refused"),
        ):
            ready, detail = model_status(config)

        self.assertFalse(ready)
        self.assertIn(config.base_url, detail)
        self.assertIn("Start its local server", detail)


if __name__ == "__main__":
    unittest.main()

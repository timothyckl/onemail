"""Provider-neutral structured model invocation with bounded JSON retries."""

import json
import time
from typing import Any, Generic, Literal, Optional, Type, TypeVar

from langchain_core.language_models import BaseChatModel
from pydantic import BaseModel, ValidationError

from .timeout import Gate


Output = TypeVar("Output", bound=BaseModel)
OutputMethod = Literal["function_calling", "json_mode", "json_schema"]


class StructuredOutput(Generic[Output]):
    """Invoke and validate one schema, retrying JSON parsing once."""

    def __init__(
        self,
        model: BaseChatModel,
        schema: Type[Output],
        method: Optional[OutputMethod] = None,
    ) -> None:
        options: dict[str, object] = {}
        if method is not None:
            options["method"] = method
        self._json_mode = method == "json_mode"
        if self._json_mode:
            options["include_raw"] = True
        self._runner = model.with_structured_output(schema, **options)
        self._schema = schema
        self._gate = Gate()

    def invoke(
        self,
        messages: list[dict[str, str]],
        timeout: float,
        label: str,
    ) -> Output:
        deadline = time.monotonic() + timeout
        attempts = 2 if self._json_mode else 1
        parsing_error: Optional[BaseException] = None
        current = list(messages)

        for attempt in range(attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{label} exceeded its timeout")
            result = self._gate.invoke(lambda: self._runner.invoke(current), remaining)
            try:
                return self._parse(result)
            except _StructuredOutputError as error:
                parsing_error = error.__cause__ or error
                if attempt + 1 < attempts:
                    current = current + [
                        {
                            "role": "user",
                            "content": (
                                "The previous response was empty or invalid. Return only "
                                "one complete JSON object matching the supplied schema."
                            ),
                        }
                    ]

        suffix = " after retry" if attempts > 1 else ""
        raise ValueError(f"{label} returned no valid structured output{suffix}") from parsing_error

    def _parse(self, result: object) -> Output:
        if self._json_mode and isinstance(result, dict) and (
            "parsed" in result or "parsing_error" in result
        ):
            error = result.get("parsing_error")
            if isinstance(error, BaseException):
                raise _StructuredOutputError from error
            result = result.get("parsed")
        if result is None:
            raise _StructuredOutputError("model returned empty structured output")
        if isinstance(result, self._schema):
            return result
        try:
            return self._schema.model_validate(result)
        except (TypeError, ValidationError) as error:
            raise _StructuredOutputError from error


class _StructuredOutputError(ValueError):
    pass


def json_instructions(schema: Type[BaseModel], example: dict[str, Any]) -> str:
    """Describe the required JSON shape for providers whose JSON mode needs a prompt."""

    return (
        " Return only one complete JSON object matching this JSON schema: "
        + json.dumps(schema.model_json_schema(), sort_keys=True)
        + " Example JSON output: "
        + json.dumps(example, sort_keys=True)
    )

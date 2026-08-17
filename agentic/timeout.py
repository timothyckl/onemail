"""Bound blocking model calls without trusting provider-specific timeout support."""

import queue
import threading
from typing import Callable, TypeVar


T = TypeVar("T")


class Gate:
    """Allow at most one in-flight call, including a call that already timed out."""

    def __init__(self) -> None:
        self._available = threading.BoundedSemaphore(1)

    def invoke(self, call: Callable[[], T], seconds: float) -> T:
        if not self._available.acquire(timeout=seconds):
            raise TimeoutError("a previous model invocation is still running")
        results: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def run() -> None:
            try:
                results.put((True, call()))
            except BaseException as error:
                results.put((False, error))
            finally:
                self._available.release()

        threading.Thread(target=run, daemon=True).start()
        try:
            succeeded, value = results.get(timeout=seconds)
        except queue.Empty as error:
            raise TimeoutError("model invocation exceeded its timeout") from error
        if succeeded:
            return value  # type: ignore[return-value]
        raise value  # type: ignore[misc]


def invoke(call: Callable[[], T], seconds: float) -> T:
    """Bound a standalone blocking call."""

    return Gate().invoke(call, seconds)

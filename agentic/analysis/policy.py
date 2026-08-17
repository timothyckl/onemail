"""Deterministically validate tasks proposed by the analysis agent."""

from typing import Iterable, Optional, Set, Tuple

from .models import Analysis, Gap, Limits, Plan, Task
from .tools import TOOLS


class Policy:
    """Permit only bounded, typed, format-appropriate static analysis."""

    def approve(
        self,
        plan: Plan,
        analysis: Analysis,
        completed: Iterable[Tuple[str, str]],
        limits: Limits,
    ) -> Tuple[Tuple[Task, ...], Tuple[Gap, ...]]:
        artifacts = {artifact.id: artifact for artifact in analysis.artifacts}
        seen: Set[Tuple[str, str]] = set(completed)
        approved = []
        rejected = []

        for task in plan.tasks:
            key = (task.name, task.artifact)
            tool = TOOLS.get(task.name)
            reason = None
            if tool is None:
                reason = "task is not allowlisted"
            elif task.artifact not in artifacts:
                reason = "artifact does not exist"
            elif key in seen:
                reason = "task already completed"
            elif len(approved) >= limits.tasks:
                reason = "task limit reached"
            elif set(task.options) - set(tool.options):
                reason = "task contains unsupported options"
            elif tool.formats and not self._applies(
                artifacts[task.artifact].format.detected,
                artifacts[task.artifact].format.extension,
                tool.formats,
            ):
                reason = "task does not apply to the detected format"

            if reason is not None:
                rejected.append(Gap(scope=f"{task.name}:{task.artifact}", reason=reason))
                continue
            approved.append(task)
            seen.add(key)

        return tuple(approved), tuple(rejected)

    @staticmethod
    def _applies(
        detected: str,
        extension: Optional[str],
        formats: Tuple[str, ...],
    ) -> bool:
        text = f"{detected} {extension or ''}".lower()
        return any(item in text for item in formats)

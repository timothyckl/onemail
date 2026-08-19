"""Deterministically validate tasks proposed by the analysis agent."""

from typing import Iterable, Optional, Set, Tuple

from .models import Analysis, Gap, Limits, Plan, Task
from .tools import TOOLS


class Policy:
    """Permit only bounded, typed, format-appropriate investigation tasks."""

    def approve(
        self,
        plan: Plan,
        analysis: Analysis,
        completed: Iterable[Tuple[str, str]],
        limits: Limits,
        available: Optional[Set[str]] = None,
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
            elif available is not None and task.name not in available:
                reason = "task is not available in this environment"
            elif task.artifact not in artifacts:
                reason = "artifact does not exist"
            elif key in seen:
                reason = "task already completed"
            elif len(approved) >= limits.tasks:
                reason = "task limit reached"
            elif set(task.options) - {option.name for option in tool.options}:
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
            option_specs = {option.name: option for option in tool.options}
            valid_options = {
                name: value
                for name, value in task.options.items()
                if option_specs[name].accepts(value)
            }
            invalid_options = sorted(set(task.options) - set(valid_options))
            if invalid_options:
                rejected.append(
                    Gap(
                        scope=f"{task.name}:{task.artifact}",
                        reason=(
                            "invalid option value ignored; bounded default used for "
                            + ", ".join(invalid_options)
                        ),
                    )
                )
            approved.append(
                Task(
                    name=task.name,
                    artifact=task.artifact,
                    options=valid_options,
                    rationale=task.rationale,
                )
            )
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

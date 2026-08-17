"""Orchestrate deterministic and adaptive static analysis for one case."""

import hashlib
import time
from dataclasses import asdict, is_dataclass, replace
from enum import Enum
from typing import Callable, Dict, Set, Tuple

from detection.data_models import FiredResult

from agentic import Case

from .agent import Agent
from .models import (
    Analysis,
    Artifact,
    Batch,
    Evidence,
    Gap,
    Limits,
    Observation,
    Trace,
)
from .policy import Policy
from .sandbox import Sandbox
from .tools import TOOLS


class Analyzer:
    """Run baseline analysis, then bounded agent-selected tasks."""

    def __init__(
        self,
        sandbox: Callable[[Case, Limits], Sandbox],
        agent: Agent,
        policy: Policy = Policy(),
        limits: Limits = Limits(),
    ) -> None:
        self._sandbox = sandbox
        self._agent = agent
        self._policy = policy
        self._limits = limits

    def analyze(self, case: Case) -> Analysis:
        if len(case.email.content) > self._limits.email_bytes:
            raise ValueError("email exceeds analysis size limit")

        detection_evidence, detection_observations = self._detection_evidence(case)
        analysis = Analysis(
            detection=case.detection,
            artifacts=(),
            traces=(),
            evidence=detection_evidence,
            observations=detection_observations,
            gaps=(),
            failures=(),
            image=None,
        )
        deadline = time.monotonic() + self._limits.seconds

        with self._sandbox(case, self._limits) as sandbox:
            analysis = self._merge(analysis, sandbox.baseline())
            analysis = self._reconcile(case, analysis)
            completed: Set[Tuple[str, str]] = {
                (trace.task, trace.artifact) for trace in analysis.traces
            }
            remaining_tasks = self._limits.tasks

            for round_index in range(self._limits.rounds):
                remaining_seconds = int(deadline - time.monotonic())
                if remaining_tasks <= 0 or remaining_seconds <= 0:
                    if remaining_seconds <= 0:
                        analysis = replace(
                            analysis,
                            gaps=analysis.gaps
                            + (Gap(scope="agent", reason="analysis deadline reached"),),
                        )
                    break
                round_limits = replace(
                    self._limits,
                    rounds=self._limits.rounds - round_index,
                    tasks=remaining_tasks,
                    seconds=remaining_seconds,
                )
                plan = self._agent.plan(analysis, tuple(TOOLS.values()), round_limits)
                if time.monotonic() >= deadline:
                    analysis = replace(
                        analysis,
                        gaps=analysis.gaps
                        + (Gap(scope="agent", reason="analysis deadline reached"),),
                    )
                    break
                approved, rejected = self._policy.approve(
                    plan,
                    analysis,
                    completed,
                    round_limits,
                )
                analysis = replace(
                    analysis,
                    gaps=analysis.gaps
                    + tuple(Gap(scope="agent", reason=gap) for gap in plan.gaps)
                    + rejected,
                )
                if plan.stop or not approved:
                    break
                for task in approved:
                    analysis = self._merge(analysis, sandbox.execute(task))
                    completed.add((task.name, task.artifact))
                    remaining_tasks -= 1

        return analysis

    @staticmethod
    def _reconcile(case: Case, analysis: Analysis) -> Analysis:
        available: Dict[str, list[Artifact]] = {}
        for artifact in analysis.artifacts:
            if artifact.id != "email":
                available.setdefault(artifact.name, []).append(artifact)

        traces = []
        evidence = []
        observations = []
        gaps = []
        for expected in case.detection.observables.attachments:
            matches = available.get(expected.name, [])
            if not matches:
                gaps.append(
                    Gap(
                        scope=f"attachment:{expected.name or 'unnamed'}",
                        reason="detection attachment was not extracted in the sandbox",
                    )
                )
                continue
            artifact = matches.pop(0)
            if expected.sha256 is None:
                gaps.append(
                    Gap(
                        scope=f"attachment:{artifact.id}",
                        reason="detection hash unavailable for reconciliation",
                    )
                )
                continue
            matched = expected.sha256 == artifact.sha256 and expected.size == artifact.size
            trace_id = _id("trace", "reconcile", artifact.id)
            evidence_id = _id("evidence", "reconcile", artifact.id)
            traces.append(
                Trace(
                    id=trace_id,
                    task="reconcile",
                    artifact=artifact.id,
                    tool="Analyzer",
                    version="1",
                    status="success",
                    duration_ms=0,
                    exit_code=0,
                )
            )
            evidence.append(
                Evidence(
                    id=evidence_id,
                    origin="analysis",
                    kind="reconciliation",
                    value={
                        "matched": matched,
                        "detection_sha256": expected.sha256,
                        "analysis_sha256": artifact.sha256,
                        "detection_size": expected.size,
                        "analysis_size": artifact.size,
                    },
                    artifact=artifact.id,
                    trace=trace_id,
                )
            )
            observations.append(
                Observation(
                    id=_id("observation", "reconcile", artifact.id),
                    summary=(
                        "Sandbox attachment matches detection metadata"
                        if matched
                        else "Sandbox attachment differs from detection metadata"
                    ),
                    evidence=(evidence_id,),
                )
            )
        return Analysis(
            detection=analysis.detection,
            artifacts=analysis.artifacts,
            traces=analysis.traces + tuple(traces),
            evidence=analysis.evidence + tuple(evidence),
            observations=analysis.observations + tuple(observations),
            gaps=analysis.gaps + tuple(gaps),
            failures=analysis.failures,
            image=analysis.image,
        )

    @staticmethod
    def _merge(analysis: Analysis, batch: Batch) -> Analysis:
        artifacts: Dict[str, Artifact] = {item.id: item for item in analysis.artifacts}
        artifacts.update({item.id: item for item in batch.artifacts})
        return Analysis(
            detection=analysis.detection,
            artifacts=tuple(artifacts.values()),
            traces=analysis.traces + batch.traces,
            evidence=analysis.evidence + batch.evidence,
            observations=analysis.observations + batch.observations,
            gaps=analysis.gaps + batch.gaps,
            failures=analysis.failures + batch.failures,
            image=batch.image or analysis.image,
        )

    @staticmethod
    def _detection_evidence(
        case: Case,
    ) -> Tuple[Tuple[Evidence, ...], Tuple[Observation, ...]]:
        evidence = []
        observations = []
        for result in case.detection.detector_results:
            if not isinstance(result, FiredResult):
                continue
            finding = result.finding
            identifier = _id("detection", finding.detector.value)
            evidence.append(
                Evidence(
                    id=identifier,
                    origin="detection",
                    kind=finding.detector.value,
                    value={
                        "clause": finding.clause,
                        "severity": finding.severity.value,
                        "heuristic": finding.heuristic,
                        "evidence": _json_value(finding.evidence),
                    },
                )
            )
            observations.append(
                Observation(
                    id=_id("observation", identifier),
                    summary=finding.clause,
                    evidence=(identifier,),
                )
            )
        return tuple(evidence), tuple(observations)


def _id(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:16]


def _json_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {
            key: _json_value(item)
            for key, item in asdict(value).items()  # type: ignore[arg-type]
        }
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value

"""Tests for agentic analysis boundaries and intelligence grounding."""

import tempfile
import unittest
import time
from dataclasses import replace
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Optional, cast

from agentic import Case
from agentic.analysis import (
    Agent,
    Analysis,
    Analyzer,
    Artifact,
    Batch,
    DockerSandbox,
    Evidence,
    Format,
    LangChainAgent,
    Limits,
    Metrics,
    Observation,
    Plan,
    Policy,
    Preview,
    Sandbox,
    SQLiteCorrelator,
    Task,
    Trace,
)
from agentic.intelligence import Renderer, Reporter
from agentic.progress import ProgressTracker
from agentic.timeout import invoke
from detection import Detection, DetectionEngine, Email


def flagged_email(attachment: bool = False) -> tuple[Email, Detection]:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.net"
    message["Reply-To"] = "reply@evil.example"
    message["Subject"] = "Review"
    message.set_content("Review this message")
    if attachment:
        message.add_attachment(
            b"MZ\x00\x00",
            maintype="application",
            subtype="octet-stream",
            filename="invoice.exe",
        )
    email = Email(file="message.eml", content=message.as_bytes())
    return email, DetectionEngine().detect(email)


def artifact(name: str = "message.eml", identifier: str = "email") -> Artifact:
    return Artifact(
        id=identifier,
        name=name,
        size=4,
        sha256="0" * 64,
        format=Format(detected="message/rfc822", extension="eml"),
        metrics=Metrics(entropy=1.0, printable_ratio=0.5),
        preview=Preview(head="00", tail="00"),
    )


class RecordingAgent(Agent):
    def __init__(self) -> None:
        self.tools = ()

    def plan(self, analysis, tools, limits):
        self.tools = tuple(tool.name for tool in tools)
        return Plan(stop=True)


class FixedAgent(Agent):
    def __init__(self, plans: tuple[Plan, ...]) -> None:
        self._plans = iter(plans)

    def plan(self, analysis, tools, limits):
        return next(self._plans, Plan(stop=True))


class FakeSandbox(Sandbox):
    def __init__(
        self,
        baseline: Batch,
        tasks: Optional[dict[str, Batch]] = None,
    ) -> None:
        self._baseline = baseline
        self._tasks = tasks or {}
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.closed = True

    def baseline(self):
        return self._baseline

    def execute(self, task):
        return self._tasks.get(task.name, Batch())


class StructuredModel:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls = 0
        self.options: dict[str, object] = {}
        self.messages: list[list[dict[str, str]]] = []

    def with_structured_output(self, schema, **options):
        self.schema = schema
        self.options = options
        return self

    def invoke(self, messages):
        self.calls += 1
        self.messages.append(list(messages))
        if isinstance(self.response, tuple):
            return self.response[min(self.calls - 1, len(self.response) - 1)]
        return self.response


class CaseTests(unittest.TestCase):
    def test_requires_a_flagged_matching_detection(self) -> None:
        email, detection = flagged_email()

        case = Case(email=email, detection=detection)

        self.assertEqual(case.email, email)
        clear_email = Email(file="clear.eml", content=b"From: a@example.com\n\nHello")
        clear = DetectionEngine().detect(clear_email)
        with self.assertRaises(ValueError):
            Case(email=clear_email, detection=clear)
        with self.assertRaises(ValueError):
            Case(email=Email(file="other.eml", content=email.content), detection=detection)
        with self.assertRaises(ValueError):
            Case(email=Email(file=email.file, content=b"different"), detection=detection)


class AnalysisTests(unittest.TestCase):
    def test_normalizes_all_detection_findings_generically(self) -> None:
        email, detection = flagged_email(attachment=True)
        attachment_hash = detection.observables.attachments[0].sha256
        assert attachment_hash is not None
        attachment_artifact = Artifact(
            id="a001",
            name="invoice.exe",
            size=4,
            sha256=attachment_hash,
            format=Format(detected="application/x-dosexec", extension="exe"),
        )
        sandbox = FakeSandbox(Batch(artifacts=(artifact(), attachment_artifact)))
        analyzer = Analyzer(lambda case, limits: sandbox, FixedAgent((Plan(stop=True),)))

        analysis = analyzer.analyze(Case(email=email, detection=detection))

        detection_kinds = {
            item.kind for item in analysis.evidence if item.origin == "detection"
        }
        self.assertEqual(
            detection_kinds,
            {finding.detector.value for finding in detection.findings},
        )
        self.assertTrue(
            any(item.kind == "reconciliation" for item in analysis.evidence)
        )
        self.assertTrue(sandbox.closed)

    def test_agent_can_run_only_policy_approved_tasks(self) -> None:
        email, detection = flagged_email()
        sandbox = FakeSandbox(Batch(artifacts=(artifact(),)))
        plans = (
            Plan(
                tasks=(
                    Task(name="metadata", artifact="email"),
                    Task(name="shell", artifact="email"),
                )
            ),
            Plan(stop=True),
        )
        analyzer = Analyzer(lambda case, limits: sandbox, FixedAgent(plans))

        analysis = analyzer.analyze(Case(email=email, detection=detection))

        self.assertTrue(any(gap.scope == "shell:email" for gap in analysis.gaps))

    def test_virustotal_tool_is_only_offered_when_configured(self) -> None:
        email, detection = flagged_email()
        sandbox = FakeSandbox(Batch(artifacts=(artifact(),)))
        disabled = RecordingAgent()
        Analyzer(lambda case, limits: sandbox, disabled).analyze(
            Case(email=email, detection=detection)
        )

        sandbox = FakeSandbox(Batch(artifacts=(artifact(),)))
        enabled = RecordingAgent()
        virustotal = type("VirusTotal", (), {"lookup": lambda self, item: Batch()})()
        Analyzer(
            lambda case, limits: sandbox,
            enabled,
            virustotal=virustotal,
        ).analyze(Case(email=email, detection=detection))

        self.assertNotIn("virustotal_hash", disabled.tools)
        self.assertIn("virustotal_hash", enabled.tools)

    def test_routes_virustotal_tasks_to_the_host_broker(self) -> None:
        email, detection = flagged_email()
        sandbox = FakeSandbox(Batch(artifacts=(artifact(),)))
        plans = (
            Plan(tasks=(Task("virustotal_hash", "email"),), stop=True),
        )
        calls = []

        class VirusTotal:
            def lookup(self, item):
                calls.append(item.id)
                trace = Trace(
                    id="vt-trace",
                    task="virustotal_hash",
                    artifact=item.id,
                    tool="VirusTotal API v3",
                    version="v3",
                    status="success",
                    duration_ms=1,
                )
                evidence = Evidence(
                    id="vt-evidence",
                    origin="analysis",
                    kind="virustotal",
                    value={"sha256": item.sha256, "file_uploaded_by_onemail": False},
                    artifact=item.id,
                    trace=trace.id,
                )
                return Batch(traces=(trace,), evidence=(evidence,))

        events = []
        analysis = Analyzer(
            lambda case, limits: sandbox,
            FixedAgent(plans),
            virustotal=VirusTotal(),
            progress=ProgressTracker(events.append),
        ).analyze(Case(email=email, detection=detection))

        self.assertEqual(calls, ["email"])
        self.assertTrue(any(item.kind == "virustotal" for item in analysis.evidence))
        self.assertTrue(
            any(
                event.stage == "enrichment"
                and event.action == "Check existing VirusTotal file report"
                and event.status == "completed"
                for event in events
            )
        )

    def test_policy_rejects_inapplicable_and_unknown_tasks(self) -> None:
        email, detection = flagged_email()
        analysis = Analysis(
            detection=detection,
            artifacts=(artifact(),),
            traces=(),
            evidence=(),
            observations=(),
            gaps=(),
            failures=(),
            image=None,
        )
        plan = Plan(
            tasks=(
                Task(name="office", artifact="email"),
                Task(name="unknown", artifact="email"),
            )
        )

        approved, rejected = Policy().approve(plan, analysis, (), Limits())

        self.assertEqual(approved, ())
        self.assertEqual(len(rejected), 2)

    def test_policy_rejects_invalid_typed_option_values(self) -> None:
        email, detection = flagged_email()
        html_artifact = replace(
            artifact(),
            name="body.html",
            format=Format(detected="text/html", extension="html"),
        )
        analysis = Analysis(
            detection=detection,
            artifacts=(html_artifact,),
            traces=(),
            evidence=(),
            observations=(),
            gaps=(),
            failures=(),
            image=None,
        )

        approved, rejected = Policy().approve(
            Plan(tasks=(Task("render", "email", {"pages": "999"}),)),
            analysis,
            (),
            Limits(),
        )

        self.assertEqual(len(approved), 1)
        self.assertEqual(approved[0].options, {})
        self.assertIn("bounded default", rejected[0].reason)

    def test_langchain_agent_returns_typed_tasks_from_an_injected_model(self) -> None:
        _, detection = flagged_email()
        analysis = Analysis(
            detection=detection,
            artifacts=(artifact(),),
            traces=(),
            evidence=(),
            observations=(),
            gaps=(),
            failures=(),
            image=None,
        )
        model = StructuredModel(
            {
                "tasks": [
                    {
                        "name": "metadata",
                        "artifact": "email",
                        "rationale": "Collect available metadata.",
                    }
                ],
                "gaps": [],
                "stop": False,
            }
        )

        plan = LangChainAgent(model).plan(analysis, (), Limits())

        self.assertEqual(plan.tasks[0].name, "metadata")
        self.assertEqual(plan.tasks[0].artifact, "email")

    def test_json_agent_retries_an_empty_structured_response(self) -> None:
        _, detection = flagged_email()
        analysis = Analysis(
            detection=detection,
            artifacts=(artifact(),),
            traces=(),
            evidence=(),
            observations=(),
            gaps=(),
            failures=(),
            image=None,
        )
        plan = {
            "tasks": [],
            "gaps": [],
            "stop": True,
        }
        model = StructuredModel(
            (
                {"raw": object(), "parsed": None, "parsing_error": None},
                {"raw": object(), "parsed": plan, "parsing_error": None},
            )
        )

        result = LangChainAgent(
            model,
            structured_output_method="json_mode",
        ).plan(analysis, (), Limits())

        self.assertTrue(result.stop)
        self.assertEqual(model.calls, 2)
        self.assertEqual(model.options, {"method": "json_mode", "include_raw": True})
        self.assertIn("Example JSON output", model.messages[0][0]["content"])
        self.assertIn("previous response", model.messages[1][-1]["content"])


class DockerTests(unittest.TestCase):
    def test_applies_required_container_restrictions_and_cleanup(self) -> None:
        email, detection = flagged_email()
        container = _Container()
        client = _Client(container)
        sandbox = DockerSandbox(Case(email=email, detection=detection), Limits(), client=client)

        with sandbox:
            source = next(iter(client.containers.options["volumes"]))
            self.assertEqual(Path(source).read_bytes(), email.content)

        options = client.containers.options
        self.assertTrue(options["network_disabled"])
        self.assertTrue(options["read_only"])
        self.assertFalse(options["auto_remove"])
        self.assertEqual(options["user"], "analyst")
        self.assertEqual(options["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges", options["security_opt"])
        self.assertEqual(next(iter(options["volumes"].values()))["mode"], "ro")
        self.assertFalse(Path(source).exists())
        self.assertTrue(container.killed)
        self.assertTrue(container.removed)

    def test_cleans_up_input_when_container_start_fails(self) -> None:
        email, detection = flagged_email()
        container = _Container()
        client = _Client(container, run_error=OSError("start failed"))
        sandbox = DockerSandbox(
            Case(email=email, detection=detection),
            Limits(),
            client=client,
        )

        with self.assertRaises(OSError):
            sandbox.__enter__()

        source = next(iter(client.containers.options["volumes"]))
        self.assertFalse(Path(source).exists())


class IntelligenceTests(unittest.TestCase):
    def test_builds_grounded_json_and_deterministic_markdown(self) -> None:
        analysis = self._analysis()
        model = StructuredModel(self._draft("ev1"))

        report = Reporter(model, name="placeholder-model").report(analysis)
        first = Renderer().render(report)
        second = Renderer().render(report)

        self.assertEqual(first, second)
        self.assertIn("Investigation Overview", first)
        self.assertIn("Detection signals", first)
        self.assertIn("Grounded analysis observations", first)
        self.assertIn("Diamond Model", first)
        self.assertIn("MITRE ATT&CK", first)
        self.assertIn("Cyber Kill Chain", first)
        self.assertIn("<details>", first)
        self.assertEqual(report.model, "placeholder-model")
        self.assertEqual(report.detection[0].detector, "reply_to_divergence")
        self.assertEqual(report.detection[0].severity, "medium")
        self.assertNotIn("verdict", report.model_dump())
        self.assertIsInstance(report.model_dump_json(), str)

        injected = report.model_copy(update={"file": "<img src=https://invalid.example/x>"})
        rendered = Renderer().render(injected)
        self.assertNotIn("<img", rendered)
        self.assertIn("&lt;img", rendered)

    def test_prunes_unsupported_optional_enrichments_after_retry(self) -> None:
        analysis = self._analysis()
        model = StructuredModel(self._draft("invented"))

        report = Reporter(model, name="placeholder-model").report(analysis)

        self.assertEqual(model.calls, 2)
        self.assertEqual(report.indicators, ())
        self.assertEqual(report.diamond.infrastructure, ())
        self.assertEqual(report.attack.mappings, ())
        self.assertEqual(report.chain.mappings, ())

    def test_does_not_turn_virustotal_provider_metadata_into_an_ioc(self) -> None:
        analysis = self._analysis()
        vt_trace = Trace(
            id="vt-trace",
            task="virustotal_hash",
            artifact="email",
            tool="VirusTotal API v3",
            version="v3",
            status="success",
            duration_ms=1,
        )
        vt_evidence = Evidence(
            id="vt-evidence",
            origin="analysis",
            kind="virustotal",
            value={
                "sha256": "0" * 64,
                "permalink": "https://www.virustotal.com/gui/file/" + "0" * 64,
            },
            artifact="email",
            trace=vt_trace.id,
        )
        analysis = replace(
            analysis,
            traces=(vt_trace,),
            evidence=analysis.evidence + (vt_evidence,),
        )
        draft = self._draft("ev1")
        provider_url = "https://www.virustotal.com/gui/file/" + "0" * 64
        draft["indicators"] = [
            {"type": "url", "value": provider_url, "evidence": ["vt-evidence"]}
        ]
        draft["diamond"] = {
            "adversary": [],
            "infrastructure": [
                {
                    "value": provider_url,
                    "confidence": "medium",
                    "evidence": ["vt-evidence"],
                }
            ],
            "capability": [],
            "victim": [],
        }

        report = Reporter(StructuredModel(draft), name="placeholder-model").report(
            analysis
        )

        self.assertEqual(report.indicators, ())
        self.assertEqual(report.diamond.infrastructure, ())

    def test_rejects_an_unknown_claim_reference_after_retry(self) -> None:
        analysis = self._analysis()
        draft = self._draft("ev1")
        claims = cast(list[dict[str, Any]], draft["claims"])
        claims[0]["observation"] = "invented"
        model = StructuredModel(draft)

        with self.assertRaises(ValueError):
            Reporter(model, name="placeholder-model").report(analysis)

        self.assertEqual(model.calls, 2)

    def test_prunes_semantically_unsupported_attack_mapping(self) -> None:
        analysis = self._analysis()
        draft = self._draft("ev1")
        attack = cast(dict[str, Any], draft["attack"])
        mappings = cast(list[dict[str, Any]], attack["mappings"])
        mappings[0]["id"] = "T1027"
        model = StructuredModel(draft)

        report = Reporter(model, name="placeholder-model").report(analysis)

        self.assertEqual(report.attack.mappings, ())

    def test_json_reporter_retries_a_parsing_error(self) -> None:
        analysis = self._analysis()
        model = StructuredModel(
            (
                {
                    "raw": object(),
                    "parsed": None,
                    "parsing_error": ValueError("invalid JSON"),
                },
                {
                    "raw": object(),
                    "parsed": self._draft("ev1"),
                    "parsing_error": None,
                },
            )
        )

        report = Reporter(
            model,
            name="placeholder-model",
            structured_output_method="json_mode",
        ).report(analysis)

        self.assertEqual(report.model, "placeholder-model")
        self.assertEqual(model.calls, 2)
        self.assertIn("JSON schema", model.messages[0][0]["content"])

    def test_json_reporter_explains_repeated_empty_output(self) -> None:
        analysis = self._analysis()
        empty = {"raw": object(), "parsed": None, "parsing_error": None}
        model = StructuredModel((empty, empty))

        with self.assertRaisesRegex(
            ValueError,
            "intelligence draft returned no valid structured output after retry",
        ):
            Reporter(
                model,
                name="placeholder-model",
                structured_output_method="json_mode",
            ).report(analysis)

        self.assertEqual(model.calls, 2)

    @staticmethod
    def _analysis() -> Analysis:
        _, detection = flagged_email()
        return Analysis(
            detection=detection,
            artifacts=(artifact(),),
            traces=(),
            evidence=(
                Evidence(
                    id="ev1",
                    origin="detection",
                    kind="reply_to_divergence",
                    value={"domain": "evil.example"},
                ),
            ),
            observations=(
                Observation(
                    id="ob1",
                    summary="Reply-To differs from sender",
                    evidence=("ev1",),
                ),
            ),
            gaps=(),
            failures=(),
            image="test-image",
        )

    @staticmethod
    def _draft(evidence: str) -> dict[str, object]:
        return {
            "claims": [
                {
                    "observation": "ob1",
                    "confidence": "high",
                }
            ],
            "indicators": [
                {"type": "domain", "value": "evil.example", "evidence": [evidence]}
            ],
            "diamond": {
                "infrastructure": [
                    {"value": "evil.example", "confidence": "high", "evidence": [evidence]}
                ]
            },
            "attack": {
                "mappings": [
                    {
                        "id": "T1566",
                        "confidence": "medium",
                        "evidence": [evidence],
                    }
                ],
            },
            "chain": {
                "mappings": [
                    {
                        "id": "Delivery",
                        "confidence": "medium",
                        "evidence": [evidence],
                    }
                ]
            },
        }


class _Container:
    def __init__(self) -> None:
        self.killed = False
        self.removed = False

    def kill(self):
        self.killed = True

    def wait(self, timeout):
        return {"StatusCode": 137}

    def remove(self, force):
        self.removed = True


class _Image:
    id = "sha256:" + "1" * 64


class _Images:
    def get(self, image):
        return _Image()


class _Containers:
    def __init__(self, container, run_error=None) -> None:
        self.container = container
        self.run_error = run_error
        self.options = {}

    def run(self, image, **options):
        self.options = options
        if self.run_error is not None:
            raise self.run_error
        return self.container


class _Client:
    def __init__(self, container, run_error=None) -> None:
        self.containers = _Containers(container, run_error)
        self.images = _Images()


class CorrelationTests(unittest.TestCase):
    def test_correlates_normalised_artifacts_without_storing_message_bytes(self) -> None:
        first = IntelligenceTests._analysis()
        second = replace(
            first,
            detection=replace(
                first.detection,
                file="second.eml",
                sha256="1" * 64,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            correlator = SQLiteCorrelator(Path(directory) / "correlation.sqlite3")
            initial = correlator.correlate(first)
            matched = correlator.correlate(second)

        self.assertIn("no relationships", initial.observations[0].summary)
        value = matched.evidence[0].value
        self.assertIsInstance(value, dict)
        assert isinstance(value, dict)
        self.assertTrue(value["exact_artifact_matches"])
        self.assertFalse(value["raw_message_stored"])


    def test_correlates_near_duplicate_similarity_hashes(self) -> None:
        first = IntelligenceTests._analysis()
        first = replace(
            first,
            artifacts=(replace(first.artifacts[0], similarity_hash="a" * 16),),
        )
        second = replace(
            first,
            detection=replace(first.detection, file="second.eml", sha256="1" * 64),
            artifacts=(
                replace(
                    first.artifacts[0],
                    sha256="2" * 64,
                    similarity_hash="a" * 16,
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            correlator = SQLiteCorrelator(Path(directory) / "correlation.sqlite3")
            correlator.correlate(first)
            matched = correlator.correlate(second)

        value = matched.evidence[0].value
        self.assertIsInstance(value, dict)
        assert isinstance(value, dict)
        self.assertTrue(value["similar_artifact_matches"])


class ProgressTests(unittest.TestCase):
    def test_records_step_and_total_durations(self) -> None:
        now = [10.0]
        events = []
        progress = ProgressTracker(events.append, clock=lambda: now[0])

        step = progress.start(
            "container",
            "Inspect archive",
            artifact="sample.zip",
            tool="7z",
            actor="agent",
            kind="tool",
            rationale="The archive may contain additional evidence.",
            command="7z l sample.zip",
        )
        now[0] += 1.25
        progress.finish(
            step,
            "container",
            "Inspect archive",
            artifact="sample.zip",
            tool="7z",
            actor="agent",
            kind="tool",
            rationale="The archive may contain additional evidence.",
            command="7z l sample.zip",
            output="file.exe",
            exit_code=0,
        )

        self.assertEqual([event.status for event in events], ["running", "completed"])
        self.assertEqual(events[1].duration_ms, 1250)
        self.assertEqual(events[1].total_elapsed_ms, 1250)
        self.assertEqual(events[1].step_id, events[0].step_id)
        self.assertEqual(events[1].actor, "agent")
        self.assertEqual(events[1].kind, "tool")
        self.assertEqual(events[1].command, "7z l sample.zip")
        self.assertEqual(events[1].output, "file.exe")
        self.assertEqual(events[1].exit_code, 0)


class TimeoutTests(unittest.TestCase):
    def test_bounds_a_blocking_call(self) -> None:
        with self.assertRaises(TimeoutError):
            invoke(lambda: time.sleep(0.05), 0.001)


if __name__ == "__main__":
    unittest.main()

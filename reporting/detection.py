"""Report completed detections and verify that findings match observables."""

import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

from detection.data_models import (
    AuthFailureEvidence,
    AuthFailureFinding,
    BecNoPayloadEvidence,
    BecNoPayloadFinding,
    CredentialUrlEvidence,
    CredentialUrlFinding,
    DetectorName,
    DetectorStatus,
    DisplayNameSpoofEvidence,
    DisplayNameSpoofFinding,
    DmarcResult,
    Finding,
    FiredResult,
    Detection,
    ReplyToDivergenceEvidence,
    ReplyToDivergenceFinding,
    Severity,
    SpfResult,
)
from detection.detectors.detectors import CREDENTIAL_LANGUAGE, URGENCY_LANGUAGE
from detection.detectors.extra_detectors import EXTRA_DETECTORS


@dataclass(frozen=True)
class ValidationIssue:
    """One finding value that could not be grounded in parsed observables."""

    file: str
    detector: DetectorName
    message: str


@dataclass(frozen=True)
class DetectionRecord:
    """A labelled detection or a file that could not be read."""

    file: str
    label: str
    detection: Optional[Detection] = None
    read_error: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.file:
            raise ValueError("detection record requires a file name")
        if not self.label:
            raise ValueError("detection record requires a label")
        if (self.detection is None) == (self.read_error is None):
            raise ValueError("detection record requires a detection or read error")
        if self.detection is not None and self.detection.file != self.file:
            raise ValueError("record and detection file names differ")

    @classmethod
    def detected(cls, label: str, detection: Detection) -> "DetectionRecord":
        """Create a record for a completed detection."""

        return cls(file=detection.file, label=label, detection=detection)

    @classmethod
    def unreadable(cls, file: str, label: str, error: Exception) -> "DetectionRecord":
        """Create a record for an email that could not be read."""

        return cls(file=file, label=label, read_error=type(error).__name__)


@dataclass(frozen=True)
class DetectionReport:
    """An immutable report built after all detection work has completed."""

    records: Tuple[DetectionRecord, ...]
    validation_issues: Tuple[ValidationIssue, ...]

    @classmethod
    def build(cls, records: Iterable[DetectionRecord]) -> "DetectionReport":
        """Build a report and automatically validate every emitted finding."""

        ordered_records = tuple(records)
        validator = _FindingValidator()
        issues = tuple(
            issue
            for record in ordered_records
            if record.detection is not None
            for issue in validator.validate(record.detection)
        )
        return cls(records=ordered_records, validation_issues=issues)

    @property
    def discovered_count(self) -> int:
        return len(self.records)

    @property
    def processed_count(self) -> int:
        return sum(record.detection is not None for record in self.records)

    @property
    def unreadable_count(self) -> int:
        return sum(record.read_error is not None for record in self.records)

    @property
    def parse_failure_count(self) -> int:
        return sum(
            record.detection is not None
            and record.detection.observables.parse_error is not None
            for record in self.records
        )

    @property
    def flagged_count(self) -> int:
        return sum(
            record.detection is not None and record.detection.flagged
            for record in self.records
        )

    @property
    def unflagged_count(self) -> int:
        return self.processed_count - self.flagged_count

    @property
    def positive_detection_rate(self) -> float:
        if not self.processed_count:
            return 0.0
        return self.flagged_count / self.processed_count

    @property
    def validation_passed(self) -> bool:
        return not self.validation_issues

    def summary(self) -> str:
        """Return a concise human-readable corpus summary."""

        return "\n".join(
            (
                f"Emails discovered: {self.discovered_count}",
                f"Emails processed: {self.processed_count}",
                f"Unreadable emails: {self.unreadable_count}",
                f"Parse failures: {self.parse_failure_count}",
                f"Flagged phishing emails: {self.flagged_count}",
                f"Unflagged phishing emails: {self.unflagged_count}",
                f"Positive detection rate: {self.positive_detection_rate:.2%}",
                f"Finding validation issues: {len(self.validation_issues)}",
            )
        )

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-compatible report with stable ordering."""

        issues_by_file: Dict[str, List[ValidationIssue]] = {}
        for issue in self.validation_issues:
            issues_by_file.setdefault(issue.file, []).append(issue)

        return {
            "summary": {
                "discovered": self.discovered_count,
                "processed": self.processed_count,
                "unreadable": self.unreadable_count,
                "parse_failures": self.parse_failure_count,
                "flagged_phishing": self.flagged_count,
                "unflagged_phishing": self.unflagged_count,
                "positive_detection_rate": self.positive_detection_rate,
                "validation_issues": len(self.validation_issues),
                "detectors": self._detector_counts(),
            },
            "emails": [
                self._record_dict(record, issues_by_file.get(record.file, []))
                for record in self.records
            ],
        }

    def write_json(self, path: Union[str, Path]) -> None:
        """Write the complete report as deterministic JSON."""

        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _detector_counts(self) -> Dict[str, Dict[str, int]]:
        counts = {
            detector.value: {status.value: 0 for status in DetectorStatus}
            for detector in DetectorName
        }
        for record in self.records:
            if record.detection is None:
                continue
            for result in record.detection.detector_results:
                counts[result.detector.value][result.status.value] += 1
        return counts

    @staticmethod
    def _record_dict(
        record: DetectionRecord,
        issues: List[ValidationIssue],
    ) -> Dict[str, object]:
        item: Dict[str, object] = {
            "file": record.file,
            "label": record.label,
            "read_error": record.read_error,
            "validation_issues": [_json_value(issue) for issue in issues],
        }
        if record.detection is None:
            item["detection"] = None
            return item

        item["detection"] = {
            "flagged": record.detection.flagged,
            "parse_error": record.detection.observables.parse_error,
            "results": [
                _json_value(result) for result in record.detection.detector_results
            ],
        }
        return item


class _FindingValidator:
    """Independently reconstruct expected findings from parsed observables."""

    def __init__(self) -> None:
        self._extra_detectors = {detector.name: detector for detector in EXTRA_DETECTORS}

    def validate(self, detection: Detection) -> Tuple[ValidationIssue, ...]:
        issues: List[ValidationIssue] = []
        for result in detection.detector_results:
            if not isinstance(result, FiredResult):
                continue
            finding = result.finding
            if not finding.clause.strip():
                self._add(issues, detection.file, result.detector, "clause is empty")
            if finding.detector is not result.detector:
                self._add(
                    issues,
                    detection.file,
                    result.detector,
                    "finding detector does not match its result",
                )

            if isinstance(finding, AuthFailureFinding):
                self._validate_auth_failure(detection, finding, issues)
            elif isinstance(finding, ReplyToDivergenceFinding):
                self._validate_reply_to(detection, finding, issues)
            elif isinstance(finding, CredentialUrlFinding):
                self._validate_credential_url(detection, finding, issues)
            elif isinstance(finding, DisplayNameSpoofFinding):
                self._validate_display_name(detection, finding, issues)
            elif isinstance(finding, BecNoPayloadFinding):
                self._validate_bec(detection, finding, issues)
            else:
                self._validate_extra_detector(detection, finding, issues)
        return tuple(issues)

    def _validate_auth_failure(
        self,
        detection: Detection,
        finding: AuthFailureFinding,
        issues: List[ValidationIssue],
    ) -> None:
        observables = detection.observables
        failed = []
        if observables.spf_result in (SpfResult.FAIL, SpfResult.SOFTFAIL):
            failed.append(f"spf={observables.spf_result.value}")
        if observables.dmarc_result is DmarcResult.FAIL:
            failed.append("dmarc=fail")
        expected_evidence = AuthFailureEvidence(
            spf_result=observables.spf_result,
            dmarc_result=observables.dmarc_result,
            from_domain=observables.from_domain,
        )
        expected_clause = "sender authentication failed: " + ", ".join(failed)
        self._expect(
            detection,
            finding,
            expected_evidence,
            expected_clause,
            Severity.MEDIUM,
            False,
            bool(failed),
            issues,
        )

    def _validate_reply_to(
        self,
        detection: Detection,
        finding: ReplyToDivergenceFinding,
        issues: List[ValidationIssue],
    ) -> None:
        observables = detection.observables
        expected_evidence = ReplyToDivergenceEvidence(
            from_domain=observables.from_domain,
            reply_to_domain=observables.reply_to_domain,
        )
        expected_clause = (
            f"Reply-To domain ({observables.reply_to_domain}) differs from From domain "
            f"({observables.from_domain})"
        )
        self._expect(
            detection,
            finding,
            expected_evidence,
            expected_clause,
            Severity.MEDIUM,
            False,
            observables.reply_to_differs is True,
            issues,
        )

    def _validate_credential_url(
        self,
        detection: Detection,
        finding: CredentialUrlFinding,
        issues: List[ValidationIssue],
    ) -> None:
        observables = detection.observables
        sender_domain = _registered_domain(observables.from_domain)
        hosts = tuple(
            host
            for host in observables.url_hosts
            if _registered_domain(host) != sender_domain
        )
        phrases = _matching_phrases(_message_text(detection), CREDENTIAL_LANGUAGE)
        expected_evidence = CredentialUrlEvidence(
            from_registered_domain=sender_domain,
            mismatched_hosts=hosts[:5],
            matched_language=phrases[:5],
        )
        self._expect(
            detection,
            finding,
            expected_evidence,
            "link to a domain unrelated to the sender, with credential-action language",
            Severity.HIGH,
            True,
            bool(hosts) and bool(phrases),
            issues,
        )

    def _validate_display_name(
        self,
        detection: Detection,
        finding: DisplayNameSpoofFinding,
        issues: List[ValidationIssue],
    ) -> None:
        observables = detection.observables
        brand = observables.display_name_brand or ""
        sender_domain = (observables.from_domain or "").lower()
        expected_evidence = DisplayNameSpoofEvidence(
            display_name=observables.display_name,
            brand=brand,
            from_domain=sender_domain,
        )
        expected_clause = (
            f"display name claims '{brand}' but sender domain "
            f"({sender_domain}) is unrelated"
        )
        self._expect(
            detection,
            finding,
            expected_evidence,
            expected_clause,
            Severity.HIGH,
            False,
            bool(brand) and brand not in sender_domain,
            issues,
        )

    def _validate_bec(
        self,
        detection: Detection,
        finding: BecNoPayloadFinding,
        issues: List[ValidationIssue],
    ) -> None:
        observables = detection.observables
        reply_to_differs = observables.reply_to_differs is True
        phrases = _matching_phrases(_message_text(detection), URGENCY_LANGUAGE)
        reasons = []
        if reply_to_differs:
            reasons.append(
                f"Reply-To ({observables.reply_to_domain}) differs from From "
                f"({observables.from_domain})"
            )
        if phrases:
            reasons.append("urgency / payment-request language")
        expected_evidence = BecNoPayloadEvidence(
            reply_to_differs=reply_to_differs,
            matched_language=phrases[:5],
            from_domain=observables.from_domain,
        )
        self._expect(
            detection,
            finding,
            expected_evidence,
            "no-payload message with " + " and ".join(reasons),
            Severity.HIGH,
            bool(phrases) and not reply_to_differs,
            not observables.url_count
            and not observables.attachment_count
            and (reply_to_differs or bool(phrases)),
            issues,
        )

    def _validate_extra_detector(
        self,
        detection: Detection,
        finding: Finding[object],
        issues: List[ValidationIssue],
    ) -> None:
        detector = self._extra_detectors.get(finding.detector)
        if detector is None:
            self._add(
                issues,
                detection.file,
                finding.detector,
                f"unsupported finding type: {type(finding).__name__}",
            )
            return

        expected_result = detector.detect(detection.observables)
        if not isinstance(expected_result, FiredResult):
            self._add(
                issues,
                detection.file,
                finding.detector,
                "detector firing predicate is not satisfied",
            )
            return
        if expected_result.finding != finding:
            self._add(
                issues,
                detection.file,
                finding.detector,
                "finding does not match grounded detector output",
            )

    def _expect(
        self,
        detection: Detection,
        finding: Finding[object],
        evidence: object,
        clause: str,
        severity: Severity,
        heuristic: bool,
        predicate: bool,
        issues: List[ValidationIssue],
    ) -> None:
        detector = finding.detector
        checks = (
            (
                isinstance(finding.evidence, type(evidence)),
                "evidence type does not match finding type",
            ),
            (finding.evidence == evidence, "evidence does not match observables"),
            (finding.clause == clause, "clause does not match grounded evidence"),
            (finding.severity is severity, "severity does not match finding type"),
            (finding.heuristic is heuristic, "heuristic flag does not match finding type"),
            (predicate, "detector firing predicate is not satisfied"),
        )
        for valid, message in checks:
            if not valid:
                self._add(issues, detection.file, detector, message)

    @staticmethod
    def _add(
        issues: List[ValidationIssue],
        file: str,
        detector: DetectorName,
        message: str,
    ) -> None:
        issues.append(ValidationIssue(file=file, detector=detector, message=message))


def _registered_domain(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    labels = host.strip().strip(".").lower().split(".")
    return ".".join(labels if len(labels) <= 2 else labels[-2:])


def _message_text(detection: Detection) -> str:
    observables = detection.observables
    return " ".join(
        part for part in (observables.subject, observables.body_text) if part
    ).lower()


def _matching_phrases(text: str, phrases: Tuple[str, ...]) -> Tuple[str, ...]:
    return tuple(phrase for phrase in phrases if phrase in text)


def _json_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value

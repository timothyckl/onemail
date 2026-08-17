"""Fixed static-analysis runner executed only inside the analysis image."""

import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from email import message_from_bytes, policy
from pathlib import Path


ROOT = Path("/work/artifacts")
MANIFEST = Path("/work/manifest.json")
RULES = Path("/opt/onemail/rules/base.yar")
CLAMAV = Path("/opt/onemail/signatures/clamav")
MAGIC = {
    b"MZ": "pe",
    b"%PDF": "pdf",
    b"PK\x03\x04": "archive",
    b"\xd0\xcf\x11\xe0": "office",
    b"\x7fELF": "elf",
    b"Rar!": "archive",
    b"7z\xbc\xaf\x27\x1c": "archive",
}


def main():
    if len(sys.argv) < 2:
        fail("runner requires a mode")
    mode = sys.argv[1]
    if mode == "baseline":
        email = Path(sys.argv[2])
        limits = json.loads(sys.argv[3])
        emit(baseline(email, limits))
    if mode == "task":
        name, artifact = sys.argv[2], sys.argv[3]
        options = json.loads(sys.argv[4])
        limits = json.loads(sys.argv[5])
        emit(task(name, artifact, options, limits))
    fail("unknown runner mode")


def baseline(email, limits):
    ROOT.mkdir(parents=True, exist_ok=True)
    artifacts, gaps, failures = extract(email, limits)
    extract_trace = trace("extract", "email", "python", "stdlib", 0, "")
    traces = [extract_trace]
    evidence = []
    observations = []
    extraction = evidence_item(
        "extract",
        "email",
        extract_trace["id"],
        {"artifacts": len(artifacts), "failures": len(failures)},
    )
    evidence.append(extraction)
    observations.append(
        observation(
            "extract",
            "email",
            f"Extracted {max(0, len(artifacts) - 1)} file payload(s) from the email",
            [extraction["id"]],
        )
    )

    for artifact in artifacts:
        path = ROOT / artifact["id"]
        profile, item_traces, item_evidence, item_observations, item_gaps = inspect(
            artifact,
            path,
            limits,
        )
        artifact.update(profile)
        traces.extend(item_traces)
        evidence.extend(item_evidence)
        observations.extend(item_observations)
        gaps.extend(item_gaps)

    MANIFEST.write_text(json.dumps({"artifacts": artifacts}, sort_keys=True))
    return batch(
        artifacts=artifacts,
        traces=traces,
        evidence=evidence,
        observations=observations,
        gaps=gaps,
        failures=failures,
    )


def extract(email, limits):
    raw = email.read_bytes()
    artifacts = []
    gaps = []
    failures = []
    total = len(raw)
    artifacts.append(write_artifact("email", safe_name(email.name), raw, "message/rfc822"))

    try:
        message = message_from_bytes(raw, policy=policy.default)
        index = 0
        for part in message.walk():
            if part.is_multipart():
                continue
            try:
                name = part.get_filename()
                disposition = part.get_content_disposition()
                declared = (part.get_content_type() or "application/octet-stream").lower()
                payload = part.get_payload(decode=True)
            except Exception as error:
                failures.append({"scope": "extract", "error": type(error).__name__})
                continue
            is_file = bool(name) or disposition == "attachment"
            if not is_file and declared.startswith("text/"):
                continue
            if not is_file and declared.startswith("image/") and disposition == "inline":
                continue
            if payload is None:
                continue
            if len(artifacts) - 1 >= limits["artifacts"]:
                gaps.append({"scope": "extract", "reason": "artifact limit reached"})
                break
            if len(payload) > limits["artifact_bytes"]:
                gaps.append({"scope": safe_name(name or declared), "reason": "artifact too large"})
                continue
            if total + len(payload) > limits["total_bytes"]:
                gaps.append({"scope": "extract", "reason": "decoded byte limit reached"})
                break
            index += 1
            identifier = f"a{index:03d}"
            artifacts.append(
                write_artifact(
                    identifier,
                    safe_name(name or f"part-{index}"),
                    payload,
                    declared,
                )
            )
            total += len(payload)
    except Exception as error:
        failures.append({"scope": "mime", "error": type(error).__name__})
    return artifacts, gaps, failures


def write_artifact(identifier, name, content, declared):
    path = ROOT / identifier
    path.write_bytes(content)
    return {
        "id": identifier,
        "name": name,
        "declared": declared,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def inspect(artifact, path, limits):
    content = path.read_bytes()
    detected, identify_trace = identify(artifact["id"], path, limits)
    extension = Path(artifact["name"]).suffix.lower().lstrip(".") or None
    magic = content[:16].hex()
    expected = next((kind for signature, kind in MAGIC.items() if content.startswith(signature)), None)
    mismatch = type_mismatch(expected, extension, artifact["declared"])
    metrics = {
        "entropy": round(entropy(content), 6),
        "printable_ratio": round(printable_ratio(content), 6),
    }
    preview = {"head": content[:64].hex(), "tail": content[-64:].hex()}
    traces = [identify_trace]
    evidence = []
    observations = []
    gaps = []

    profile_trace = trace("profile", artifact["id"], "python", "stdlib", 0, "")
    traces.append(profile_trace)
    values = {
        "sha256": artifact["sha256"],
        "size": artifact["size"],
        "detected": detected,
        "declared": artifact["declared"],
        "extension": extension,
        "mismatch": mismatch,
        **metrics,
    }
    profile_evidence = evidence_item("profile", artifact["id"], profile_trace["id"], values)
    evidence.append(profile_evidence)
    observations.append(
        observation(
            "profile",
            artifact["id"],
            f"{artifact['name']} identified as {detected}; SHA-256 {artifact['sha256']}",
            [profile_evidence["id"]],
        )
    )

    string_trace, string_output = command(
        "strings",
        artifact["id"],
        ["/usr/bin/strings", "-a", "-n", "6", str(path)],
        limits,
    )
    traces.append(string_trace)
    if string_trace["status"] == "success":
        lines = string_output.splitlines()
        item = evidence_item(
            "strings",
            artifact["id"],
            string_trace["id"],
            {"count": len(lines), "preview": lines[:20]},
        )
        evidence.append(item)

    matches = []
    if RULES.exists():
        yara_trace, yara_output = command(
            "yara",
            artifact["id"],
            ["/usr/bin/yara", str(RULES), str(path)],
            limits,
        )
        traces.append(yara_trace)
        if yara_trace["status"] == "success":
            for line in yara_output.splitlines():
                rule = line.split()[0] if line.split() else ""
                if rule and rule not in {"0x0:"}:
                    matches.append({"rule": rule, "namespace": "onemail", "tags": []})
            item = evidence_item(
                "yara",
                artifact["id"],
                yara_trace["id"],
                {
                    "matches": matches,
                    "rules_sha256": hashlib.sha256(RULES.read_bytes()).hexdigest(),
                },
            )
            evidence.append(item)
            if matches:
                observations.append(
                    observation(
                        "yara",
                        artifact["id"],
                        "YARA rule match: " + ", ".join(match["rule"] for match in matches),
                        [item["id"]],
                    )
                )

    databases = list(CLAMAV.glob("*.cvd")) + list(CLAMAV.glob("*.cld"))
    if databases:
        clam_trace, clam_output = command(
            "antivirus",
            artifact["id"],
            ["/usr/bin/clamscan", "--database", str(CLAMAV), "--no-summary", str(path)],
            limits,
            ok_codes=(0, 1),
        )
        traces.append(clam_trace)
        database_hashes = {
            item.name: hashlib.sha256(item.read_bytes()).hexdigest()
            for item in databases
        }
        item = evidence_item(
            "antivirus",
            artifact["id"],
            clam_trace["id"],
            {
                "result": clam_output.strip() or "no signature match",
                "databases": database_hashes,
            },
        )
        evidence.append(item)
        if "FOUND" in clam_output:
            observations.append(
                observation("antivirus", artifact["id"], clam_output.strip(), [item["id"]])
            )
    else:
        gaps.append({"scope": f"antivirus:{artifact['id']}", "reason": "ClamAV database unavailable"})

    return (
        {
            "format": {
                "magic": magic,
                "detected": detected,
                "declared": artifact["declared"],
                "extension": extension,
                "mismatch": mismatch,
            },
            "metrics": metrics,
            "preview": preview,
            "matches": matches,
        },
        traces,
        evidence,
        observations,
        gaps,
    )


def task(name, artifact_id, options, limits):
    manifest = json.loads(MANIFEST.read_text())
    artifacts = {item["id"]: item for item in manifest["artifacts"]}
    if artifact_id not in artifacts:
        fail("unknown artifact")
    artifact = artifacts[artifact_id]
    path = ROOT / artifact_id
    handlers = {
        "archive": archive,
        "office": office,
        "pdf": pdf,
        "pe": pe,
        "script": script,
        "embedded": embedded,
        "metadata": metadata,
    }
    if name not in handlers:
        fail("unknown task")
    return handlers[name](artifact, path, options, limits)


def archive(artifact, path, options, limits):
    item_trace, output = command(
        "archive", artifact["id"], ["/usr/bin/7z", "l", "-slt", str(path)], limits
    )
    return result_from_output(artifact, item_trace, "archive", output)


def office(artifact, path, options, limits):
    item_trace, output = command(
        "office", artifact["id"], ["/opt/venv/bin/olevba", "-a", str(path)], limits
    )
    return result_from_output(artifact, item_trace, "office", output)


def pdf(artifact, path, options, limits):
    started = time.monotonic()
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path), strict=False)
        value = {"pages": len(reader.pages), "encrypted": reader.is_encrypted}
        status, error = "success", ""
    except Exception as exc:
        value = {}
        status, error = "failure", type(exc).__name__
    item_trace = trace("pdf", artifact["id"], "pypdf", version("pypdf"), elapsed(started), error, status=status)
    return result_from_value(artifact, item_trace, "pdf", value)


def pe(artifact, path, options, limits):
    started = time.monotonic()
    try:
        import pefile

        parsed = pefile.PE(str(path), fast_load=True)
        value = {
            "machine": parsed.FILE_HEADER.Machine,
            "sections": [section.Name.rstrip(b"\0").decode("ascii", "replace") for section in parsed.sections[:20]],
        }
        status, error = "success", ""
    except Exception as exc:
        value = {}
        status, error = "failure", type(exc).__name__
    item_trace = trace("pe", artifact["id"], "pefile", version("pefile"), elapsed(started), error, status=status)
    return result_from_value(artifact, item_trace, "pe", value)


def script(artifact, path, options, limits):
    text = path.read_bytes()[:262144].decode("utf-8", "replace").lower()
    tokens = [
        token
        for token in ("powershell", "invoke-expression", "frombase64string", "wscript.shell", "cmd.exe")
        if token in text
    ]
    item_trace = trace("script", artifact["id"], "python", "stdlib", 0, "")
    return result_from_value(artifact, item_trace, "script", {"tokens": tokens})


def embedded(artifact, path, options, limits):
    content = path.read_bytes()
    found = []
    for signature, kind in MAGIC.items():
        offset = content.find(signature, 1)
        if offset >= 0:
            found.append({"type": kind, "offset": offset})
    item_trace = trace("embedded", artifact["id"], "python", "stdlib", 0, "")
    return result_from_value(artifact, item_trace, "embedded", found)


def metadata(artifact, path, options, limits):
    item_trace, output = command(
        "metadata", artifact["id"], ["/usr/bin/exiftool", "-j", str(path)], limits
    )
    return result_from_output(artifact, item_trace, "metadata", output)


def result_from_output(artifact, item_trace, kind, output):
    return result_from_value(artifact, item_trace, kind, output)


def result_from_value(artifact, item_trace, kind, value):
    failures = []
    evidence = []
    observations = []
    if item_trace["status"] == "success":
        item = evidence_item(kind, artifact["id"], item_trace["id"], value)
        evidence.append(item)
        observations.append(
            observation(kind, artifact["id"], f"{kind} analysis completed for {artifact['name']}", [item["id"]])
        )
    else:
        failures.append({"scope": f"{kind}:{artifact['id']}", "error": item_trace["stderr"] or "tool failed"})
    return batch(traces=[item_trace], evidence=evidence, observations=observations, failures=failures)


def identify(artifact, path, limits):
    item_trace, output = command(
        "identify", artifact, ["/usr/bin/file", "--brief", "--mime-type", str(path)], limits
    )
    return output.strip() or "unknown", item_trace


def command(task_name, artifact, argv, limits, ok_codes=(0,)):
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            timeout=min(30, limits["seconds"]),
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
        )
        stdout = completed.stdout.decode("utf-8", "replace")
        stderr = completed.stderr.decode("utf-8", "replace")
        status = "success" if completed.returncode in ok_codes else "failure"
        exit_code = completed.returncode
    except Exception as error:
        stdout, stderr = "", type(error).__name__
        status, exit_code = "failure", None
    limit = limits["output_bytes"]
    combined = stdout
    item_trace = trace(
        task_name,
        artifact,
        Path(argv[0]).name,
        tool_version(argv[0]),
        elapsed(started),
        stderr[:limit],
        status=status,
        exit_code=exit_code,
        stdout=stdout[:limit],
        truncated=len(stdout) > limit or len(stderr) > limit,
    )
    return item_trace, combined[:limit]


def trace(task_name, artifact, tool, tool_version_value, duration, stderr, status="success", exit_code=None, stdout="", truncated=False):
    identifier = stable("trace", task_name, artifact, str(time.monotonic_ns()))
    return {
        "id": identifier,
        "task": task_name,
        "artifact": artifact,
        "tool": tool,
        "version": tool_version_value,
        "status": status,
        "duration_ms": duration,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": truncated,
    }


def evidence_item(kind, artifact, trace_id, value):
    return {
        "id": stable("evidence", kind, artifact, json.dumps(value, sort_keys=True)),
        "origin": "analysis",
        "kind": kind,
        "value": value,
        "artifact": artifact,
        "trace": trace_id,
    }


def observation(kind, artifact, summary, evidence):
    return {
        "id": stable("observation", kind, artifact, *evidence),
        "summary": summary,
        "evidence": evidence,
    }


def batch(artifacts=None, traces=None, evidence=None, observations=None, gaps=None, failures=None):
    return {
        "artifacts": artifacts or [],
        "traces": traces or [],
        "evidence": evidence or [],
        "observations": observations or [],
        "gaps": gaps or [],
        "failures": failures or [],
        "image": "onemail-analysis:ubuntu-24.04",
    }


def entropy(content):
    if not content:
        return 0.0
    counts = [0] * 256
    for byte in content:
        counts[byte] += 1
    length = len(content)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def printable_ratio(content):
    if not content:
        return 0.0
    printable = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in content)
    return printable / len(content)


def type_mismatch(expected, extension, declared):
    if expected is None:
        return False
    extension_types = {
        "pe": {"exe", "dll", "scr", "msi"},
        "pdf": {"pdf"},
        "archive": {"zip", "7z", "rar", "tar", "docx", "xlsx", "pptx"},
        "office": {"doc", "xls", "ppt", "docm", "xlsm"},
    }
    declared_types = {
        "pe": ("executable", "dosexec", "msdownload"),
        "pdf": ("pdf",),
        "archive": ("zip", "compressed", "archive", "openxml", "officedocument"),
        "office": ("ole", "msword", "ms-excel", "ms-powerpoint", "officedocument"),
    }
    extension_mismatch = extension is not None and extension not in extension_types.get(expected, {extension})
    declared_text = (declared or "").lower()
    declared_mismatch = (
        bool(declared_text)
        and declared_text != "application/octet-stream"
        and not any(item in declared_text for item in declared_types.get(expected, (expected,)))
    )
    return bool(extension_mismatch or declared_mismatch)


def safe_name(name):
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", Path(name).name)[:200]
    return cleaned or "unnamed"


def stable(*parts):
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:16]


def elapsed(started):
    return int((time.monotonic() - started) * 1000)


def tool_version(executable):
    try:
        completed = subprocess.run(
            [executable, "--version"], capture_output=True, timeout=3, check=False
        )
        text = (completed.stdout or completed.stderr).decode("utf-8", "replace")
        return text.splitlines()[0][:120] if text else "unknown"
    except Exception:
        return "unknown"


def version(package):
    try:
        from importlib.metadata import version as package_version

        return package_version(package)
    except Exception:
        return "unknown"


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0)


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    main()

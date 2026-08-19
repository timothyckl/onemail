"""Fixed investigation runner executed only inside the isolated image."""

import base64
import binascii
import hashlib
import ipaddress
import json
import math
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from email import message_from_bytes, policy
from pathlib import Path


ROOT = Path("/work/artifacts")
MANIFEST = Path("/work/manifest.json")
RULES = Path("/opt/onemail/rules/base.yar")
EVENT_SEQUENCE = 0
ACTION_LABELS = {
    "extract": "Extract MIME payloads",
    "identify": "Identify file type",
    "profile": "Profile artifact",
    "strings": "Extract printable strings",
    "yara": "Scan with YARA",
    "archive": "Inspect archive contents",
    "office": "Inspect Office document",
    "pdf": "Inspect PDF structure",
    "pe": "Inspect Portable Executable",
    "script": "Inspect script content",
    "embedded": "Locate embedded files",
    "metadata": "Extract metadata",
    "decode": "Decode embedded content",
    "ioc": "Extract indicators",
    "render": "Render document safely",
    "emulate_pe": "Emulate Portable Executable",
    "emulate_script": "Symbolically emulate script",
    "archive_extract": "Extract bounded archive members",
}
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
    extraction_event, extraction_started = progress_start(
        "extract", "email", "python"
    )
    artifacts, gaps, failures = extract(email, limits)
    extraction_duration = elapsed(extraction_started)
    progress_finish(
        extraction_event,
        "extract",
        "email",
        "python",
        "completed" if not failures else "failed",
        extraction_duration,
        f"Discovered {max(0, len(artifacts) - 1)} file payload(s)",
    )
    extract_trace = trace(
        "extract", "email", "python", "stdlib", extraction_duration, ""
    )
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
            is_html_body = not is_file and declared == "text/html"
            if not is_file and declared.startswith("text/") and not is_html_body:
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
                    safe_name(name or (f"body-{index}.html" if is_html_body else f"part-{index}")),
                    payload,
                    declared,
                )
            )
            total += len(payload)
    except Exception as error:
        failures.append({"scope": "mime", "error": type(error).__name__})
    return artifacts, gaps, failures


def write_artifact(identifier, name, content, declared, parent=None, depth=0):
    path = ROOT / identifier
    path.write_bytes(content)
    return {
        "id": identifier,
        "name": name,
        "declared": declared,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "parent": parent,
        "depth": depth,
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
    similarity = similarity_hash(content)
    preview = {"head": content[:64].hex(), "tail": content[-64:].hex()}
    traces = [identify_trace]
    evidence = []
    observations = []
    gaps = []

    profile_event, profile_started = progress_start(
        "profile", artifact["name"], "python"
    )
    profile_duration = elapsed(profile_started)
    progress_finish(
        profile_event,
        "profile",
        artifact["name"],
        "python",
        "completed",
        profile_duration,
    )
    profile_trace = trace(
        "profile", artifact["id"], "python", "stdlib", profile_duration, ""
    )
    traces.append(profile_trace)
    values = {
        "sha256": artifact["sha256"],
        "size": artifact["size"],
        "detected": detected,
        "declared": artifact["declared"],
        "extension": extension,
        "mismatch": mismatch,
        "similarity_hash": similarity,
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
            "similarity_hash": similarity,
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
        "decode": decode,
        "ioc": ioc,
        "render": render,
        "emulate_pe": emulate_pe,
        "emulate_script": emulate_script,
    }
    if name not in handlers:
        fail("unknown task")
    return handlers[name](artifact, path, options, limits)


def archive(artifact, path, options, limits):
    list_trace, listing = command(
        "archive", artifact["id"], ["/usr/bin/7z", "l", "-slt", str(path)], limits
    )
    if list_trace["status"] != "success":
        return result_from_output(artifact, list_trace, "archive", listing)
    if int(artifact.get("depth", 0)) >= limits["archive_depth"]:
        return batch(
            traces=[list_trace],
            gaps=[{"scope": f"archive:{artifact['id']}", "reason": "archive depth limit reached"}],
        )

    destination = Path("/work/unpack") / artifact["id"]
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)
    extract_trace, _ = command(
        "archive_extract",
        artifact["id"],
        ["/usr/bin/7z", "x", "-y", f"-o{destination}", str(path)],
        limits,
    )
    if extract_trace["status"] != "success":
        return batch(
            traces=[list_trace, extract_trace],
            failures=[{"scope": f"archive:{artifact['id']}", "error": extract_trace["stderr"] or "archive extraction failed"}],
        )

    candidates = []
    expanded = 0
    gaps = []
    for candidate in sorted(destination.rglob("*")):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        relative = candidate.relative_to(destination).as_posix()
        size = candidate.stat().st_size
        if len(candidates) >= limits["archive_entries"]:
            gaps.append({"scope": f"archive:{artifact['id']}", "reason": "archive entry limit reached"})
            break
        if size > limits["artifact_bytes"]:
            gaps.append({"scope": relative, "reason": "archive member too large"})
            continue
        if expanded + size > limits["expanded_bytes"]:
            gaps.append({"scope": f"archive:{artifact['id']}", "reason": "expanded byte limit reached"})
            break
        candidates.append((relative, candidate.read_bytes()))
        expanded += size

    children = register_children(artifact, candidates, limits, "archive")
    value = {
        "listing": listing[: limits["output_bytes"]],
        "extracted": [item["id"] for item in children["artifacts"]],
        "expanded_bytes": expanded,
    }
    item = evidence_item("archive", artifact["id"], extract_trace["id"], value)
    return batch(
        artifacts=children["artifacts"],
        traces=[list_trace, extract_trace] + children["traces"],
        evidence=[item] + children["evidence"],
        observations=[
            observation(
                "archive",
                artifact["id"],
                f"Extracted {len(children['artifacts'])} bounded archive member(s) from {artifact['name']}",
                [item["id"]],
            )
        ] + children["observations"],
        gaps=gaps + children["gaps"],
    )


def office(artifact, path, options, limits):
    item_trace, output = command(
        "office", artifact["id"], ["/opt/venv/bin/olevba", "-a", str(path)], limits
    )
    relationships = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as package:
                for name in package.namelist()[: limits["archive_entries"]]:
                    if name.endswith(".rels"):
                        text = package.read(name)[:262144].decode("utf-8", "replace")
                        relationships.extend(
                            re.findall(r'Target=["\']([^"\']+)', text)[:50]
                        )
    except Exception:
        relationships = []
    value = {
        "macro_analysis": output,
        "relationships": relationships[:100],
        "external_relationships": [
            item for item in relationships if re.match(r"(?i)^(?:https?|ftp|file):", item)
        ][:50],
    }
    if item_trace["status"] != "success" and not relationships:
        return result_from_value(artifact, item_trace, "office", value)
    item_trace["status"] = "success"
    return result_from_value(artifact, item_trace, "office", value)


def pdf(artifact, path, options, limits):
    event_id, started = progress_start("pdf", artifact["name"], "pypdf")
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path), strict=False)
        markers = []
        uris = []
        if not reader.is_encrypted:
            root = reader.trailer.get("/Root", {})
            walk_pdf(root, markers, uris, set(), 0)
        value = {
            "pages": len(reader.pages),
            "encrypted": reader.is_encrypted,
            "structural_markers": sorted(set(markers))[:100],
            "uris": sorted(set(uris))[:100],
            "has_javascript": "/JavaScript" in markers or "/JS" in markers,
            "has_open_action": "/OpenAction" in markers,
            "has_embedded_files": "/EmbeddedFiles" in markers,
        }
        status, error = "success", ""
    except Exception as exc:
        value = {}
        status, error = "failure", type(exc).__name__
    duration = elapsed(started)
    progress_finish(event_id, "pdf", artifact["name"], "pypdf", status, duration, error)
    item_trace = trace(
        "pdf", artifact["id"], "pypdf", version("pypdf"), duration, error,
        status=status,
    )
    return result_from_value(artifact, item_trace, "pdf", value)


def pe(artifact, path, options, limits):
    event_id, started = progress_start("pe", artifact["name"], "pefile")
    try:
        import pefile

        parsed = pefile.PE(str(path), fast_load=False)
        imports = []
        for entry in getattr(parsed, "DIRECTORY_ENTRY_IMPORT", [])[:100]:
            library = entry.dll.decode("ascii", "replace") if entry.dll else ""
            names = []
            for imported in entry.imports[:100]:
                names.append(
                    imported.name.decode("ascii", "replace")
                    if imported.name else f"ordinal:{imported.ordinal}"
                )
            imports.append({"library": library, "symbols": names})
        sections = []
        for section in parsed.sections[:30]:
            sections.append(
                {
                    "name": section.Name.rstrip(b"\0").decode("ascii", "replace"),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(section.get_entropy(), 4),
                    "executable": bool(section.Characteristics & 0x20000000),
                    "writable": bool(section.Characteristics & 0x80000000),
                }
            )
        security = parsed.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        value = {
            "machine": parsed.FILE_HEADER.Machine,
            "timestamp": parsed.FILE_HEADER.TimeDateStamp,
            "entry_point": parsed.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": parsed.OPTIONAL_HEADER.ImageBase,
            "sections": sections,
            "imports": imports,
            "exports": [
                symbol.name.decode("ascii", "replace") if symbol.name else f"ordinal:{symbol.ordinal}"
                for symbol in getattr(getattr(parsed, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])[:100]
            ],
            "resource_entries": len(getattr(parsed, "DIRECTORY_ENTRY_RESOURCE", {}).entries)
            if hasattr(getattr(parsed, "DIRECTORY_ENTRY_RESOURCE", None), "entries") else 0,
            "has_authenticode": bool(security.VirtualAddress and security.Size),
            "high_entropy_sections": [item["name"] for item in sections if item["entropy"] >= 7.2],
            "write_execute_sections": [
                item["name"] for item in sections if item["writable"] and item["executable"]
            ],
        }
        status, error = "success", ""
    except Exception as exc:
        value = {}
        status, error = "failure", type(exc).__name__
    duration = elapsed(started)
    progress_finish(event_id, "pe", artifact["name"], "pefile", status, duration, error)
    item_trace = trace(
        "pe", artifact["id"], "pefile", version("pefile"), duration, error,
        status=status,
    )
    return result_from_value(artifact, item_trace, "pe", value)


def script(artifact, path, options, limits):
    event_id, started = progress_start("script", artifact["name"], "python")
    raw = path.read_bytes()[: min(limits["artifact_bytes"], 1048576)]
    text = decode_text(raw)
    lowered = text.lower()
    suspicious = (
        "powershell", "invoke-expression", "iex", "frombase64string",
        "wscript.shell", "cmd.exe", "mshta", "rundll32", "regsvr32",
        "downloadstring", "xmlhttp", "adodb.stream", "shell.application",
    )
    tokens = [token for token in suspicious if token in lowered]
    value = {
        "encoding": text_encoding(raw),
        "lines": min(text.count("\n") + 1, 1000000),
        "suspicious_tokens": tokens,
        "base64_candidates": len(re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text[:262144])),
        "longest_line": max((len(line) for line in text.splitlines()[:10000]), default=0),
    }
    duration = elapsed(started)
    progress_finish(event_id, "script", artifact["name"], "python", "completed", duration)
    item_trace = trace("script", artifact["id"], "python", "stdlib", duration, "")
    return result_from_value(artifact, item_trace, "script", value)


def embedded(artifact, path, options, limits):
    event_id, started = progress_start("embedded", artifact["name"], "python")
    content = path.read_bytes()[: limits["artifact_bytes"]]
    found = []
    candidates = []
    for signature, kind in MAGIC.items():
        offset = content.find(signature, 1)
        if offset >= 0:
            found.append({"type": kind, "offset": offset})
            candidates.append((f"embedded-{offset}.{extension_for(kind)}", content[offset:]))
    children = register_children(artifact, candidates, limits, "embedded")
    duration = elapsed(started)
    progress_finish(event_id, "embedded", artifact["name"], "python", "completed", duration)
    item_trace = trace("embedded", artifact["id"], "python", "stdlib", duration, "")
    item = evidence_item(
        "embedded", artifact["id"], item_trace["id"],
        {"signatures": found, "carved": [child["id"] for child in children["artifacts"]]},
    )
    return batch(
        artifacts=children["artifacts"],
        traces=[item_trace] + children["traces"],
        evidence=[item] + children["evidence"],
        observations=[
            observation(
                "embedded", artifact["id"],
                f"Located {len(found)} embedded file signature(s) in {artifact['name']}",
                [item["id"]],
            )
        ] + children["observations"],
        gaps=children["gaps"],
    )


def metadata(artifact, path, options, limits):
    item_trace, output = command(
        "metadata", artifact["id"], ["/usr/bin/exiftool", "-j", str(path)], limits
    )
    try:
        value = json.loads(output)
    except ValueError:
        value = output
    return result_from_value(artifact, item_trace, "metadata", value)


def decode(artifact, path, options, limits):
    event_id, started = progress_start("decode", artifact["name"], "python")
    raw = path.read_bytes()[: min(limits["artifact_bytes"], 1048576)]
    text = decode_text(raw)
    candidates = []
    seen = set()
    for index, match in enumerate(re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text[:524288])[:10]):
        try:
            value = base64.b64decode(match + "=" * (-len(match) % 4), validate=True)
        except (ValueError, binascii.Error):
            continue
        digest = hashlib.sha256(value).hexdigest()
        if value and len(value) <= limits["artifact_bytes"] and digest not in seen:
            candidates.append((f"decoded-base64-{index}.bin", value))
            seen.add(digest)
    for index, match in enumerate(re.findall(r"(?:[0-9A-Fa-f]{2}){32,}", text[:524288])[:10]):
        try:
            value = bytes.fromhex(match)
        except ValueError:
            continue
        digest = hashlib.sha256(value).hexdigest()
        if value and len(value) <= limits["artifact_bytes"] and digest not in seen:
            candidates.append((f"decoded-hex-{index}.bin", value))
            seen.add(digest)
    children = register_children(artifact, candidates[:5], limits, "decode")
    duration = elapsed(started)
    progress_finish(event_id, "decode", artifact["name"], "python", "completed", duration)
    item_trace = trace("decode", artifact["id"], "python", "stdlib", duration, "")
    item = evidence_item(
        "decode", artifact["id"], item_trace["id"],
        {"decoded": [child["id"] for child in children["artifacts"]]},
    )
    return batch(
        artifacts=children["artifacts"],
        traces=[item_trace] + children["traces"],
        evidence=[item] + children["evidence"],
        observations=[
            observation(
                "decode", artifact["id"],
                f"Recovered {len(children['artifacts'])} encoded child artifact(s) from {artifact['name']}",
                [item["id"]],
            )
        ] + children["observations"],
        gaps=children["gaps"],
    )


def ioc(artifact, path, options, limits):
    event_id, started = progress_start("ioc", artifact["name"], "python")
    text = decode_text(path.read_bytes()[: min(limits["artifact_bytes"], 1048576)])
    urls = sorted(set(re.findall(r"(?i)https?://[^\s<>\"']{3,500}", text)))[:100]
    emails = sorted(set(re.findall(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", text)))[:100]
    ips = []
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
        try:
            ips.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            pass
    domains = sorted(set(re.findall(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", text)))[:100]
    value = {
        "urls": urls,
        "domains": domains,
        "ip_addresses": sorted(set(ips))[:100],
        "email_addresses": emails,
    }
    duration = elapsed(started)
    progress_finish(event_id, "ioc", artifact["name"], "python", "completed", duration)
    item_trace = trace("ioc", artifact["id"], "python", "stdlib", duration, "")
    return result_from_value(artifact, item_trace, "ioc", value)


def emulate_script(artifact, path, options, limits):
    event_id, started = progress_start("emulate_script", artifact["name"], "python")
    text = decode_text(path.read_bytes()[: min(limits["artifact_bytes"], 1048576)])
    decoded = []
    for match in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text[:524288])[:10]:
        try:
            value = base64.b64decode(match + "=" * (-len(match) % 4), validate=True)
        except (ValueError, binascii.Error):
            continue
        preview = decode_text(value[:4096])
        if preview.strip():
            decoded.append(preview[:1000])
    commands = [
        line.strip()[:1000]
        for line in text.splitlines()[:10000]
        if re.search(r"(?i)(powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript)", line)
    ][:50]
    value = {
        "mode": "symbolic-only",
        "decoded_string_previews": decoded,
        "constructed_command_lines": commands,
        "native_execution": False,
    }
    duration = elapsed(started)
    progress_finish(event_id, "emulate_script", artifact["name"], "python", "completed", duration)
    item_trace = trace("emulate_script", artifact["id"], "python", "stdlib", duration, "")
    return result_from_value(artifact, item_trace, "emulate_script", value)


def render(artifact, path, options, limits):
    return render_document(artifact, path, options, limits)


def emulate_pe(artifact, path, options, limits):
    seconds = int(options.get("seconds", 10))
    destination = Path("/work/emulate") / artifact["id"]
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / safe_name(artifact["name"])
    shutil.copyfile(path, target)
    report_path = destination / "report.json"
    item_trace, output = command(
        "emulate_pe",
        artifact["id"],
        [
            "/opt/venv/bin/speakeasy", "-t", str(target), "-o", str(report_path),
            "--timeout", str(min(seconds, 30)),
            "--max-api-count", "2000",
            "--max-instructions", "5000000",
            "--no-analysis-memory-tracing",
            "--no-snapshot-memory-regions",
        ],
        limits,
    )
    try:
        report = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
        value = summarise_emulation(report)
    except (OSError, ValueError):
        value = {"summary": output[: limits["output_bytes"]], "native_execution": False}
    return result_from_value(artifact, item_trace, "emulate_pe", value)


def register_children(parent, candidates, limits, source):
    manifest = json.loads(MANIFEST.read_text())
    existing = {item["id"] for item in manifest["artifacts"]}
    total = sum(int(item.get("size", 0)) for item in manifest["artifacts"])
    artifacts = []
    traces = []
    evidence = []
    observations = []
    gaps = []
    parent_depth = int(parent.get("depth", 0))

    for name, content in candidates:
        if len(manifest["artifacts"]) - 1 >= limits["artifacts"]:
            gaps.append({"scope": source, "reason": "artifact limit reached"})
            break
        if not content or len(content) > limits["artifact_bytes"]:
            gaps.append({"scope": safe_name(name), "reason": "child artifact size limit reached"})
            continue
        if total + len(content) > limits["total_bytes"]:
            gaps.append({"scope": source, "reason": "decoded byte limit reached"})
            break
        identifier = "x" + stable(source, parent["id"], name, hashlib.sha256(content).hexdigest())[:14]
        if identifier in existing:
            continue
        declared = mimetypes.guess_type(name)[0] or "application/octet-stream"
        child = write_artifact(
            identifier,
            f"{parent['name']}!{safe_name(name)}",
            content,
            declared,
            parent=parent["id"],
            depth=parent_depth + 1,
        )
        profile, item_traces, item_evidence, item_observations, item_gaps = inspect(
            child, ROOT / identifier, limits
        )
        child.update(profile)
        manifest["artifacts"].append(child)
        artifacts.append(child)
        traces.extend(item_traces)
        evidence.extend(item_evidence)
        observations.extend(item_observations)
        gaps.extend(item_gaps)
        existing.add(identifier)
        total += len(content)

    MANIFEST.write_text(json.dumps(manifest, sort_keys=True))
    return {
        "artifacts": artifacts,
        "traces": traces,
        "evidence": evidence,
        "observations": observations,
        "gaps": gaps,
    }


def walk_pdf(value, markers, uris, seen, depth):
    if depth > 8 or len(seen) > 1000:
        return
    try:
        value = value.get_object()
    except Exception:
        pass
    identity = id(value)
    if identity in seen:
        return
    seen.add(identity)
    if isinstance(value, dict):
        for key, item in list(value.items())[:200]:
            name = str(key)
            if name in {"/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFiles", "/URI"}:
                markers.append(name)
            if name == "/URI":
                uris.append(str(item)[:1000])
            walk_pdf(item, markers, uris, seen, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value[:200]:
            walk_pdf(item, markers, uris, seen, depth + 1)


def render_document(artifact, path, options, limits):
    pages = min(max(int(options.get("pages", 3)), 1), 5)
    destination = Path("/work/render") / artifact["id"]
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)
    pdf_path = destination / "rendered.pdf"
    traces = []
    event_id, started = progress_start("render", artifact["name"], "renderer")
    detected = str(artifact.get("format", {}).get("detected", "")).lower()
    extension = Path(artifact["name"]).suffix.lower()
    error = ""

    try:
        if "html" in detected or extension in {".html", ".htm"}:
            from weasyprint import HTML, default_url_fetcher

            def offline_fetch(url, *args, **kwargs):
                if str(url).startswith("data:"):
                    return default_url_fetcher(url, *args, **kwargs)
                return {"string": b"", "mime_type": "application/octet-stream"}

            HTML(
                string=decode_text(path.read_bytes()[: limits["artifact_bytes"]]),
                url_fetcher=offline_fetch,
            ).write_pdf(pdf_path)
        elif "pdf" in detected or extension == ".pdf":
            shutil.copyfile(path, pdf_path)
        else:
            office_input = destination / safe_name(artifact["name"])
            shutil.copyfile(path, office_input)
            office_trace, _ = command(
                "render",
                artifact["id"],
                [
                    "/usr/bin/libreoffice", "--headless", "--nologo", "--nodefault",
                    "--nolockcheck", "--norestore", "--convert-to", "pdf",
                    "--outdir", str(destination), str(office_input),
                ],
                limits,
            )
            traces.append(office_trace)
            produced = [item for item in destination.glob("*.pdf") if item != pdf_path]
            if produced:
                produced[0].replace(pdf_path)
        if not pdf_path.is_file():
            raise ValueError("renderer did not produce a PDF")
    except Exception as exc:
        error = type(exc).__name__

    if error:
        duration = elapsed(started)
        progress_finish(event_id, "render", artifact["name"], "renderer", "failure", duration, error)
        item_trace = trace("render", artifact["id"], "renderer", "1", duration, error, status="failure")
        return batch(
            traces=traces + [item_trace],
            failures=[{"scope": f"render:{artifact['id']}", "error": error}],
        )

    text_trace, text = command(
        "render",
        artifact["id"],
        ["/usr/bin/pdftotext", "-f", "1", "-l", str(pages), str(pdf_path), "-"],
        limits,
    )
    image_prefix = destination / "page-1"
    image_trace, _ = command(
        "render",
        artifact["id"],
        [
            "/usr/bin/pdftoppm", "-f", "1", "-singlefile", "-png", "-r", "96",
            str(pdf_path), str(image_prefix),
        ],
        limits,
    )
    screenshot = image_prefix.with_suffix(".png")
    ocr = ""
    if screenshot.is_file():
        ocr_trace, ocr = command(
            "render",
            artifact["id"],
            ["/usr/bin/tesseract", str(screenshot), "stdout"],
            limits,
        )
        traces.append(ocr_trace)
    duration = elapsed(started)
    status = "success" if text_trace["status"] == "success" or screenshot.is_file() else "failure"
    progress_finish(event_id, "render", artifact["name"], "renderer", status, duration)
    item_trace = trace(
        "render", artifact["id"], "renderer", "1", duration, "" if status == "success" else "render output unavailable",
        status=status,
    )
    value = {
        "pages_requested": pages,
        "text_preview": text[:20000],
        "ocr_preview": ocr[:10000],
        "screenshot_sha256": hashlib.sha256(screenshot.read_bytes()).hexdigest()
        if screenshot.is_file() else None,
        "screenshot_bytes": screenshot.stat().st_size if screenshot.is_file() else 0,
        "external_resources_fetched": False,
    }
    all_traces = traces + [text_trace, image_trace, item_trace]
    if status != "success":
        return batch(
            traces=all_traces,
            failures=[{"scope": f"render:{artifact['id']}", "error": "render output unavailable"}],
        )
    item = evidence_item("render", artifact["id"], item_trace["id"], value)
    return batch(
        traces=all_traces,
        evidence=[item],
        observations=[
            observation(
                "render", artifact["id"],
                f"Rendered {artifact['name']} offline and extracted visual text",
                [item["id"]],
            )
        ],
    )


def summarise_emulation(report):
    api_calls = []
    network = []
    dropped = []

    def visit(value, depth=0):
        if depth > 10 or len(api_calls) >= 500:
            return
        if isinstance(value, dict):
            for key, item in list(value.items())[:500]:
                lowered = str(key).lower()
                if lowered in {"api_name", "api", "function"} and isinstance(item, str):
                    api_calls.append(item[:200])
                elif "network" in lowered or lowered in {"domain", "host", "url", "port"}:
                    network.append({str(key)[:80]: str(item)[:500]})
                elif "dropped" in lowered or lowered == "file_create":
                    dropped.append(str(item)[:500])
                visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:500]:
                visit(item, depth + 1)

    visit(report)
    return {
        "mode": "Speakeasy API emulation",
        "native_execution": False,
        "api_calls": api_calls[:500],
        "attempted_network_activity": network[:100],
        "dropped_file_records": dropped[:100],
        "top_level_keys": list(report)[:100] if isinstance(report, dict) else [],
    }


def decode_text(content):
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", "replace")


def text_encoding(content):
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    try:
        content.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        return "binary-or-legacy"


def extension_for(kind):
    return {
        "pe": "exe", "pdf": "pdf", "archive": "zip", "office": "doc",
        "elf": "elf",
    }.get(kind, "bin")


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
    event_id, started = progress_start(task_name, artifact, Path(argv[0]).name)
    try:
        runtime = Path("/work/runtime")
        home = runtime / "home"
        temporary = runtime / "tmp"
        home.mkdir(parents=True, exist_ok=True)
        temporary.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            timeout=min(30, limits["seconds"]),
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(home),
                "TMPDIR": str(temporary),
                "XDG_CACHE_HOME": str(runtime / "cache"),
                "XDG_CONFIG_HOME": str(runtime / "config"),
            },
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
    duration = elapsed(started)
    progress_finish(
        event_id,
        task_name,
        artifact,
        Path(argv[0]).name,
        status,
        duration,
        stderr[:500],
    )
    item_trace = trace(
        task_name,
        artifact,
        Path(argv[0]).name,
        tool_version(argv[0]),
        duration,
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


def similarity_hash(content):
    """Return a bounded 64-bit SimHash for local near-duplicate correlation."""

    sample = content[:1048576]
    text_tokens = re.findall(rb"[A-Za-z0-9_./:-]{4,}", sample.lower())[:10000]
    tokens = text_tokens or [sample[index:index + 64] for index in range(0, len(sample), 64)][:4096]
    if not tokens:
        return "0" * 16
    weights = [0] * 64
    for token in tokens:
        number = int.from_bytes(hashlib.sha256(token).digest()[:8], "big")
        for bit in range(64):
            weights[bit] += 1 if number & (1 << bit) else -1
    value = sum(1 << bit for bit, weight in enumerate(weights) if weight >= 0)
    return f"{value:016x}"


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


def progress_start(task_name, artifact, tool):
    global EVENT_SEQUENCE
    EVENT_SEQUENCE += 1
    identifier = f"runner-{EVENT_SEQUENCE:04d}"
    print(
        json.dumps(
            {
                "type": "event",
                "id": identifier,
                "action": ACTION_LABELS.get(task_name, task_name),
                "artifact": safe_name(str(artifact)),
                "tool": str(tool)[:80],
                "status": "running",
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )
    return identifier, time.monotonic()


def progress_finish(
    identifier,
    task_name,
    artifact,
    tool,
    status,
    duration_ms,
    detail="",
):
    print(
        json.dumps(
            {
                "type": "event",
                "id": identifier,
                "action": ACTION_LABELS.get(task_name, task_name),
                "artifact": safe_name(str(artifact)),
                "tool": str(tool)[:80],
                "status": (
                    "completed" if status == "success"
                    else "failed" if status == "failure"
                    else status
                ),
                "duration_ms": max(0, int(duration_ms)),
                "detail": str(detail).replace("\x00", "")[:500],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )


def emit(value):
    print(
        json.dumps(
            {"type": "result", "batch": value},
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )
    raise SystemExit(0)


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    main()

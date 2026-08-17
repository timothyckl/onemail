"use strict";

// --------------------------------------------------------------------------
// Small helpers
// --------------------------------------------------------------------------
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "html") node.innerHTML = value;
    else node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) {
    if (child) node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function show(node) { node.hidden = false; }
function hide(node) { node.hidden = true; }

function setStatus(box, message, isError = false, busy = false) {
  box.className = "status" + (isError ? " is-error" : "");
  box.innerHTML = "";
  if (busy) box.appendChild(el("span", { class: "spin" }));
  box.appendChild(document.createTextNode(message));
  show(box);
}

function fmt(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (value === true) return "true";
  if (value === false) return "false";
  return String(value);
}

// --------------------------------------------------------------------------
// Mode tabs
// --------------------------------------------------------------------------
$$(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    const mode = button.dataset.mode;
    $$(".tab").forEach((b) => {
      const active = b === button;
      b.classList.toggle("is-active", active);
      b.setAttribute("aria-selected", active ? "true" : "false");
    });
    // Show the matching intake (left) and output (right) blocks; hide the rest.
    $$("[data-mode-view]").forEach((view) => {
      view.hidden = view.dataset.modeView !== mode;
    });
  });
});

// --------------------------------------------------------------------------
// Dropzone wiring (shared by both forms)
// --------------------------------------------------------------------------
function wireDropzone(formId, inputId, onFile) {
  const form = $("#" + formId);
  const input = $("#" + inputId);

  form.addEventListener("click", (event) => {
    if (event.target.closest(".linklike")) return; // handled below
    input.click();
  });
  $$("[data-open]").forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      $("#" + btn.dataset.open).click();
    });
  });

  input.addEventListener("change", () => {
    if (input.files.length) onFile(input.files[0]);
  });

  ["dragenter", "dragover"].forEach((type) =>
    form.addEventListener(type, (event) => {
      event.preventDefault();
      form.classList.add("is-drag");
    })
  );
  ["dragleave", "dragend", "drop"].forEach((type) =>
    form.addEventListener(type, (event) => {
      event.preventDefault();
      if (type === "dragleave" && form.contains(event.relatedTarget)) return;
      form.classList.remove("is-drag");
    })
  );
  form.addEventListener("drop", (event) => {
    const file = event.dataTransfer.files[0];
    if (file) onFile(file);
  });
}

async function postFile(url, file) {
  const data = new FormData();
  data.append("file", file, file.name);
  const response = await fetch(url, { method: "POST", body: data });
  const payload = await response.json().catch(() => ({ ok: false, error: "Bad server response." }));
  if (!response.ok || !payload.ok) {
    throw new Error(payload.error || "Request failed (" + response.status + ").");
  }
  return payload;
}

async function getJson(url) {
  const response = await fetch(url);
  const payload = await response.json().catch(() => ({ ok: false, error: "Bad server response." }));
  if (!response.ok || !payload.ok) {
    throw new Error(payload.error || "Request failed (" + response.status + ").");
  }
  return payload;
}

// Raw variants for the agentic endpoint: they return the JSON body as-is,
// because ok:false there carries a structured "unavailable/failed" result the
// UI should render, not a thrown error.
async function postFileRaw(url, file) {
  const data = new FormData();
  data.append("file", file, file.name);
  const response = await fetch(url, { method: "POST", body: data });
  return response.json().catch(() => ({ ok: false, error: "Bad server response (" + response.status + ")." }));
}
async function getJsonRaw(url) {
  const response = await fetch(url);
  return response.json().catch(() => ({ ok: false, error: "Bad server response (" + response.status + ")." }));
}

// Which .eml produced the current scan, so "Investigate" knows what to send.
let currentScan = null; // { kind: "file", file } | { kind: "sample", name }
// Agentic readiness, fetched once on load (best-effort).
let agenticStatus = null;
getJsonRaw("/api/agentic-status").then((s) => { agenticStatus = s; }).catch(() => {});

// --------------------------------------------------------------------------
// SCAN rendering
// --------------------------------------------------------------------------
const scanStatus = $("#scan-status");
const scanResult = $("#scan-result");

function evidenceList(evidence) {
  const dl = el("dl", { class: "kv" });
  for (const [key, raw] of Object.entries(evidence)) {
    let value = raw;
    if (Array.isArray(value)) value = value.length ? value.join(", ") : "";
    dl.appendChild(el("dt", { text: key }));
    dl.appendChild(el("dd", { class: value === "" || value === null ? "empty" : "", text: fmt(value) }));
  }
  return dl;
}

function findingCard(f) {
  const top = el("div", { class: "finding-top" }, [
    el("span", { class: "detector", text: f.detector }),
    el("span", { class: "sev " + f.severity, text: f.severity }),
    f.heuristic ? el("span", { class: "tag-heuristic", text: "heuristic" }) : null,
  ]);
  const card = el("div", { class: "finding" }, [top, el("p", { class: "clause", text: f.clause })]);
  if (f.evidence && Object.keys(f.evidence).length) {
    card.appendChild(el("div", { class: "evidence" }, [evidenceList(f.evidence)]));
  }
  return card;
}

function obsCard(label, value, tone) {
  const v = el("div", { class: "v" + (tone ? " " + tone : "") + (value === "—" ? " empty" : ""), text: value });
  return el("div", { class: "obs" }, [el("div", { class: "k", text: label }), v]);
}

function renderScan(data) {
  scanResult.innerHTML = "";
  const empty = $("#scan-empty");
  if (empty) hide(empty);

  // Verdict banner
  const verdict = el("div", { class: "verdict " + (data.flagged ? "flagged" : "clear") }, [
    el("div", { class: "verdict-main" }, [
      el("span", { class: "verdict-badge", text: data.flagged ? "FLAGGED" : "CLEAR" }),
      el("span", { class: "verdict-file", text: data.file + "  ·  sha256 " + data.sha256.slice(0, 16) + "…" }),
    ]),
    el("div", { class: "verdict-counts", html:
      data.findings.length + " fired · " + data.clear.length + " clear · " +
      data.skipped.length + " skipped<br>" + data.byte_count.toLocaleString() + " bytes" }),
  ]);
  scanResult.appendChild(verdict);

  // Findings
  const findingsBlock = el("div", { class: "block" }, [
    el("h3", { class: "block-head", text: "Findings" }),
  ]);
  if (data.findings.length) {
    data.findings.forEach((f) => findingsBlock.appendChild(findingCard(f)));
  } else {
    findingsBlock.appendChild(el("p", { class: "clause", text: "No deterministic detector fired for this message." }));
  }
  scanResult.appendChild(findingsBlock);

  // Observables
  const o = data.observables;
  const grid = el("div", { class: "obs-grid" });
  grid.appendChild(obsCard("From domain", fmt(o.from_domain)));
  grid.appendChild(obsCard("Reply-To domain", fmt(o.reply_to_domain), o.reply_to_differs ? "warn" : null));
  grid.appendChild(obsCard("SPF", fmt(o.spf_result), o.spf_result === "fail" || o.spf_result === "softfail" ? "warn" : (o.spf_result === "pass" ? "ok" : null)));
  grid.appendChild(obsCard("DMARC", fmt(o.dmarc_result), o.dmarc_result === "fail" ? "warn" : (o.dmarc_result === "pass" ? "ok" : null)));
  grid.appendChild(obsCard("Display name", fmt(o.display_name)));
  grid.appendChild(obsCard("Claimed brand", fmt(o.display_name_brand)));
  grid.appendChild(obsCard("URLs", fmt(o.url_count), o.url_count ? "warn" : null));
  grid.appendChild(obsCard("Attachments", fmt(o.attachment_count), o.attachment_count ? "warn" : null));
  grid.appendChild(obsCard("MIME depth", fmt(o.mime_depth)));
  grid.appendChild(obsCard("Received hops", fmt(o.received_count)));

  const obsBlock = el("div", { class: "block" }, [
    el("h3", { class: "block-head", text: "Observables" }),
    grid,
  ]);
  if (o.subject) {
    obsBlock.insertBefore(obsCard("Subject", o.subject), grid);
  }
  if (o.url_hosts && o.url_hosts.length) {
    const pills = el("div", { class: "pill-list" });
    o.url_hosts.forEach((h) => pills.appendChild(el("span", { class: "pill", text: h })));
    if (o.url_hosts_truncated) pills.appendChild(el("span", { class: "pill", text: "+" + o.url_hosts_truncated + " more" }));
    obsBlock.appendChild(el("div", { class: "block" }, [
      el("h3", { class: "block-head", text: "URL hosts" }), pills,
    ]));
  }
  if (o.parse_error) {
    obsBlock.appendChild(el("p", { class: "status is-error", text: "Parse note: " + o.parse_error }));
  }
  scanResult.appendChild(obsBlock);

  // Skipped detectors
  if (data.skipped.length) {
    const rows = data.skipped.map((s) =>
      el("div", { class: "skip-row" }, [
        el("span", { class: "name", text: s.detector }),
        el("span", { class: "why", text: s.reason }),
      ])
    );
    scanResult.appendChild(el("details", {}, [
      el("summary", { text: "Skipped detectors (" + data.skipped.length + ")" }),
      el("div", { class: "details-body" }, rows),
    ]));
  }

  // Canonical report JSON
  scanResult.appendChild(el("details", {}, [
    el("summary", { text: "Canonical DetectionReport JSON" }),
    el("div", { class: "details-body" }, [
      el("pre", { class: "json", text: JSON.stringify(data.report, null, 2) }),
    ]),
  ]));

  show(scanResult);

  // Agentic investigation is only possible for flagged emails (they form a Case).
  if (data.flagged) {
    scanResult.appendChild(buildAgenticBlock());
  }
}

// ---- Agentic investigation (DeepSeek + Docker) ----
function buildAgenticBlock() {
  const block = el("div", { class: "block agentic" }, [
    el("h3", { class: "block-head", text: "Agentic investigation" }),
  ]);
  const btn = el("button", { class: "btn-run", type: "button" },
    ["Run agentic investigation", el("span", { class: "btn-run-sub", text: "DeepSeek + Docker sandbox" })]);
  const note = el("p", { class: "agentic-note" });
  if (agenticStatus && agenticStatus.ready === false) {
    const missing = [];
    if (agenticStatus.model && !agenticStatus.model.ok) missing.push(agenticStatus.model.detail);
    if (agenticStatus.docker && !agenticStatus.docker.ok) missing.push(agenticStatus.docker.detail);
    note.textContent = "Not ready in this environment — running it will report why. " + missing.join(" ");
  } else if (agenticStatus && agenticStatus.ready) {
    note.textContent = "Environment looks ready. This runs a sandboxed static analysis and drafts an evidence-grounded report; it can take a minute.";
  } else {
    note.textContent = "Runs a sandboxed static analysis and drafts an evidence-grounded report; it can take a minute.";
  }
  const status = el("div", { class: "status", hidden: "" });
  status.id = "agentic-status";
  const out = el("div", { class: "agentic-out", hidden: "" });
  out.id = "agentic-out";
  btn.addEventListener("click", () => runInvestigation(btn, status, out));
  block.appendChild(btn);
  block.appendChild(note);
  block.appendChild(status);
  block.appendChild(out);
  return block;
}

async function runInvestigation(btn, status, out) {
  if (!currentScan) return;
  btn.disabled = true;
  out.hidden = true;
  out.innerHTML = "";
  setStatus(status, "Running DeepSeek + Docker analysis — this can take a minute…", false, true);
  try {
    const result = currentScan.kind === "file"
      ? await postFileRaw("/api/investigate", currentScan.file)
      : await getJsonRaw("/api/investigate/sample/" + encodeURIComponent(currentScan.name));
    renderInvestigation(result, status, out);
  } catch (err) {
    setStatus(status, "Investigation request failed: " + err.message, true);
  } finally {
    btn.disabled = false;
  }
}

function renderInvestigation(result, status, out) {
  out.innerHTML = "";
  // Not flagged (shouldn't happen from this button) or explicit note.
  if (result.flagged === false) {
    setStatus(status, result.note || "Agentic investigation does not apply to this email.", false);
    return;
  }
  // Unavailable environment: list the specific problems.
  if (!result.ok) {
    setStatus(status, result.error || "Agentic investigation could not run.", true);
    if (Array.isArray(result.problems) && result.problems.length) {
      const list = el("div", { class: "problems" },
        result.problems.map((p) => el("div", { class: "problem", text: p })));
      out.appendChild(list);
      out.hidden = false;
    }
    return;
  }
  // Success: render the intelligence report.
  setStatus(status, "Investigation complete" + (result.model ? " · model " + result.model : ""), false);
  out.appendChild(el("div", { class: "rendered", html: result.report_html }));
  out.appendChild(el("details", {}, [
    el("summary", { text: "Intelligence report JSON" }),
    el("div", { class: "details-body" }, [
      el("pre", { class: "json", text: JSON.stringify(result.report_json, null, 2) }),
    ]),
  ]));
  out.hidden = false;
}

async function runScanFile(file) {
  hide(scanResult);
  if (!/\.eml$/i.test(file.name)) {
    setStatus(scanStatus, "Only .eml files can be scanned.", true);
    return;
  }
  currentScan = { kind: "file", file };
  setStatus(scanStatus, "Detecting " + file.name + "…", false, true);
  try {
    const data = await postFile("/api/scan", file);
    setStatus(scanStatus, "Detection complete: " + file.name, false);
    renderScan(data);
  } catch (err) {
    setStatus(scanStatus, err.message, true);
  }
}

async function runScanSample(name) {
  hide(scanResult);
  currentScan = { kind: "sample", name };
  setStatus(scanStatus, "Detecting " + name + "…", false, true);
  try {
    const data = await getJson("/api/sample/" + encodeURIComponent(name));
    setStatus(scanStatus, "Detection complete: " + name, false);
    renderScan(data);
  } catch (err) {
    setStatus(scanStatus, err.message, true);
  }
}

wireDropzone("scan-form", "scan-input", runScanFile);
$$(".chip[data-sample]").forEach((chip) =>
  chip.addEventListener("click", (e) => { e.stopPropagation(); runScanSample(chip.dataset.sample); })
);

// --------------------------------------------------------------------------
// PREVIEW rendering
// --------------------------------------------------------------------------
const previewStatus = $("#preview-status");
const previewResult = $("#preview-result");

function renderPreview(data) {
  previewResult.innerHTML = "";
  const empty = $("#preview-empty");
  if (empty) hide(empty);
  previewResult.appendChild(el("div", { class: "report-head" }, [
    el("span", { class: "name", text: data.file }),
    el("span", { class: "engine", text: "rendered via " + data.engine }),
  ]));
  previewResult.appendChild(el("div", { class: "rendered", html: data.html }));
  previewResult.appendChild(el("details", {}, [
    el("summary", { text: "Markdown source" }),
    el("div", { class: "details-body" }, [el("pre", { class: "json", text: data.source })]),
  ]));
  show(previewResult);
}

async function runPreviewFile(file) {
  hide(previewResult);
  if (!/\.(md|markdown|txt)$/i.test(file.name)) {
    setStatus(previewStatus, "Only .md, .markdown or .txt files can be previewed.", true);
    return;
  }
  setStatus(previewStatus, "Rendering " + file.name + "…", false, true);
  try {
    const data = await postFile("/api/preview", file);
    setStatus(previewStatus, "Rendered " + file.name, false);
    renderPreview(data);
  } catch (err) {
    setStatus(previewStatus, err.message, true);
  }
}

wireDropzone("preview-form", "preview-input", runPreviewFile);
const sampleReportBtn = $("[data-sample-report]");
if (sampleReportBtn) {
  sampleReportBtn.addEventListener("click", async (e) => {
    e.stopPropagation();
    hide(previewResult);
    setStatus(previewStatus, "Loading sample report…", false, true);
    try {
      const data = await getJson("/api/sample-report");
      setStatus(previewStatus, "Rendered " + data.file, false);
      renderPreview(data);
    } catch (err) {
      setStatus(previewStatus, err.message, true);
    }
  });
}
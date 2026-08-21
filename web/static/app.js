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

function fmtDuration(milliseconds) {
  const value = Math.max(0, Number(milliseconds) || 0);
  if (value < 1000) return Math.round(value) + " ms";
  const seconds = value / 1000;
  if (seconds < 60) return seconds.toFixed(seconds < 10 ? 1 : 0) + " s";
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.floor(seconds % 60);
  return minutes + "m " + String(remainder).padStart(2, "0") + "s";
}

function fmtPhaseDuration(milliseconds, running = false) {
  const value = Math.max(0, Number(milliseconds) || 0);
  if (!running && value < 1000) return "<1 s";
  const seconds = Math.floor(value / 1000);
  if (seconds < 60) return seconds + " s";
  const minutes = Math.floor(seconds / 60);
  return minutes + "m " + String(seconds % 60).padStart(2, "0") + "s";
}

function fmtBytes(bytes) {
  const value = Math.max(0, Number(bytes) || 0);
  if (value < 1024) return value.toLocaleString() + " bytes";
  if (value < 1024 * 1024) return (value / 1024).toFixed(1) + " KB";
  return (value / (1024 * 1024)).toFixed(1) + " MB";
}

function prepareRenderedContent(container) {
  $$("table", container).forEach((table) => {
    const headings = $$('thead th', table).map((cell) => cell.textContent.trim());
    $$('tbody tr', table).forEach((row) => {
      $$('td', row).forEach((cell, index) => {
        cell.dataset.label = headings[index] || "Value";
      });
    });

    table.classList.add("responsive-table");
    if (!table.parentElement.classList.contains("table-scroll")) {
      const wrapper = el("div", { class: "table-scroll" });
      table.parentNode.insertBefore(wrapper, table);
      wrapper.appendChild(table);
    }
  });
}

// --------------------------------------------------------------------------
// Mode tabs
// --------------------------------------------------------------------------
function selectMode(mode) {
  $$(".tab").forEach((button) => {
    const active = button.dataset.mode === mode;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  $$("[data-mode-view]").forEach((view) => {
    view.hidden = view.dataset.modeView !== mode;
  });
}

$$(".tab").forEach((button) => {
  button.addEventListener("click", () => selectMode(button.dataset.mode));
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
  $$('[data-open="' + inputId + '"]').forEach((btn) => {
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
const investigationHeaders = { "X-OneMail-Request": "investigate" };

async function postFileRaw(url, file) {
  const data = new FormData();
  data.append("file", file, file.name);
  const response = await fetch(url, {
    method: "POST",
    headers: investigationHeaders,
    body: data,
  });
  return response.json().catch(() => ({ ok: false, error: "Bad server response (" + response.status + ")." }));
}
async function postJsonRaw(url) {
  const response = await fetch(url, { method: "POST", headers: investigationHeaders });
  return response.json().catch(() => ({ ok: false, error: "Bad server response (" + response.status + ")." }));
}
async function getInvestigationRaw(url) {
  const response = await fetch(url, { headers: investigationHeaders });
  return response.json().catch(() => ({ ok: false, error: "Bad server response (" + response.status + ")." }));
}

// Which .eml produced the current scan, so "Investigate" knows what to send.
let currentScan = null; // { kind: "file", file } | { kind: "sample", name }
let investigationRunSequence = 0;

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

function keyFacts(facts) {
  const list = el("div", { class: "key-facts" });
  facts.forEach((fact) => {
    list.appendChild(el("div", { class: "key-fact" }, [
      el("span", { class: "key-fact-label", text: fact.label }),
      el("strong", { class: "key-fact-value", text: fact.value }),
    ]));
  });
  return list;
}

function findingCard(f) {
  const p = f.presentation;
  const top = el("div", { class: "finding-top" }, [
    el("h4", { class: "finding-title", text: p.title }),
    el("span", { class: "sev " + f.severity, text: p.severity_label }),
    el("span", { class: "signal-basis", text: p.basis_label }),
  ]);
  const card = el("article", { class: "finding" }, [
    top,
    el("p", { class: "detector-id", text: "Check ID: " + f.detector }),
    el("p", { class: "finding-interpretation", text: p.interpretation }),
    el("div", { class: "finding-meaning" }, [
      el("p", {}, [el("strong", { text: p.severity_label + ": " }), p.severity_explanation]),
      el("p", {}, [el("strong", { text: p.basis_label + ": " }), p.basis_explanation]),
    ]),
  ]);
  if (p.key_facts && p.key_facts.length) {
    card.appendChild(el("div", { class: "key-evidence" }, [
      el("h5", { text: "Key evidence" }),
      keyFacts(p.key_facts),
    ]));
  }
  if (f.evidence && Object.keys(f.evidence).length) {
    card.appendChild(el("div", { class: "evidence" }, [
      el("h5", { text: "Raw technical evidence" }),
      el("p", { class: "raw-clause", text: f.clause }),
      evidenceList(f.evidence),
    ]));
  }
  return card;
}

function observableSection(section) {
  const grid = el("div", { class: "obs-grid" });
  section.items.forEach((item) => {
    const value = fmt(item.value);
    grid.appendChild(el("div", { class: "obs " + (item.tone || "neutral") }, [
      el("div", { class: "k", text: item.label }),
      el("strong", { class: "v" + (value === "—" ? " empty" : ""), text: value }),
      el("p", { class: "obs-explanation", text: item.explanation }),
    ]));
  });
  const groupClass = "observable-group" + (section.max_columns === 2 ? " max-two-columns" : "");
  return el("section", { class: groupClass }, [
    el("h4", { text: section.title }),
    el("p", { class: "group-summary", text: section.summary }),
    grid,
  ]);
}

function emailPresentation(data) {
  const o = data.observables;
  const formats = [];
  if (o.presentation_body_format === "html") {
    formats.push("HTML");
    if (o.has_plain) formats.push("Plain-text alternative");
  } else {
    if (o.has_plain) formats.push("Plain text");
    if (o.has_html) formats.push("HTML alternative");
  }
  if (!formats.length) formats.push("No readable body format identified");

  const header = el("header", { class: "email-preview-head" }, [
    el("div", { class: "email-preview-title-row" }, [
      el("h4", { text: o.subject || "(No subject)" }),
      el("time", { class: "email-preview-date", text: o.raw_date || "Date not observed" }),
    ]),
    el("div", { class: "email-preview-meta-row" }, [
      el("div", { class: "email-preview-sender" }, [
        el("strong", { text: o.display_name || o.from_domain || "Unknown sender" }),
        el("span", { text: o.from_domain ? "From domain · " + o.from_domain : "From domain not observed" }),
      ]),
      el("div", { class: "email-preview-formats" },
        formats.map((format) => el("span", { class: "email-format", text: format }))),
    ]),
  ]);

  const preferredText = o.presentation_body_format === "plain"
    ? o.presentation_body_text
    : (o.presentation_body_format ? "" : o.body_text);
  const preferredHTML = o.presentation_body_format === "html"
    ? o.presentation_body_html
    : "";
  const body = preferredHTML
    ? el("div", { class: "email-preview-body is-html", html: preferredHTML })
    : el("div", {
      class: "email-preview-body" + (preferredText ? "" : " is-empty"),
      text: preferredText || "No readable message body was extracted.",
    });

  const footer = el("footer", { class: "email-preview-foot" });
  let hasFooter = false;
  if (o.inline_image_count) {
    hasFooter = true;
    footer.appendChild(el("p", {
      class: "email-preview-note",
      text: o.inline_image_count + " inline image" + (o.inline_image_count === 1 ? " was" : "s were") + " not loaded.",
    }));
  }
  if (o.attachments.length) {
    hasFooter = true;
    footer.appendChild(el("div", { class: "email-attachments" },
      o.attachments.map((attachment) => el("div", { class: "email-attachment" }, [
        el("strong", { text: attachment.name || "Unnamed attachment" }),
        el("span", { text: attachment.attachment_class + " · " + fmtBytes(attachment.size) }),
      ]))));
  }

  return el("section", { class: "block email-presentation" }, [
    el("h3", { class: "block-head", text: "Message presentation" }),
    el("p", { class: "section-intro", text: "A safe presentation of the parsed message. Active HTML, scripts and remote content are not rendered." }),
    el("article", { class: "email-preview" }, [
      header,
      body,
      hasFooter ? footer : null,
    ]),
  ]);
}

function renderScan(data) {
  resetAgenticStage();
  scanResult.innerHTML = "";
  const empty = $("#scan-empty");
  if (empty) hide(empty);

  // Compact verdict and deterministic interpretation summary.
  const summary = data.scan_summary;
  const verdict = el("div", { class: "verdict " + (data.flagged ? "flagged" : "clear") }, [
    el("div", { class: "verdict-top" }, [
      el("div", { class: "verdict-main" }, [
        el("span", { class: "verdict-badge", text: data.flagged ? "FLAGGED" : "CLEAR" }),
        el("div", { class: "verdict-file" }, [
          el("span", { class: "verdict-name", text: data.file }),
          el("span", { class: "verdict-hash", text: "sha256 " + data.sha256.slice(0, 16) + "…" }),
        ]),
      ]),
      el("div", { class: "verdict-counts", html:
        data.findings.length + " concerns · " + data.clear.length + " found no concern · " +
        data.skipped.length + " could not be assessed<br>" + data.byte_count.toLocaleString() + " bytes" }),
    ]),
    el("div", { class: "verdict-summary" + (data.flagged ? " is-description-only" : "") },
      data.flagged
        ? [el("p", { text: summary.text })]
        : [el("h3", { text: summary.title }), el("p", { text: summary.text })]),
  ]);
  scanResult.appendChild(verdict);

  // Findings
  const findingsBlock = el("div", { class: "block" }, [
    el("h3", { class: "block-head", text: "Interpreted findings" }),
    el("p", { class: "section-intro", text: "Severity describes the strength of each signal, not whether the email is definitively malicious. Raw detector evidence remains visible on every finding." }),
  ]);
  if (data.findings.length) {
    data.findings.forEach((f) => findingsBlock.appendChild(findingCard(f)));
  } else {
    findingsBlock.appendChild(el("p", { class: "clause", text: "No deterministic detector fired for this message." }));
  }
  scanResult.appendChild(findingsBlock);

  // Message facts with deterministic context
  const o = data.observables;
  const obsBlock = el("div", { class: "block" }, [
    el("h3", { class: "block-head", text: "Message facts and interpretation" }),
    el("p", { class: "section-intro", text: "Facts are grouped by purpose. Highlighting reflects a fired check, not the mere presence of a link or attachment." }),
  ]);
  data.observable_sections.forEach((section) => obsBlock.appendChild(observableSection(section)));
  if (o.parse_error) {
    obsBlock.appendChild(el("p", { class: "status is-error", text: "Parse note: " + o.parse_error }));
  }
  scanResult.appendChild(obsBlock);

  // Checks that lacked the facts required for assessment
  if (data.skipped.length) {
    const rows = data.skipped.map((s) =>
      el("div", { class: "skip-row" }, [
        el("div", { class: "skip-identity" }, [
          el("strong", { class: "name", text: s.title }),
          el("span", { class: "skip-id", text: s.detector }),
        ]),
        el("div", { class: "why" }, [
          el("span", { text: s.reason }),
          el("small", { text: s.check }),
        ]),
      ])
    );
    scanResult.appendChild(el("details", {}, [
      el("summary", { text: "Checks that could not be assessed (" + data.skipped.length + ")" }),
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

  // Safe, deterministic presentation of the parsed message and its contents.
  scanResult.appendChild(emailPresentation(data));

  show(scanResult);

  // Agentic investigation is only possible for flagged emails (they form a Case).
  if (data.flagged) {
    scanResult.appendChild(buildAgenticBlock(currentScan, data));
  }
}

// ---- Agentic investigation (LM Studio + Docker) ----
function buildAgenticBlock(source, data) {
  const block = el("div", { class: "block agentic" }, [
    el("h3", { class: "block-head", text: "Agentic investigation" }),
  ]);
  const btn = el("button", { class: "btn-run", type: "button", text: "Continue investigating" });
  btn.addEventListener("click", () => startAgenticStage(source, data, btn));
  block.appendChild(btn);
  return block;
}

function progressRow(event, totalElapsed, phaseTiming = false) {
  const running = event.status === "running";
  const duration = event.duration_ms === null || event.duration_ms === undefined
    ? (running ? Math.max(0, totalElapsed - event.total_elapsed_ms) : 0)
    : event.duration_ms;
  const meta = [event.tool, event.artifact].filter(Boolean).join(" · ");
  return el("div", { class: "progress-row is-" + event.status }, [
    el("span", { class: "progress-mark", text: running
      ? "●"
      : (event.status === "completed"
        ? "✓"
        : (event.status === "queued" ? "○" : (event.status === "stopped" ? "■" : "!"))) }),
    el("div", { class: "progress-copy" }, [
      el("div", { class: "progress-action", text: event.action }),
      meta ? el("div", { class: "progress-meta", text: meta }) : null,
      event.detail ? el("div", { class: "progress-detail", text: event.detail }) : null,
    ]),
    el("span", { class: "progress-time", text: phaseTiming ? fmtPhaseDuration(duration, running) : fmtDuration(duration) }),
  ]);
}

function activityOutput(value) {
  const text = String(value || "");
  if (!text) return "";
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch (_error) {
    return text;
  }
}

function activitySummary(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return Object.entries(parsed).slice(0, 5).map(([key, item]) => {
        if (Array.isArray(item)) return key + ": " + item.length;
        if (item && typeof item === "object") return key + ": " + Object.keys(item).length;
        const rendered = String(item);
        return key + ": " + (rendered.length > 50 ? rendered.slice(0, 47) + "…" : rendered);
      }).join(" · ");
    }
  } catch (_error) {
    // Plain command output is summarised below.
  }
  const compact = text.replace(/\s+/g, " ");
  return compact.length > 180 ? compact.slice(0, 177) + "…" : compact;
}

function activityRow(event, totalElapsed) {
  const running = event.status === "running";
  const decision = event.kind === "decision";
  const duration = event.duration_ms === null || event.duration_ms === undefined
    ? (running ? Math.max(0, totalElapsed - event.total_elapsed_ms) : 0)
    : event.duration_ms;
  const mark = running ? "●" : (event.status === "completed" ? "✓" : (event.status === "skipped" ? "–" : "!"));
  const stateText = decision ? mark : mark + " " + fmtDuration(duration);
  const meta = [event.tool, event.artifact].filter(Boolean).join(" · ");
  const summary = activitySummary(event.output);
  const rawOutput = activityOutput(event.output);

  return el("div", {
    class: "activity-row is-" + event.status + " is-" + (event.kind || "activity"),
  }, [
    el("div", { class: "activity-main" }, [
      el("div", { class: "activity-line" }, [
        el("strong", { class: "activity-title", text: event.action }),
        meta ? el("span", { class: "activity-meta", text: meta }) : null,
      ]),
      decision && event.rationale
        ? el("p", { class: "activity-reason", text: event.rationale })
        : null,
      event.command
        ? el("code", { class: "activity-command", text: "$ " + event.command, title: event.command })
        : null,
      summary
        ? el("p", { class: "activity-summary", text: summary })
        : (event.detail ? el("p", { class: "activity-summary", text: event.detail }) : null),
      rawOutput && rawOutput.replace(/\s+/g, " ").trim() !== summary
        ? el("details", { class: "activity-raw" }, [
          el("summary", { text: "Raw output" }),
          el("pre", { text: rawOutput }),
        ])
        : null,
    ]),
    el("span", { class: "activity-state", text: stateText }),
  ]);
}

function investigationPhase(event) {
  const action = event.action || "";
  if (event.stage === "container") return null;
  if (event.stage === "pipeline") {
    return action === "Validate investigation case"
      ? { id: "prepare", action: "Prepare secure environment" }
      : null;
  }
  if (["detection", "preflight", "model"].includes(event.stage)) {
    return { id: "prepare", action: "Prepare secure environment" };
  }
  if (event.stage === "sandbox") {
    return action === "Create isolated analysis container"
      ? { id: "prepare", action: "Prepare secure environment" }
      : null;
  }
  if (event.stage === "analysis" && [
    "Run deterministic baseline",
    "Reconcile extracted artifacts",
  ].includes(action)) {
    return { id: "evidence", action: "Extract and catalogue evidence" };
  }
  if (["planning", "policy"].includes(event.stage)) {
    return { id: "planning", action: "Plan targeted analysis" };
  }
  if (["analysis", "enrichment"].includes(event.stage)) {
    return { id: "analysis", action: "Analyse suspicious artefacts" };
  }
  if (event.stage === "correlation") {
    return { id: "correlation", action: "Correlate findings" };
  }
  if (event.stage === "reporting") {
    return { id: "reporting", action: "Generate investigation report" };
  }
  return null;
}

function investigationPhases(events, totalElapsed, jobStatus) {
  const phases = [];
  for (const event of events) {
    const definition = investigationPhase(event);
    if (!definition) continue;
    const running = event.status === "running";
    const eventEnd = running ? totalElapsed : Number(event.total_elapsed_ms) || 0;
    const eventDuration = event.duration_ms === null || event.duration_ms === undefined
      ? 0
      : Math.max(0, Number(event.duration_ms) || 0);
    const eventStart = running
      ? Number(event.total_elapsed_ms) || 0
      : Math.max(0, eventEnd - eventDuration);
    let phase = phases.at(-1);
    if (!phase || phase.phase_id !== definition.id) {
      phase = {
        phase_id: definition.id,
        step_id: "phase-" + definition.id + "-" + phases.length,
        stage: "phase",
        action: definition.action,
        status: "completed",
        total_elapsed_ms: eventStart,
        duration_ms: 0,
        started_ms: eventStart,
        ended_ms: eventEnd,
      };
      phases.push(phase);
    } else {
      phase.started_ms = Math.min(phase.started_ms, eventStart);
      phase.ended_ms = Math.max(phase.ended_ms, eventEnd);
    }
    if (event.status === "failed") phase.status = "failed";
    else if (running) phase.status = "running";
    else phase.status = "completed";
    phase.total_elapsed_ms = phase.started_ms;
    phase.duration_ms = phase.status === "running"
      ? null
      : Math.max(0, phase.ended_ms - phase.started_ms);
  }

  if (!phases.length && jobStatus === "running") {
    phases.push({
      phase_id: "prepare",
      step_id: "phase-prepare-0",
      stage: "phase",
      action: "Prepare secure environment",
      status: "running",
      total_elapsed_ms: 0,
      duration_ms: null,
    });
  }
  if (jobStatus !== "running") {
    for (const phase of phases) {
      if (phase.status !== "running") continue;
      phase.status = jobStatus === "cancelled" ? "stopped" : "failed";
      phase.duration_ms = Math.max(0, totalElapsed - phase.total_elapsed_ms);
    }
  }
  return phases;
}

function renderProgress(job, progressOut, containerOut) {
  let panel = $(".investigation-progress", progressOut);
  if (!panel) {
    panel = el("div", { class: "investigation-progress" });
    progressOut.appendChild(panel);
  }
  panel.innerHTML = "";
  const latest = new Map();
  for (const event of job.events || []) latest.set(event.step_id, event);
  const steps = Array.from(latest.values());
  const activity = steps.filter((event) => ["container", "agent_activity"].includes(event.stage));
  const phases = investigationPhases(steps, job.total_elapsed_ms, job.status);
  const active = phases.filter((phase) => phase.status === "running").at(-1);
  const current = job.status === "running"
    ? (active ? active.action : "Prepare secure environment")
    : (job.status === "completed"
      ? "Investigation complete"
      : (job.status === "cancelled" ? "Investigation stopped" : "Investigation failed"));
  const progressLabel = job.status === "running"
    ? "Investigation in progress"
    : (job.status === "cancelled" ? "Investigation stopped" : "Investigation " + job.status);

  panel.appendChild(el("div", { class: "progress-head" }, [
    el("div", {}, [
      el("div", { class: "progress-label", text: progressLabel }),
      el("div", { class: "progress-current", text: current }),
    ]),
    el("div", { class: "progress-total" }, [
      el("span", { text: "Total" }),
      el("strong", { text: fmtDuration(job.total_elapsed_ms) }),
    ]),
  ]));

  const timeline = el("div", { class: "progress-list" });
  phases.forEach((phase) => timeline.appendChild(progressRow(phase, job.total_elapsed_ms, true)));
  panel.appendChild(timeline);

  const previousFeed = $(".activity-feed", containerOut);
  const previousScrollTop = previousFeed ? previousFeed.scrollTop : 0;
  const followLatest = !previousFeed ||
    previousFeed.scrollHeight - previousFeed.scrollTop - previousFeed.clientHeight < 24;
  containerOut.innerHTML = "";
  const body = el("div", { class: "activity-feed" });
  if (activity.length) {
    activity.forEach((event) => body.appendChild(activityRow(event, job.total_elapsed_ms)));
  } else {
    body.appendChild(el("p", { class: "container-awaiting", text: "Waiting for isolated container activity." }));
  }
  const agentDecisions = activity.filter((event) => event.kind === "decision").length;
  const toolCalls = activity.filter((event) => event.kind === "tool").length;
  const details = el("section", { class: "container-progress" }, [
    el("div", { class: "container-progress-head" }, [
      el("strong", { text: "Container activity" }),
      el("span", { text: agentDecisions + " decision" + (agentDecisions === 1 ? "" : "s") + " · " + toolCalls + " tool call" + (toolCalls === 1 ? "" : "s") }),
    ]),
    body,
  ]);
  containerOut.appendChild(details);
  body.scrollTop = followLatest ? body.scrollHeight : previousScrollTop;
  progressOut.hidden = false;
  containerOut.hidden = false;
  return active;
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function runInvestigation(source, startBtn, restartBtn, stopBtn, status, progressOut, containerOut, reportOut, entryBtn) {
  if (!source) return;
  const runSequence = ++investigationRunSequence;
  if (entryBtn) entryBtn.disabled = true;
  startBtn.hidden = true;
  startBtn.disabled = true;
  progressOut.hidden = false;
  progressOut.innerHTML = "";
  containerOut.innerHTML = "";
  reportOut.innerHTML = "";
  setStatus(status, "Starting agentic investigation…", false, true);
  try {
    const started = source.kind === "file"
      ? await postFileRaw("/api/investigate", source.file)
      : await postJsonRaw("/api/investigate/sample/" + encodeURIComponent(source.name));
    if (!started.ok || !started.job) {
      renderInvestigation(started, status, reportOut);
      return;
    }
    let job = started.job;
    stopBtn.dataset.jobId = job.id;
    stopBtn.disabled = false;
    stopBtn.hidden = false;
    while (job.status === "queued" || job.status === "running") {
      const active = renderProgress(job, progressOut, containerOut);
      setStatus(
        status,
        (active ? active.action : "Investigation queued") + " · total " + fmtDuration(job.total_elapsed_ms),
        false,
        true
      );
      await wait(500);
      const update = await getInvestigationRaw("/api/investigate/" + encodeURIComponent(job.id));
      if (!update.ok || !update.job) throw new Error(update.error || "Could not read investigation progress.");
      job = update.job;
    }
    renderProgress(job, progressOut, containerOut);
    renderInvestigation(job.result || { ok: false, flagged: true, error: "Investigation ended without a result." }, status, reportOut, job);
  } catch (err) {
    setStatus(status, "Investigation request failed: " + err.message, true);
  } finally {
    if (runSequence !== investigationRunSequence) return;
    if (entryBtn) entryBtn.disabled = false;
    if (!restartBtn.hidden) {
      stopBtn.disabled = true;
      delete stopBtn.dataset.jobId;
      return;
    }
    restartBtn.hidden = true;
    restartBtn.disabled = true;
    stopBtn.hidden = true;
    stopBtn.disabled = true;
    delete stopBtn.dataset.jobId;
  }
}

function renderInvestigation(result, status, out, job = null) {
  // Not flagged (shouldn't happen from this button) or explicit note.
  if (result.flagged === false) {
    setStatus(status, result.note || "Agentic investigation does not apply to this email.", false);
    const description = $(".agentic-case-description", agenticResult);
    if (description) description.textContent = "This message does not require agentic investigation.";
    return;
  }
  if (result.cancelled) {
    setStatus(status, result.error || result.note || "Investigation stopped.", Boolean(result.error));
    const state = $(".agentic-case-state", agenticResult);
    if (state) state.textContent = "Stopped";
    const description = $(".agentic-case-description", agenticResult);
    if (description) description.textContent = "The investigation was stopped and its container removed.";
    return;
  }
  // Unavailable environment: list the specific problems.
  if (!result.ok) {
    setStatus(status, result.error || "Agentic investigation could not run.", true);
    const state = $(".agentic-case-state", agenticResult);
    if (state) state.textContent = "Failed";
    const description = $(".agentic-case-description", agenticResult);
    if (description) description.textContent = "The investigation could not be completed.";
    if (Array.isArray(result.problems) && result.problems.length) {
      const list = el("div", { class: "problems" },
        result.problems.map((p) => el("div", { class: "problem", text: p })));
      out.appendChild(list);
      out.hidden = false;
    }
    return;
  }
  // Success: route the completed report to the dedicated preview stage.
  setStatus(
    status,
    "Investigation complete" +
      (result.model ? " · model " + result.model : "") +
      (job ? " · total " + fmtDuration(job.total_elapsed_ms) : ""),
    false
  );
  const state = $(".agentic-case-state", agenticResult);
  if (state) state.textContent = "Complete";
  const description = $(".agentic-case-description", agenticResult);
  if (description) description.textContent = "Investigation complete. The report is ready to preview.";
  const markdown = result.report_markdown || "";
  const reportName = (result.file || "investigation").replace(/\.eml$/i, "") + "-investigation.md";
  const preview = el("button", {
    class: "btn-preview-report",
    type: "button",
    text: "Preview report",
  });
  preview.addEventListener("click", () => {
    renderPreview({
      file: reportName,
      download_name: reportName,
      engine: result.model ? "agentic investigation · " + result.model : "agentic investigation",
      html: result.report_html || "",
      source: markdown,
    });
    setStatus(previewStatus, "Rendered " + reportName, false);
    selectMode("preview");
  });
  out.appendChild(el("div", { class: "report-actions" }, [preview]));
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
// Agentic stage — unlocked only by deterministic escalation
// --------------------------------------------------------------------------
const agenticTab = $('.tab[data-mode="agentic"]');
const agenticContext = $("#agentic-context");
const agenticResult = $("#agentic-result");

function resetAgenticStage() {
  agenticTab.disabled = true;
  agenticTab.setAttribute("aria-disabled", "true");
  agenticContext.innerHTML = "";
  hide(agenticContext);
  agenticResult.innerHTML = "";
  hide(agenticResult);
}

function startAgenticStage(source, data, trigger) {
  agenticTab.disabled = false;
  agenticTab.setAttribute("aria-disabled", "false");

  agenticContext.innerHTML = "";
  agenticContext.appendChild(el("span", { class: "agentic-context-label", text: "Investigation ready" }));
  agenticContext.appendChild(el("strong", { text: data.file }));
  agenticContext.appendChild(el("p", {
    text: data.findings.length + " deterministic concern" + (data.findings.length === 1 ? "" : "s") + " triggered escalation.",
  }));
  const status = el("div", { class: "status", hidden: "" });
  const progressOut = el("div", { class: "agentic-progress-out", hidden: "" });
  const startBtn = el("button", {
    class: "btn-start",
    type: "button",
    text: "Start investigation",
  });
  const restartBtn = el("button", {
    class: "btn-restart",
    type: "button",
    text: "↻",
    title: "Restart investigation",
    "aria-label": "Restart investigation",
    hidden: "",
    disabled: "",
  });
  const stopBtn = el("button", {
    class: "btn-stop",
    type: "button",
    text: "Stop investigation",
    hidden: "",
    disabled: "",
  });
  agenticContext.appendChild(status);
  agenticContext.appendChild(progressOut);
  agenticContext.appendChild(el("div", { class: "investigation-controls" }, [startBtn, stopBtn, restartBtn]));
  show(agenticContext);

  agenticResult.innerHTML = "";
  agenticResult.appendChild(el("section", { class: "agentic-case is-eligible" }, [
    el("div", { class: "agentic-case-main" }, [
      el("span", { class: "agentic-case-label", text: "Intelligence investigation" }),
      el("h3", { text: data.file }),
      el("p", { class: "agentic-case-description", text: "Ready to analyse the flagged message in the isolated workflow." }),
    ]),
    el("span", { class: "agentic-case-state", text: "Ready" }),
  ]));
  const containerOut = el("div", { class: "container-activity-out", hidden: "" });
  const reportOut = el("div", { class: "agentic-out", hidden: "" });
  agenticResult.appendChild(containerOut);
  agenticResult.appendChild(reportOut);
  show(agenticResult);

  const beginInvestigation = () => {
    restartBtn.hidden = true;
    restartBtn.disabled = true;
    stopBtn.hidden = true;
    stopBtn.disabled = true;
    delete stopBtn.dataset.jobId;
    const state = $(".agentic-case-state", agenticResult);
    const description = $(".agentic-case-description", agenticResult);
    if (state) state.textContent = "In progress";
    if (description) description.textContent = "Analysing the flagged message in the isolated workflow.";
    runInvestigation(source, startBtn, restartBtn, stopBtn, status, progressOut, containerOut, reportOut, trigger);
  };

  startBtn.addEventListener("click", beginInvestigation);

  stopBtn.addEventListener("click", async () => {
    const identifier = stopBtn.dataset.jobId;
    if (!identifier) return;
    restartBtn.disabled = true;
    stopBtn.disabled = true;
    setStatus(status, "Stopping investigation and removing its container…", false, true);
    try {
      const stopped = await postJsonRaw("/api/investigate/" + encodeURIComponent(identifier) + "/stop");
      if (!stopped.ok || !stopped.job) throw new Error(stopped.error || "Could not stop the investigation.");
      renderProgress(stopped.job, progressOut, containerOut);
      renderInvestigation(stopped.job.result, status, reportOut, stopped.job);
      stopBtn.hidden = false;
      stopBtn.disabled = true;
      restartBtn.hidden = false;
      restartBtn.disabled = false;
    } catch (err) {
      setStatus(status, "Could not stop investigation: " + err.message, true);
      stopBtn.disabled = false;
    }
  });

  restartBtn.addEventListener("click", () => {
    restartBtn.disabled = true;
    stopBtn.disabled = true;
    setStatus(status, "Restarting investigation…", false, true);
    beginInvestigation();
  });

  selectMode("agentic");
}

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
  const rendered = el("div", { class: "rendered", html: data.html });
  prepareRenderedContent(rendered);
  previewResult.appendChild(rendered);
  previewResult.appendChild(el("details", {}, [
    el("summary", { text: "Markdown source" }),
    el("div", { class: "details-body" }, [el("pre", { class: "json", text: data.source })]),
  ]));
  const downloadUrl = URL.createObjectURL(new Blob([data.source || ""], { type: "text/markdown;charset=utf-8" }));
  const download = el("a", {
    class: "btn-download",
    href: downloadUrl,
    download: data.download_name || data.file || "report.md",
    text: "Download report",
  });
  download.addEventListener("click", () => window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000), { once: true });
  previewResult.appendChild(el("div", { class: "report-actions preview-download-actions" }, [download]));
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

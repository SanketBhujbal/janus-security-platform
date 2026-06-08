"use strict";

const $ = (id) => document.getElementById(id);

const state = {
    scanId: null,
    eventSource: null,
    findings: new Map(),   // idx -> row payload
};

const statusPill = $("statusPill");

function setStatus(label, klass) {
    statusPill.textContent = label;
    statusPill.classList.remove("running", "done", "error");
    if (klass) statusPill.classList.add(klass);
    // Body-level flag so CSS can drive secondary indicators (logo pulse,
    // progress-card header spinner) without each one needing its own JS.
    document.body.classList.toggle("scan-running", klass === "running");
}

function fmtTime(iso) {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour12: false });
}

function appendLog(event) {
    const log = $("logStream");
    const line = document.createElement("div");
    line.className = `line t-${event.type}`;
    const ts = document.createElement("span");
    ts.className = "ts";
    ts.textContent = fmtTime(event.ts);
    const msg = document.createElement("span");
    msg.className = "msg";
    msg.textContent = `${event.type.padEnd(26)}  ${event.message}`;
    line.appendChild(ts);
    line.appendChild(msg);
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
}

function renderFindings() {
    const body = $("findingsBody");
    body.innerHTML = "";
    const rows = Array.from(state.findings.values()).sort((a, b) => a.idx - b.idx);
    if (rows.length === 0) {
        $("findingsEmpty").style.display = "block";
        return;
    }
    $("findingsEmpty").style.display = "none";
    for (const f of rows) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${f.idx}</td>
            <td><span class="sev ${f.severity}">${f.severity.toUpperCase()}</span></td>
            <td>${escapeHtml(f.category)}</td>
            <td class="loc">${escapeHtml(f.location)}</td>
            <td class="status-cell ${f.status}">${f.status}</td>
            <td><button class="btn-ghost" data-idx="${f.idx}">view</button></td>
        `;
        tr.querySelector("button").addEventListener("click", () => openDrawer(f.idx));
        body.appendChild(tr);
    }
}

function displayMode(mode) {
    // Map internal mode names to human-readable labels for the KPI tile.
    if (mode === "full" || mode === "demo-security-dotnet" || mode === "demo-security") return "security";
    if (mode === "import-sarif" || mode === "import-checkmarx") return "import";
    return mode || "—";
}

function updateKpis(summary) {
    if (!summary) return;
    $("kpiMode").textContent      = displayMode(summary.mode);
    $("kpiScanned").textContent   = summary.scanned ?? 0;
    if (summary.mode === "efficiency-ci-guard") {
        const counts = summary.counts || {};
        relabelTile("kpiExploited", "High",   counts.high ?? 0);
        relabelTile("kpiPatched",   "Medium", counts.medium ?? 0);
        relabelTile("kpiValidated", "Verdict", summary.passed ? "PASS" : "FAIL");
        relabelTile("kpiFailed",    "Critical", counts.critical ?? 0);
    } else if (summary.mode === "efficiency") {
        // Re-label tiles for the efficiency mission.
        relabelTile("kpiExploited", "Refactored", summary.refactored ?? 0);
        relabelTile("kpiPatched",   "Verified",   summary.verified ?? 0);
        const dollars = (summary.total_annual_dollars ?? 0).toFixed(2);
        const co2     = Math.round(summary.total_annual_co2_grams ?? 0);
        relabelTile("kpiValidated", "$/year saved", "$" + dollars);
        relabelTile("kpiFailed",    "g CO₂/year",   co2);
    } else {
        relabelTile("kpiExploited", "Exploited",   summary.exploited ?? 0);
        relabelTile("kpiPatched",   "Patched",     summary.patched ?? 0);
        relabelTile("kpiValidated", "Validated",   summary.validated ?? 0);
        relabelTile("kpiFailed",    "Failed",      summary.failed ?? 0);
    }
}

// Update both the visible label (parent .kpi-label) and the value.
function relabelTile(valueId, label, value) {
    const valueEl = $(valueId);
    if (!valueEl) return;
    valueEl.textContent = value;
    const labelEl = valueEl.parentElement && valueEl.parentElement.querySelector(".kpi-label");
    if (labelEl) labelEl.textContent = label;
}

function handleEvent(event) {
    appendLog(event);
    const d = event.data || {};
    switch (event.type) {
        case "scan_start":
            $("kpiMode").textContent = displayMode(d.mode);
            break;
        case "scan_findings_prioritized":
            $("kpiScanned").textContent = d.count ?? 0;
            break;
        case "finding_discovered":
            state.findings.set(d.idx, {
                idx: d.idx,
                fingerprint: d.fingerprint,
                category: d.category,
                severity: d.severity,
                location: d.location,
                title: d.title,
                rule_id: d.rule_id,
                status: d.status || "discovered",
            });
            renderFindings();
            break;
        case "finding_skipped":
        case "agent_done": {
            const f = state.findings.get(d.idx);
            if (f && d.status) {
                f.status = d.status;
                renderFindings();
            }
            break;
        }
        case "finding_completed": {
            const f = state.findings.get(d.idx);
            if (f && d.status) {
                f.status = d.status;
                renderFindings();
            }
            // bump counters opportunistically
            const summary = currentSummaryFromFindings();
            updateKpis(summary);
            break;
        }
        case "chains_discovered": {
            const chains = d.chains || [];
            if (chains.length > 0) {
                const logEl = $("logStream");
                const banner = document.createElement("div");
                banner.className = "chain-banner";
                const items = chains.map(c =>
                    `<li><strong>${escapeHtml(c.title)}</strong> <span class="sev ${c.severity}">${c.severity.toUpperCase()}</span> — ${escapeHtml(c.attack_narrative || "").slice(0, 100)}…</li>`
                ).join("");
                banner.innerHTML = `&#x1F517; <strong>${chains.length} attack chain(s) identified:</strong><ul>${items}</ul>`;
                logEl.appendChild(banner);
                logEl.scrollTop = logEl.scrollHeight;
            }
            break;
        }
        case "ci_verdict": {
            const passed = d.passed;
            const logEl = $("logStream");
            const banner = document.createElement("div");
            banner.className = passed ? "pr-banner" : "chain-banner";
            banner.innerHTML = passed
                ? `&#x2705; <strong>CI guard PASSED</strong> — no blocking efficiency findings in the diff.`
                : `&#x274C; <strong>CI guard FAILED</strong> — a finding met the fail threshold. See findings below.`;
            logEl.appendChild(banner);
            logEl.scrollTop = logEl.scrollHeight;
            break;
        }
        case "history_updated": {
            // Re-render from event data first (instant, no network round-trip).
            renderLifetime({
                verified_count: d.verified_count,
                total_annual_dollars: d.total_annual_dollars,
                total_annual_co2_grams: d.total_annual_co2_grams,
                runs: d.runs,
                by_category: {},
            });
            // Then fetch the full breakdown (category bars) using the repo the
            // scan ran against — passed on the event so the demo path works too.
            if (d.repo) loadLifetimeSavings(d.repo);
            break;
        }
        case "pr_opened": {
            const prUrl = d.url || "";
            if (prUrl) {
                // Inject a clickable PR link into the log after the log line.
                const logEl = $("logStream");
                const banner = document.createElement("div");
                banner.className = "pr-banner";
                banner.innerHTML = `&#x2705; PR opened: <a href="${prUrl}" target="_blank" rel="noopener noreferrer">${prUrl}</a>`;
                logEl.appendChild(banner);
                logEl.scrollTop = logEl.scrollHeight;
            }
            break;
        }
        case "scan_done":
            setStatus("done", "done");
            updateKpis(d.summary);
            $("startBtn").disabled = false;
            $("downloadBtn").disabled = false;
            $("complianceBtn").disabled = false;
            closeEventSource();
            break;
        case "scan_error":
            setStatus("error", "error");
            $("startBtn").disabled = false;
            break;
    }
}

function currentSummaryFromFindings() {
    let exploited = 0, patched = 0, validated = 0, failed = 0;
    for (const f of state.findings.values()) {
        if (f.status === "exploited") exploited++;
        if (f.status === "patched")   patched++;
        if (f.status === "validated") validated++;
        if (f.status === "failed")    failed++;
    }
    return {
        mode: $("kpiMode").textContent,
        scanned: state.findings.size,
        exploited, patched, validated, failed,
    };
}

function closeEventSource() {
    if (state.eventSource) {
        state.eventSource.close();
        state.eventSource = null;
    }
}

function setScanId(id) {
    state.scanId = id;
    try { localStorage.setItem("lastScanId", id); } catch (_) {}
}

// On load: restore last completed scan so download buttons work after refresh.
// Primary source: /api/scans list (server-authoritative).
// Fallback: localStorage for the most recently started scan.
async function restoreLastScan() {
    try {
        const r = await fetch("/api/scans");
        if (!r.ok) return;
        const scans = await r.json();
        // Pick the most-recently finished "done" scan.
        const done = scans.filter(s => s.status === "done")
                          .sort((a, b) => (b.finished_at || "").localeCompare(a.finished_at || ""));
        if (done.length === 0) return;
        const latest = done[0];
        state.scanId = latest.scan_id;
        try { localStorage.setItem("lastScanId", latest.scan_id); } catch (_) {}
        setStatus("done", "done");
        $("downloadBtn").disabled = false;
        $("complianceBtn").disabled = false;
        // Fetch full summary for KPI tiles.
        try {
            const sr = await fetch(`/api/scans/${latest.scan_id}`);
            if (sr.ok) {
                const sd = await sr.json();
                if (sd.summary) updateKpis(sd.summary);
            }
        } catch (_) {}
        appendLog({
            ts: new Date().toISOString(),
            type: "scan_done",
            message: `Restored last scan: ${latest.scan_id} (mode=${latest.mode || "—"})`,
        });
    } catch (_) {}
}

// Show/hide import-specific fields when mode changes.
function onModeChange() {
    const mode = $("mode").value;
    const isEff = mode === "efficiency" || mode === "efficiency-profile" || mode === "efficiency-ci-guard";
    $("sarifFields").style.display      = mode === "import-sarif"      ? "" : "none";
    $("checkmarxFields").style.display  = mode === "import-checkmarx"  ? "" : "none";
    $("efficiencyFields").style.display = (isEff && mode !== "efficiency-ci-guard") ? "" : "none";
    $("ciGuardFields").style.display    = mode === "efficiency-ci-guard" ? "" : "none";
    // Lifetime savings only make sense for efficiency repos.
    if (isEff) loadLifetimeSavings();
    else $("lifetimeCard").style.display = "none";
}

// Toggle GitHub vs Bitbucket PR field groups.
function onPrProviderChange() {
    const p = $("prProvider").value;
    $("githubPrFields").style.display    = p === "github"    ? "" : "none";
    $("bitbucketPrFields").style.display = p === "bitbucket" ? "" : "none";
}

// Fetch + render the cumulative savings ledger for the current repo (P8).
async function loadLifetimeSavings(repoOverride) {
    const repo = repoOverride || $("repoPath").value.trim();
    if (!repo) { $("lifetimeCard").style.display = "none"; return; }
    try {
        const r = await fetch(`/api/efficiency/history?repo=${encodeURIComponent(repo)}`);
        if (!r.ok) { $("lifetimeCard").style.display = "none"; return; }
        const h = await r.json();
        renderLifetime(h);
    } catch (_) { $("lifetimeCard").style.display = "none"; }
}

function renderLifetime(h) {
    if (!h || !h.verified_count) { $("lifetimeCard").style.display = "none"; return; }
    $("lifetimeCard").style.display = "";
    $("ltCount").textContent   = h.verified_count;
    $("ltDollars").textContent = "$" + Number(h.total_annual_dollars || 0).toLocaleString(undefined, { maximumFractionDigits: 2 });
    $("ltCo2").textContent     = Math.round(h.total_annual_co2_grams || 0).toLocaleString();
    $("ltRuns").textContent    = h.runs || 0;
    const byCat = h.by_category || {};
    const rows = Object.entries(byCat)
        .sort((a, b) => (b[1].annual_dollars || 0) - (a[1].annual_dollars || 0))
        .map(([cat, agg]) =>
            `<div class="cat-row"><span class="cat-name">${escapeHtml(cat)}</span>`
            + `<span class="cat-bar-wrap"><span class="cat-bar" style="width:${barPct(agg.annual_dollars, h.total_annual_dollars)}%"></span></span>`
            + `<span class="cat-val">$${Number(agg.annual_dollars || 0).toFixed(0)} · ${agg.count}×</span></div>`)
        .join("");
    $("ltByCategory").innerHTML = rows;
}

function barPct(part, total) {
    if (!total) return 0;
    return Math.max(2, Math.round(100 * (part || 0) / total));
}

function resetScanUI() {
    state.findings.clear();
    renderFindings();
    $("logStream").innerHTML = "";
    updateKpis({ mode: $("mode").value, scanned: 0, exploited: 0, patched: 0, validated: 0, failed: 0 });
    setStatus("starting…", "running");
    $("startBtn").disabled = true;
    $("downloadBtn").disabled = true;
    $("complianceBtn").disabled = true;
    closeEventSource();
}

async function connectAndStream(resp) {
    if (!resp.ok) {
        const txt = await resp.text();
        setStatus("error", "error");
        appendLog({ ts: new Date().toISOString(), type: "scan_error", message: `HTTP ${resp.status}: ${txt}` });
        $("startBtn").disabled = false;
        return;
    }
    const { scan_id } = await resp.json();
    setScanId(scan_id);
    setStatus("running", "running");
    const es = new EventSource(`/api/scans/${scan_id}/events`);
    state.eventSource = es;
    es.onmessage = (e) => {
        try { handleEvent(JSON.parse(e.data)); } catch (err) { console.error(err); }
    };
}

async function startScan(ev) {
    ev.preventDefault();
    const mode = $("mode").value;

    if (mode === "import-sarif") {
        await startSarifImport();
    } else if (mode === "import-checkmarx") {
        await startCheckmarxImport();
    } else {
        await startRegularScan();
    }
}

// Assemble the /api/scans body, including efficiency savings, profile, PR
// provider, and CI-guard fields where relevant.
function buildScanPayload(repo) {
    const mode = $("mode").value;
    const provider = ($("prProvider") || {}).value || "github";
    const payload = {
        repo,
        mode,
        min_severity: $("severity").value,
        max_findings: parseInt($("maxFindings").value, 10),
        github_base_branch: $("githubBaseBranch").value.trim() || "main",
        pr_provider: provider,
    };
    if (provider === "github") {
        payload.github_repo_slug = $("githubRepoSlug").value.trim() || null;
        payload.github_token = $("githubToken").value.trim() || null;
    } else {
        payload.bitbucket_workspace = ($("bbWorkspace") || {}).value.trim() || null;
        payload.bitbucket_repo_slug = ($("bbRepoSlug") || {}).value.trim() || null;
        payload.bitbucket_token = ($("bbToken") || {}).value.trim() || null;
    }
    if (mode === "efficiency" || mode === "efficiency-profile") {
        payload.calls_per_year = parseInt($("effCallsPerYear").value, 10) || 3600000;
        payload.cpu_cost_per_hour_usd = parseFloat($("effCpuCost").value) || null;
        payload.grid_region = $("effGridRegion").value || null;
        const prof = $("effProfileJson").value.trim();
        if (prof) payload.profile_json = prof;
    }
    if (mode === "efficiency-ci-guard") {
        payload.ci_base_ref = $("ciBaseRef").value.trim() || "origin/main";
        payload.ci_fail_severity = $("ciFailSeverity").value;
        const prn = parseInt($("ciPrNumber").value, 10);
        if (prn) payload.ci_pr_number = prn;
    }
    return payload;
}

async function startRegularScan() {
    const repo = $("repoPath").value.trim();
    if (!repo) return;
    resetScanUI();
    let resp;
    try {
        resp = await fetch("/api/scans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(buildScanPayload(repo)),
        });
    } catch (e) {
        setStatus("error", "error");
        appendLog({ ts: new Date().toISOString(), type: "scan_error", message: String(e) });
        $("startBtn").disabled = false;
        return;
    }
    await connectAndStream(resp);
}

async function startSarifImport() {
    const repo = $("repoPath").value.trim();
    const fileInput = $("sarifFile");
    if (!repo) { alert("Please enter the repository path."); return; }
    if (!fileInput.files.length) { alert("Please select a SARIF file."); return; }

    resetScanUI();
    const formData = new FormData();
    formData.append("sarif_file", fileInput.files[0]);
    formData.append("repo", repo);
    formData.append("min_severity", $("severity").value);
    formData.append("max_findings", $("maxFindings").value);
    if ($("githubRepoSlug").value.trim()) formData.append("github_repo_slug", $("githubRepoSlug").value.trim());
    if ($("githubToken").value.trim())    formData.append("github_token", $("githubToken").value.trim());
    formData.append("github_base_branch", $("githubBaseBranch").value.trim() || "main");

    let resp;
    try {
        resp = await fetch("/api/import/sarif", { method: "POST", body: formData });
    } catch (e) {
        setStatus("error", "error");
        appendLog({ ts: new Date().toISOString(), type: "scan_error", message: String(e) });
        $("startBtn").disabled = false;
        return;
    }
    await connectAndStream(resp);
}

async function startCheckmarxImport() {
    const repo = $("repoPath").value.trim();
    if (!repo) { alert("Please enter the local repository path."); return; }
    if (!$("cxUrl").value.trim())      { alert("Please enter the Checkmarx One URL."); return; }
    if (!$("cxTenant").value.trim())   { alert("Please enter the Checkmarx tenant."); return; }
    if (!$("cxClientId").value.trim()) { alert("Please enter the Client ID."); return; }
    if (!$("cxClientSecret").value.trim()) { alert("Please enter the Client Secret."); return; }
    if (!$("cxScanId").value.trim())   { alert("Please enter the Checkmarx Scan ID."); return; }

    resetScanUI();
    let resp;
    try {
        resp = await fetch("/api/import/checkmarx", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                repo,
                checkmarx_url:    $("cxUrl").value.trim(),
                checkmarx_tenant: $("cxTenant").value.trim(),
                client_id:        $("cxClientId").value.trim(),
                client_secret:    $("cxClientSecret").value.trim(),
                scan_id:          $("cxScanId").value.trim(),
                min_severity:     $("severity").value,
                max_findings:     parseInt($("maxFindings").value, 10),
                github_repo_slug: $("githubRepoSlug").value.trim() || null,
                github_token:     $("githubToken").value.trim() || null,
                github_base_branch: $("githubBaseBranch").value.trim() || "main",
            }),
        });
    } catch (e) {
        setStatus("error", "error");
        appendLog({ ts: new Date().toISOString(), type: "scan_error", message: String(e) });
        $("startBtn").disabled = false;
        return;
    }
    await connectAndStream(resp);
}

async function openDrawer(idx) {
    const drawer = $("drawer");
    const body = $("drawerBody");
    const title = $("drawerTitle");
    body.innerHTML = `<p class="dim">Loading…</p>`;
    title.textContent = `Finding #${idx}`;
    drawer.classList.add("open");
    $("drawerBackdrop").classList.add("open");
    drawer.setAttribute("aria-hidden", "false");

    try {
        const r = await fetch(`/api/scans/${state.scanId}/findings/${idx}`);
        if (!r.ok) {
            body.innerHTML = `<p class="dim">Could not load finding (HTTP ${r.status}).</p>`;
            return;
        }
        const f = await r.json();
        body.innerHTML = renderFindingDetail(f);
    } catch (e) {
        body.innerHTML = `<p class="dim">Error: ${escapeHtml(String(e))}</p>`;
    }
}

// Inspect a finding's status + notes to produce a single, prominent banner
// that explains what happened to this finding through the loop. The goal is
// that a reviewer (or hackathon judge) instantly sees the outcome and -- if
// it didn't validate -- WHY, without scrolling to the notes section.
function buildOutcomeBanner(f) {
    const status = (f.status || "").toLowerCase();
    const notes = (f.notes || []).map(String);
    const exploit = f.exploit || {};
    const patch = f.patch || {};
    const refactoring = f.refactoring || {};
    const benchmark = f.benchmark || {};
    const savings = f.savings || {};

    let cls, headline, detail = "";

    // --- Efficiency-mission statuses ---
    if (status === "verified") {
        cls = "ok";
        const dollars = Number(savings.annual_dollars || 0).toFixed(2);
        const co2     = Math.round(Number(savings.annual_co2_grams || 0));
        const speedup = benchmark.runtime_ms_old && benchmark.runtime_ms_new
            ? (benchmark.runtime_ms_old / benchmark.runtime_ms_new).toFixed(1)
            : "?";
        headline = `Verified — ${speedup}× faster, outputs match`;
        detail = `Projected $${dollars} / yr and ${co2.toLocaleString()} g CO₂ / yr saved at the configured call rate.`;
    } else if (status === "refactored") {
        cls = "warn";
        headline = "Refactor proposed — not yet verified";
        detail = "LLM produced refactored code + a benchmark script. Verifier hasn't run yet (or hasn't accepted yet).";
    } else if (status === "benchmarked") {
        cls = "warn";
        headline = "Baseline benchmark captured";
        detail = "We have the original runtime/memory; LLM refactor hasn't run yet.";
    }
    // --- Security-mission statuses ---
    else if (status === "validated") {
        cls = "ok";
        headline = "Validated end-to-end";
        detail = "Tests pass after patch AND the exploit no longer reproduces. Ready to merge.";
    } else if (status === "patched") {
        cls = "warn";
        headline = "Patch applied — not yet revalidated";
        detail = "Healer wrote a syntactically valid fix. Validator did not (yet) confirm it defeats the exploit.";
    } else if (status === "exploited") {
        cls = "warn";
        headline = "Exploit confirmed — no patch yet";
        detail = exploit.actual_signal
            ? `Sandbox returned: ${exploit.actual_signal}`
            : "Attacker reproduced the issue; healer phase did not run or was skipped.";
    } else if (status === "failed") {
        cls = "bad";
        // Find the most informative note to surface as the reason.
        const reasonNote = notes.find(n => /tests failed|exploit still succeeds|syntax check|redeploy|skipped|DIFFERENT output|did NOT improve/i.test(n))
                        || notes[notes.length - 1]
                        || "";
        if (/syntax check/i.test(reasonNote)) {
            headline = "Patch REJECTED — safety net";
            detail = "Healer's proposed patch failed AST validation. File was NOT modified. This is exactly the guard rail you want before LLM-generated code reaches production.";
        } else if (/tests failed/i.test(reasonNote)) {
            headline = "Patch REJECTED — would break callers";
            detail = "Patch applied but the existing regression tests failed. Validator caught a contract-breaking change before merge.";
        } else if (/exploit still succeeds/i.test(reasonNote)) {
            headline = "Patch INSUFFICIENT — exploit still works";
            detail = "Patch applied + tests passed, but replaying the exploit STILL produced EXPLOIT_SUCCESS. The fix didn't actually close the hole.";
        } else if (/DIFFERENT output/i.test(reasonNote)) {
            headline = "Refactor REJECTED — outputs diverged";
            detail = "Refactored function produced different results than the original on the benchmark inputs. File was NOT modified. Output-equivalence is non-negotiable.";
        } else if (/did NOT improve/i.test(reasonNote)) {
            headline = "Refactor REJECTED — no measured speedup";
            detail = "Refactored function ran the same speed (or slower) than the original. Verifier requires a measurable win to accept.";
        } else if (/redeploy/i.test(reasonNote)) {
            headline = "Validator could not redeploy target";
            detail = "Patch applied but the target service failed to restart for the replay step.";
        } else if (/BENCH_RESULT|timed out|TIMEOUT/i.test(reasonNote)) {
            headline = "Benchmark timed out — cannot verify";
            detail = "The original function is so slow that even a single benchmark call exceeded JANUS's 60-second safety limit. A refactoring was generated but JANUS refuses to apply it without measured proof it is both correct AND faster. This protects production from unverified changes.";
        } else {
            headline = "Failed";
            detail = reasonNote || "See Notes below for the specific failure mode.";
        }
    } else if (status === "discovered") {
        cls = "info";
        headline = "Discovered — not yet exercised";
        detail = "Scanner flagged this; downstream agents did not (or could not) act on it.";
    } else {
        return "";
    }

    let body = `<div class="banner ${cls}"><div class="banner-title">${escapeHtml(headline)}</div>`;
    if (detail) body += `<div class="banner-detail">${escapeHtml(detail)}</div>`;
    if (status === "failed" && patch.explanation) {
        body += `<div class="banner-sub"><b>Proposed fix:</b> ${escapeHtml(patch.explanation)}</div>`;
    }
    if (status === "failed" && refactoring.explanation) {
        body += `<div class="banner-sub"><b>Proposed refactor:</b> ${escapeHtml(refactoring.explanation)}</div>`;
    }
    body += `</div>`;
    return body;
}

function renderFindingDetail(f) {
    if (f._partial) {
        return `<p class="dim">Scan still in progress — only summary is available so far.</p>
                <dl class="meta">
                    <dt>Category</dt><dd>${escapeHtml(f.category || "")}</dd>
                    <dt>Severity</dt><dd>${escapeHtml(f.severity || "")}</dd>
                    <dt>Location</dt><dd>${escapeHtml(f.location || "")}</dd>
                    <dt>Rule</dt><dd>${escapeHtml(f.rule_id || "")}</dd>
                </dl>`;
    }
    const loc = f.location || {};
    const exp = f.exploit || {};
    const patch = f.patch || {};
    const refactoring = f.refactoring || {};
    const benchmark = f.benchmark || {};
    const savings = f.savings || {};
    const html = [];

    // Outcome banner first.
    const banner = buildOutcomeBanner(f);
    if (banner) html.push(banner);

    // Meta block. Render exploitability only when present (security-mode findings).
    // Render function_name when present (efficiency-mode findings).
    let metaRows = `
        <dt>Category</dt><dd>${escapeHtml(f.category || "")}</dd>
        <dt>Severity</dt><dd>${escapeHtml(f.severity || "")}</dd>
        <dt>Status</dt><dd>${escapeHtml(f.status || "")}</dd>
        <dt>Location</dt><dd>${escapeHtml(loc.file || "")}:${escapeHtml(loc.start_line || "")}-${escapeHtml(loc.end_line || "")}</dd>
        <dt>Rule</dt><dd>${escapeHtml(f.rule_id || "n/a")}</dd>
    `;
    if (typeof f.exploitability === "number") {
        metaRows += `<dt>Exploitability</dt><dd>${f.exploitability.toFixed(2)}</dd>`;
    }
    if (f.function_name) {
        metaRows += `<dt>Function</dt><dd>${escapeHtml(f.function_name)}</dd>`;
    }
    html.push(`<dl class="meta">${metaRows}</dl>`);

    if (f.description) {
        html.push(`<h4>Description</h4><pre>${escapeHtml(f.description)}</pre>`);
    }
    if (loc.snippet) {
        html.push(`<h4>Code snippet</h4><pre>${escapeHtml(loc.snippet)}</pre>`);
    }

    // ----- Security-mode blocks -----
    if (exp.script) {
        html.push(`<h4>Exploit (executed in sandbox)</h4>`);
        if (exp.payload) html.push(`<p class="dim">Payload: ${escapeHtml(exp.payload)}</p>`);
        if (exp.actual_signal) html.push(`<p class="dim">Signal: ${escapeHtml(exp.actual_signal)}</p>`);
        html.push(`<pre>${escapeHtml(exp.script)}</pre>`);
    }
    if (patch.patched_code) {
        html.push(`<h4>Proposed fix</h4>`);
        if (patch.explanation) html.push(`<p>${escapeHtml(patch.explanation)}</p>`);
        html.push(`<h4>Before</h4><pre>${escapeHtml(patch.original_code || "")}</pre>`);
        html.push(`<h4>After</h4><pre>${escapeHtml(patch.patched_code || "")}</pre>`);
        if (patch.references && patch.references.length) {
            html.push(`<p class="dim">References: ${patch.references.map(escapeHtml).join(", ")}</p>`);
        }
    }

    // ----- Efficiency-mode blocks -----
    if (refactoring.refactored_code) {
        html.push(`<h4>Proposed refactor</h4>`);
        if (refactoring.explanation) html.push(`<p>${escapeHtml(refactoring.explanation)}</p>`);
        html.push(`<h4>Before</h4><pre>${escapeHtml(refactoring.original_code || "")}</pre>`);
        html.push(`<h4>After</h4><pre>${escapeHtml(refactoring.refactored_code)}</pre>`);
        if (refactoring.benchmark_script) {
            html.push(`<h4>Benchmark driver</h4><pre>${escapeHtml(refactoring.benchmark_script)}</pre>`);
        }
        if (refactoring.references && refactoring.references.length) {
            html.push(`<p class="dim">References: ${refactoring.references.map(escapeHtml).join(", ")}</p>`);
        }
    }
    if (benchmark.runtime_ms_old !== undefined && benchmark.runtime_ms_old !== null) {
        const old_ms = Number(benchmark.runtime_ms_old || 0);
        const new_ms = Number(benchmark.runtime_ms_new || 0);
        const speedup = new_ms > 0 ? (old_ms / new_ms) : 0;
        const iters = benchmark.iterations || 0;
        html.push(`<h4>Benchmark</h4>`);
        html.push(`<dl class="meta">
            <dt>Old runtime</dt><dd>${old_ms.toFixed(2)} ms / iter</dd>
            <dt>New runtime</dt><dd>${new_ms.toFixed(2)} ms / iter</dd>
            <dt>Speedup</dt><dd>${speedup.toFixed(1)}×</dd>
            <dt>Iterations</dt><dd>${iters}</dd>
            <dt>Outputs match</dt><dd>${benchmark.outputs_match ? "YES" : "NO"}</dd>
            ${benchmark.inputs_description ? `<dt>Inputs</dt><dd>${escapeHtml(benchmark.inputs_description)}</dd>` : ""}
        </dl>`);
    }
    if (savings.annual_dollars !== undefined && savings.annual_dollars !== null) {
        const dollars = Number(savings.annual_dollars || 0);
        const co2     = Number(savings.annual_co2_grams || 0);
        const calls   = Number(savings.calls_per_year || 0);
        const msPerCall = Number(savings.runtime_saved_ms_per_call || 0);
        html.push(`<h4>Projected savings</h4>`);
        const memMb = Number(savings.memory_saved_mb_per_call || 0);
        const region = savings.grid_region ? ` (${savings.grid_region})` : "";
        html.push(`<dl class="meta">
            <dt>Per call saved</dt><dd>${msPerCall.toFixed(2)} ms</dd>
            ${memMb > 0 ? `<dt>Memory saved / call</dt><dd>${memMb.toFixed(3)} MB</dd>` : ""}
            <dt>Calls / year (assumed)</dt><dd>${calls.toLocaleString()}</dd>
            <dt>$ saved / year</dt><dd>$${dollars.toFixed(2)}</dd>
            <dt>CO₂ saved / year${region}</dt><dd>${Math.round(co2).toLocaleString()} g</dd>
        </dl>`);
        if (savings.assumption_note) {
            html.push(`<p class="dim">${escapeHtml(savings.assumption_note)}</p>`);
        }
    }

    if (f.notes && f.notes.length) {
        html.push(`<h4>Notes</h4><pre>${f.notes.map(escapeHtml).join("\n")}</pre>`);
    }
    return html.join("");
}

function closeDrawer() {
    $("drawer").classList.remove("open");
    $("drawer").setAttribute("aria-hidden", "true");
    $("drawerBackdrop").classList.remove("open");
}

function escapeHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

async function startEfficiencyDemo() {
    state.findings.clear();
    renderFindings();
    $("logStream").innerHTML = "";
    updateKpis({ mode: "efficiency", scanned: 0, exploited: 0, patched: 0, validated: 0, failed: 0 });
    setStatus("starting efficiency demo…", "running");
    $("startBtn").disabled = true;
    $("demoDotnetBtn").disabled = true;
    $("efficiencyBtn").disabled = true;
    $("downloadBtn").disabled = true;
    $("complianceBtn").disabled = true;
    closeEventSource();
    appendLog({
        ts: new Date().toISOString(),
        type: "scan_start",
        message: "Demo: profile -> refactor -> verify loop on the seeded inefficient target",
    });
    let resp;
    try {
        resp = await fetch("/api/scans/demo-efficiency", { method: "POST" });
    } catch (e) {
        setStatus("error", "error");
        appendLog({ ts: new Date().toISOString(), type: "scan_error", message: String(e) });
        $("startBtn").disabled = false; $("demoDotnetBtn").disabled = false; $("efficiencyBtn").disabled = false;
        return;
    }
    if (!resp.ok) {
        const txt = await resp.text();
        setStatus("error", "error");
        appendLog({ ts: new Date().toISOString(), type: "scan_error",
                    message: `HTTP ${resp.status}: ${txt}` });
        $("startBtn").disabled = false; $("demoDotnetBtn").disabled = false; $("efficiencyBtn").disabled = false;
        return;
    }
    const { scan_id } = await resp.json();
    setScanId(scan_id);
    setStatus("running", "running");
    const es = new EventSource(`/api/scans/${scan_id}/events`);
    state.eventSource = es;
    es.onmessage = (e) => {
        try {
            const ev = JSON.parse(e.data);
            handleEvent(ev);
            if (ev.type === "scan_done" || ev.type === "scan_error") {
                $("startBtn").disabled = false;
                $("demoDotnetBtn").disabled = false;
                $("efficiencyBtn").disabled = false;
            }
        } catch (err) { console.error(err); }
    };
}

async function startSecurityDotnetDemo() {
    const allBtns = ["startBtn","demoDotnetBtn","demoSecDotnetBtn","efficiencyBtn","effDotnetBtn"];
    const reenable = () => allBtns.forEach(id => { if ($(id)) $(id).disabled = false; });
    state.findings.clear(); renderFindings();
    $("logStream").innerHTML = "";
    updateKpis({ mode: "full", scanned: 0, exploited: 0, patched: 0, validated: 0, failed: 0 });
    setStatus("starting .NET security demo…", "running");
    allBtns.forEach(id => { if ($(id)) $(id).disabled = true; });
    $("downloadBtn").disabled = true; $("complianceBtn").disabled = true;
    closeEventSource();
    appendLog({ ts: new Date().toISOString(), type: "scan_start",
        message: "Demo: .NET security — 4 PCI-DSS findings (3 validated + 1 failed)" });
    let resp;
    try { resp = await fetch("/api/scans/demo-security-dotnet", { method: "POST" }); }
    catch (e) { setStatus("error","error"); appendLog({ts:new Date().toISOString(),type:"scan_error",message:String(e)}); reenable(); return; }
    if (!resp.ok) { const t=await resp.text(); setStatus("error","error"); appendLog({ts:new Date().toISOString(),type:"scan_error",message:`HTTP ${resp.status}: ${t}`}); reenable(); return; }
    const { scan_id } = await resp.json(); setScanId(scan_id); setStatus("running","running");
    const es = new EventSource(`/api/scans/${scan_id}/events`); state.eventSource = es;
    es.onmessage = (e) => { try { const ev=JSON.parse(e.data); handleEvent(ev); if(ev.type==="scan_done"||ev.type==="scan_error") reenable(); } catch(err){console.error(err);} };
}

async function startEfficiencyDotnetDemo() {
    const allBtns = ["startBtn","demoDotnetBtn","demoSecDotnetBtn","efficiencyBtn","effDotnetBtn"];
    const reenable = () => allBtns.forEach(id => { if ($(id)) $(id).disabled = false; });
    state.findings.clear(); renderFindings();
    $("logStream").innerHTML = "";
    updateKpis({ mode: "efficiency", scanned: 0, exploited: 0, patched: 0, validated: 0, failed: 0 });
    setStatus("starting .NET efficiency demo…", "running");
    allBtns.forEach(id => { if ($(id)) $(id).disabled = true; });
    $("downloadBtn").disabled = true; $("complianceBtn").disabled = true;
    closeEventSource();
    appendLog({ ts: new Date().toISOString(), type: "scan_start",
        message: "Demo: .NET efficiency — 3 C# anti-patterns (2 verified + 1 failed)" });
    let resp;
    try { resp = await fetch("/api/scans/demo-efficiency-dotnet", { method: "POST" }); }
    catch (e) { setStatus("error","error"); appendLog({ts:new Date().toISOString(),type:"scan_error",message:String(e)}); reenable(); return; }
    if (!resp.ok) { const t=await resp.text(); setStatus("error","error"); appendLog({ts:new Date().toISOString(),type:"scan_error",message:`HTTP ${resp.status}: ${t}`}); reenable(); return; }
    const { scan_id } = await resp.json(); setScanId(scan_id); setStatus("running","running");
    const es = new EventSource(`/api/scans/${scan_id}/events`); state.eventSource = es;
    es.onmessage = (e) => { try { const ev=JSON.parse(e.data); handleEvent(ev); if(ev.type==="scan_done"||ev.type==="scan_error") reenable(); } catch(err){console.error(err);} };
}

async function startDotnetDemoLoop() {
    // Full attack -> patch -> validate loop against the seeded ASP.NET Core target.
    const demoBtns = ["startBtn", "demoDotnetBtn", "efficiencyBtn"];
    const reenable = () => demoBtns.forEach((id) => { $(id).disabled = false; });

    state.findings.clear();
    renderFindings();
    $("logStream").innerHTML = "";
    updateKpis({ mode: "full", scanned: 0, exploited: 0, patched: 0, validated: 0, failed: 0 });
    setStatus("starting security demo…", "running");
    demoBtns.forEach((id) => { $(id).disabled = true; });
    $("downloadBtn").disabled = true;
    $("complianceBtn").disabled = true;
    closeEventSource();
    appendLog({
        ts: new Date().toISOString(),
        type: "scan_start",
        message: "Demo: full attack -> patch -> validate loop on the seeded payments-domain target (~3-5 min)",
    });
    // Pick up GitHub PR fields from the form (if filled in).
    const ghSlug  = ($("githubRepoSlug")  || {}).value || "";
    const ghToken = ($("githubToken")     || {}).value || "";
    const ghBase  = ($("githubBaseBranch")|| {}).value || "main";
    const body = JSON.stringify({
        github_repo_slug:   ghSlug  || null,
        github_token:       ghToken || null,
        github_base_branch: ghBase,
    });
    if (ghSlug) {
        appendLog({ ts: new Date().toISOString(), type: "scan_start",
                    message: `GitHub PR enabled -> ${ghSlug} (branch: ${ghBase})` });
    }
    let resp;
    try {
        resp = await fetch("/api/scans/demo-security", { method: "POST",
            headers: { "Content-Type": "application/json" }, body });
    } catch (e) {
        setStatus("error", "error");
        appendLog({ ts: new Date().toISOString(), type: "scan_error", message: String(e) });
        reenable();
        return;
    }
    if (!resp.ok) {
        const txt = await resp.text();
        setStatus("error", "error");
        appendLog({ ts: new Date().toISOString(), type: "scan_error",
                    message: `HTTP ${resp.status}: ${txt}` });
        reenable();
        return;
    }
    const { scan_id } = await resp.json();
    setScanId(scan_id);
    setStatus("running", "running");
    const es = new EventSource(`/api/scans/${scan_id}/events`);
    state.eventSource = es;
    es.onmessage = (e) => {
        try { handleEvent(JSON.parse(e.data)); } catch (err) { console.error(err); }
    };
    es.addEventListener("message", (e) => {
        try {
            const ev = JSON.parse(e.data);
            if (ev.type === "scan_done" || ev.type === "scan_error") reenable();
        } catch {}
    });
}

document.addEventListener("DOMContentLoaded", () => {
    restoreLastScan();
    $("scanForm").addEventListener("submit", startScan);
    $("mode").addEventListener("change", onModeChange);
    if ($("prProvider")) $("prProvider").addEventListener("change", onPrProviderChange);
    // Refresh the lifetime card when the repo path changes in an efficiency mode.
    $("repoPath").addEventListener("change", () => {
        const m = $("mode").value;
        if (m === "efficiency" || m === "efficiency-profile" || m === "efficiency-ci-guard") loadLifetimeSavings();
    });
    $("demoDotnetBtn").addEventListener("click", startSecurityDotnetDemo);
    $("efficiencyBtn").addEventListener("click", startEfficiencyDotnetDemo);
    $("drawerClose").addEventListener("click", closeDrawer);
    $("drawerBackdrop").addEventListener("click", closeDrawer);
    $("downloadBtn").addEventListener("click", async () => {
        if (!state.scanId) return;
        const url = `/api/scans/${state.scanId}/report?download=true`;
        try {
            const r = await fetch(url);
            if (!r.ok) {
                const txt = await r.text();
                appendLog({ ts: new Date().toISOString(), type: "scan_error",
                            message: `Download failed (HTTP ${r.status}): ${txt}` });
                return;
            }
            const blob = await r.blob();
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = `report-${state.scanId}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(a.href);
        } catch (e) {
            appendLog({ ts: new Date().toISOString(), type: "scan_error",
                        message: `Download failed: ${e}` });
        }
    });

    $("complianceBtn").addEventListener("click", async () => {
        if (!state.scanId) return;
        const url = `/api/scans/${state.scanId}/compliance?format=html`;
        try {
            const r = await fetch(url);
            if (!r.ok) {
                appendLog({ ts: new Date().toISOString(), type: "scan_error",
                            message: `Compliance report unavailable (HTTP ${r.status})` });
                return;
            }
            const blob = await r.blob();
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = `compliance-${state.scanId}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(a.href);
        } catch (e) {
            appendLog({ ts: new Date().toISOString(), type: "scan_error",
                        message: `Compliance report failed: ${e}` });
        }
    });
});

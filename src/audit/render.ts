// Renderers for audit reports: terminal text, Markdown (GitHub step summaries), HTML, badge.

import type { AuditReport, CheckStatus, ProbeResult, Verdict } from "./run.js";

const VERDICT_TEXT: Record<AuditReport["verdict"], string> = {
  ready: "Ready for AI agents",
  "partly-ready": "Partly ready for AI agents",
  "not-ready": "Not ready for AI agents",
};

const OUTCOME_TEXT: Record<Verdict, string> = {
  admitted: "admitted",
  turned_away: "turned away",
  challenged: "challenged",
  rate_limited: "rate limited",
  not_found: "not found",
  error: "no response",
  other: "other",
};

const MARK: Record<CheckStatus, string> = { pass: "✓", warn: "!", fail: "✕", skip: "–", info: "i" };
const WORD: Record<CheckStatus, string> = { pass: "Pass", warn: "Needs work", fail: "Fail", skip: "Not tested", info: "Note" };

export function badgeUrl(report: AuditReport): string {
  const color = report.score >= 85 ? "brightgreen" : report.score >= 60 ? "yellow" : "red";
  return `https://img.shields.io/badge/agent--ready-${report.score}%2F100-${color}`;
}

function hostOf(report: AuditReport): string {
  return new URL(report.target).host;
}

// ------------------------------------------------------------------ terminal

export function renderText(report: AuditReport, opts: { color?: boolean } = {}): string {
  const c = opts.color ?? false;
  const paint = (code: string, s: string) => (c ? `\x1b[${code}m${s}\x1b[0m` : s);
  const bold = (s: string) => paint("1", s);
  const dim = (s: string) => paint("2", s);
  const tone: Record<CheckStatus, (s: string) => string> = {
    pass: (s) => paint("32", s),
    warn: (s) => paint("33", s),
    fail: (s) => paint("31", s),
    skip: dim,
    info: (s) => paint("36", s),
  };
  const out: string[] = [];
  out.push("");
  out.push(`${bold("agent-doorman")} ${dim(`v${report.tool.version}`)}  ${report.target}  ${dim(`(${report.mode})`)}`);
  out.push("");
  if (report.probes.length) {
    out.push(bold("Door test"));
    const width = Math.max(...report.probes.map((p) => p.label.length), 10);
    let lastPath = "";
    for (const p of report.probes) {
      if (p.path !== lastPath) {
        out.push(`  ${dim(p.path)}`);
        lastPath = p.path;
      }
      const note = p.concern ? `  ${tone[p.concern.level](`${MARK[p.concern.level]} ${p.concern.note}`)}` : "";
      out.push(`    ${p.label.padEnd(width)}  ${String(p.status ?? "---").padStart(3)}  ${OUTCOME_TEXT[p.verdict].padEnd(12)}${note}`);
    }
    out.push("");
  }
  const sc = report.score >= 85 ? tone.pass : report.score >= 60 ? tone.warn : tone.fail;
  out.push(`${bold("Score")} ${sc(bold(String(report.score)))}/100  ${VERDICT_TEXT[report.verdict]}`);
  out.push("");
  for (const cat of report.categories) {
    out.push(`${bold(cat.title)}  ${cat.score === null ? dim("not scored") : `${cat.score}/100`}`);
    for (const ch of cat.checks) {
      out.push(`  ${tone[ch.status](MARK[ch.status])} ${ch.title}: ${ch.summary}`);
      for (const d of ch.details.slice(0, 5)) out.push(`      ${dim(d)}`);
    }
    out.push("");
  }
  if (report.fixes.length) {
    out.push(bold("Fix first"));
    report.fixes.slice(0, 5).forEach((f, i) => out.push(`  ${i + 1}. ${f.title}: ${f.fix}`));
    out.push("");
  }
  for (const n of report.notes) out.push(dim(`Note: ${n}`));
  out.push("");
  return out.join("\n");
}

// ------------------------------------------------------------------ markdown

function mdEscape(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/</g, "&lt;");
}

export function renderMarkdown(report: AuditReport): string {
  const out: string[] = [];
  out.push(`## Agent readiness: ${hostOf(report)}`);
  out.push("");
  out.push(`![agent-ready](${badgeUrl(report)})`);
  out.push("");
  out.push(`**${report.score}/100**, ${VERDICT_TEXT[report.verdict].toLowerCase()} (${report.mode} audit, agent-doorman ${report.tool.version}).`);
  out.push("");
  if (report.probes.length) {
    out.push("### Door test");
    out.push("");
    out.push("| Page | Visitor | HTTP | Outcome | Problem |");
    out.push("|---|---|---|---|---|");
    for (const p of report.probes) {
      const problem = p.concern ? `${MARK[p.concern.level]} ${mdEscape(p.concern.note)}` : "";
      out.push(`| \`${mdEscape(p.path)}\` | ${mdEscape(p.label)} | ${p.status ?? "–"} | ${OUTCOME_TEXT[p.verdict]} | ${problem} |`);
    }
    out.push("");
  }
  out.push("### Checks");
  out.push("");
  out.push("| Area | Check | Result | Finding |");
  out.push("|---|---|---|---|");
  for (const cat of report.categories) {
    for (const ch of cat.checks) {
      out.push(`| ${cat.title} | ${mdEscape(ch.title)} | ${MARK[ch.status]} ${WORD[ch.status]} | ${mdEscape(ch.summary)} |`);
    }
  }
  out.push("");
  if (report.fixes.length) {
    out.push("### Fix first");
    out.push("");
    report.fixes.slice(0, 5).forEach((f, i) => out.push(`${i + 1}. **${mdEscape(f.title)}.** ${mdEscape(f.fix)}`));
    out.push("");
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------- html

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function doorBody(probes: ProbeResult[]): string {
  const paths = [...new Set(probes.map((p) => p.path))];
  return paths
    .map((path) => {
      const rows = probes
        .filter((p) => p.path === path)
        .map((p) => {
          const concern = p.concern
            ? `<span class="concern ${p.concern.level}"><span aria-hidden="true">${MARK[p.concern.level]}</span> ${esc(p.concern.note)}</span>`
            : "";
          return `<tr class="${p.concern ? `flag-${p.concern.level}` : ""}"><td>${esc(p.label)}</td><td class="num">${p.status ?? "–"}</td><td><span class="outcome">${OUTCOME_TEXT[p.verdict]}</span>${concern}</td></tr>`;
        })
        .join("\n");
      return `<tbody><tr class="group"><th scope="rowgroup" colspan="3">${esc(path)}</th></tr>\n${rows}</tbody>`;
    })
    .join("\n");
}

export function renderHtml(report: AuditReport): string {
  const host = hostOf(report);
  const when = new Date(report.auditedAt).toUTCString();
  const tone = report.score >= 85 ? "pass" : report.score >= 60 ? "warn" : "fail";
  const door = report.probes.length
    ? `<section aria-labelledby="door-h">
  <h2 id="door-h">Who got in</h2>
  <p class="lede">The same page, requested by different kinds of visitor. Claims without proof should not get further than a script, and a fake signature should never help. Problems are marked.</p>
  <table class="door">
    <thead><tr><th scope="col">Visitor</th><th scope="col" class="num">HTTP</th><th scope="col">Outcome</th></tr></thead>
    ${doorBody(report.probes)}
  </table>
</section>`
    : `<section aria-labelledby="door-h">
  <h2 id="door-h">Who got in</h2>
  <p class="lede">The door test was not run. Run <code>agent-doorman audit ${esc(report.target)} --active</code> against a site you operate to see how it treats claimed, forged and verified agents.</p>
</section>`;
  const fixes = report.fixes.length
    ? `<section aria-labelledby="fix-h">
  <h2 id="fix-h">Fix first</h2>
  <ol class="fixes">${report.fixes
    .slice(0, 5)
    .map((f) => `<li><strong>${esc(f.title)}.</strong> ${esc(f.fix)}</li>`)
    .join("")}</ol>
</section>`
    : "";
  const cats = report.categories
    .map(
      (cat) => `<section class="cat" aria-labelledby="cat-${cat.id}">
  <div class="cat-head"><h3 id="cat-${cat.id}">${esc(cat.title)}</h3><span class="cat-score">${cat.score === null ? "not scored" : `${cat.score}<small>/100</small>`}</span></div>
  <ul class="checks">${cat.checks
    .map(
      (ch) => `<li class="check ${ch.status}">
    <span class="mark" aria-hidden="true">${MARK[ch.status]}</span>
    <div><p class="ct"><span class="sr">${WORD[ch.status]}: </span>${esc(ch.title)}</p><p class="cs">${esc(ch.summary)}</p>${
      ch.details.length
        ? `<details><summary>Details</summary><ul>${ch.details.map((d) => `<li>${esc(d)}</li>`).join("")}</ul></details>`
        : ""
    }</div>
  </li>`,
    )
    .join("")}</ul>
</section>`,
    )
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Door report for ${esc(host)}</title>
<style>
:root{--ink:#1c2541;--brass:#b5893b;--paper:#f6f7f9;--surface:#ffffff;--text:#2e3442;--muted:#646b7d;--rule:#d9dde5;--pass:#2b7a57;--warn:#9a5f00;--fail:#b42318;}
@media (prefers-color-scheme:dark){:root{--ink:#e4e9f5;--brass:#d4a957;--paper:#121726;--surface:#1a2133;--text:#d6dcea;--muted:#9aa3b8;--rule:#2c3550;--pass:#5cc497;--warn:#e0a640;--fail:#f07a6e;}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--text);font:16px/1.55 ui-sans-serif,"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;font-variant-numeric:tabular-nums}
main{max-width:880px;margin:0 auto;padding:48px 24px 72px}
a{color:inherit}
code{font-size:.92em;background:var(--surface);border:1px solid var(--rule);border-radius:4px;padding:1px 5px}
.plaque{display:inline-block;border:3px double var(--brass);padding:14px 22px 12px;margin:0 0 28px;background:var(--surface)}
.plaque h1{margin:0;font-size:clamp(1.9rem,5vw,3rem);line-height:1.05;letter-spacing:-.02em;color:var(--ink);font-weight:700;word-break:break-word}
.plaque p{margin:6px 0 0;color:var(--muted);font-size:.95rem}
.verdict{font-size:1.35rem;line-height:1.35;margin:0 0 8px;color:var(--ink);max-width:36ch}
.verdict b{color:var(--${tone})}
.meta{color:var(--muted);font-size:.9rem;margin:0 0 40px}
h2{font-size:1.25rem;color:var(--ink);margin:48px 0 8px}
h3{font-size:1.05rem;color:var(--ink);margin:0}
.lede{margin:0 0 16px;max-width:68ch;color:var(--muted)}
table.door{border-collapse:collapse;width:100%;background:var(--surface);border:1px solid var(--rule)}
.door th,.door td{text-align:left;padding:9px 12px;border-top:1px solid var(--rule);vertical-align:top}
.door thead th{border-top:0;font-weight:600;color:var(--muted);font-size:.9rem}
.door tr.group th{color:var(--ink);font-weight:700;background:var(--paper);border-top:2px solid var(--rule);padding-top:12px}
.door .num{text-align:right;width:4em}
.outcome{color:var(--ink)}
.concern{display:block;font-size:.9rem;font-weight:600;margin-top:2px}
.concern.fail{color:var(--fail)}.concern.warn{color:var(--warn)}
.door tr.flag-fail td:first-child{box-shadow:inset 3px 0 0 var(--fail)}
.door tr.flag-warn td:first-child{box-shadow:inset 3px 0 0 var(--warn)}
.fixes{padding-left:1.4em;margin:0;max-width:72ch}
.fixes li{margin:0 0 10px}
.cat{margin:28px 0 0;padding-top:20px;border-top:2px solid var(--ink)}
.cat-head{display:flex;justify-content:space-between;align-items:baseline;gap:16px}
.cat-score{font-weight:700;color:var(--ink);font-size:1.1rem}
.cat-score small{font-weight:400;color:var(--muted)}
.checks{list-style:none;margin:12px 0 0;padding:0}
.check{display:grid;grid-template-columns:1.8em 1fr;gap:4px 10px;padding:10px 0;border-bottom:1px solid var(--rule)}
.check:last-child{border-bottom:0}
.mark{font-weight:700;text-align:center;line-height:1.55}
.check.pass .mark{color:var(--pass)}.check.warn .mark{color:var(--warn)}.check.fail .mark{color:var(--fail)}.check.skip .mark,.check.info .mark{color:var(--muted)}
.ct{margin:0;font-weight:600;color:var(--ink)}
.cs{margin:2px 0 0;max-width:72ch}
details{margin-top:6px;color:var(--muted);font-size:.93rem}
summary{cursor:pointer}
summary:focus-visible,a:focus-visible{outline:2px solid var(--brass);outline-offset:2px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
footer{margin-top:56px;color:var(--muted);font-size:.9rem;max-width:72ch}
footer p{margin:0 0 8px}
@media (max-width:560px){main{padding:28px 16px 48px}.plaque{padding:10px 14px}.door th,.door td{padding:8px 8px}}
</style>
</head>
<body>
<main>
<header>
  <div class="plaque"><h1>${esc(host)}</h1><p>Door report</p></div>
  <p class="verdict">${VERDICT_TEXT[report.verdict]}. Score <b>${report.score}</b> of 100.</p>
  <p class="meta">${report.mode === "active" ? "Active audit with door test" : "Passive audit"}, ${esc(when)}.</p>
</header>
${door}
${fixes}
<section aria-labelledby="checks-h">
<h2 id="checks-h">All checks</h2>
${cats}
</section>
<footer>
${report.notes.map((n) => `<p>${esc(n)}</p>`).join("\n")}
<p>Generated by agent-doorman ${esc(report.tool.version)}.</p>
</footer>
</main>
</body>
</html>
`;
}

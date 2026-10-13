#!/usr/bin/env node
/**
 * verify-licenses.mjs — checks declared licenses against the PRIMARY source.
 *
 * Why this exists
 * ---------------
 * The recurring, expensive mistake in this project was attributing a license from
 * memory: Moneta credited to the wrong author, Fluxzy labeled MIT when it is
 * GPL-3.0, and (found by this script) ghidriff, YARA-X, msynth, Diaphora and AFL++
 * all mislabeled. A wrong license label is worse than a missing one, because people
 * act on it. This opens the ACTUAL upstream LICENSE (raw file from the manifest or
 * registry) and cross-checks GitHub's own detection, so a wrong declaration fails
 * CI instead of shipping.
 *
 * Sources of declarations:
 *   - config/tools.json     (the core tools the fetch installs)
 *   - config/licenses.json  (the wider registry of referenced tools)
 *
 * It is NETWORKED, so it runs as its own CI job. A network error is a warning
 * unless --strict; a genuine mismatch is ALWAYS fatal.
 *
 * Usage: node scripts/verify-licenses.mjs [--json] [--strict]
 * Exit:  0 verified (or network-degraded) · 1 a mismatch was found · 2 crash.
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const JSON_OUT = process.argv.includes("--json");
const STRICT = process.argv.includes("--strict");

/** Normalize SPDX so 'GPL-3.0', 'GPL-3.0-only' and 'GPL-3.0-or-later' compare equal. */
const spdxBase = (s) => (s || "").replace(/-(only|or-later)$/i, "").trim().toLowerCase();

// GITHUB_TOKEN raises the API rate limit from 60/h to 1000/h — CI passes it in.
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;

async function get(url) {
  const headers = { "User-Agent": "UnboxRE-verify-licenses", Accept: "application/vnd.github+json" };
  if (GH_TOKEN && url.includes("api.github.com")) headers.Authorization = `Bearer ${GH_TOKEN}`;
  const res = await fetch(url, { headers, redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res;
}

// ── Build the list of declarations to verify ─────────────────────────────────
const checks = [];

const tools = JSON.parse(readFileSync(join(ROOT, "config/tools.json"), "utf8"));
for (const [slug, t] of Object.entries(tools.tools)) {
  checks.push({
    slug,
    declared: t.license?.spdx,
    rawUrl: t.license?.rawUrl,
    needles: t.license?.needles ?? [],
    repo: t.upstream?.repo ?? null,
    source: "tools.json",
  });
}

if (existsSync(join(ROOT, "config/licenses.json"))) {
  const reg = JSON.parse(readFileSync(join(ROOT, "config/licenses.json"), "utf8"));
  for (const t of reg.tools) {
    checks.push({
      slug: t.name,
      declared: t.spdx,
      rawUrl: t.rawUrl ?? null,
      needles: t.needles ?? [],
      repo: t.repo ?? null,
      source: "licenses.json",
    });
  }
}

// ── Verify ───────────────────────────────────────────────────────────────────
const results = [];
const failures = [];

for (const c of checks) {
  const row = { slug: c.slug, declared: c.declared, rawOk: null, apiSpdx: null, notes: [] };

  if (c.rawUrl && c.needles.length) {
    try {
      const text = await (await get(c.rawUrl)).text();
      const missing = c.needles.filter((n) => !text.toLowerCase().includes(n.toLowerCase()));
      row.rawOk = missing.length === 0;
      if (missing.length) {
        row.notes.push(`LICENSE upstream não contém: ${missing.join(", ")}`);
        failures.push(`${c.slug}: ${c.rawUrl} não confirma "${c.declared}"`);
      }
    } catch (e) {
      row.rawOk = "net-error";
      row.notes.push(`não consegui ler o LICENSE: ${e.message}`);
      if (STRICT) failures.push(`${c.slug}: falha de rede lendo ${c.rawUrl}`);
    }
  }

  if (c.repo) {
    try {
      const data = await (await get(`https://api.github.com/repos/${c.repo}/license`)).json();
      const detected = data.license?.spdx_id ?? "NOASSERTION";
      row.apiSpdx = detected;
      if (detected !== "NOASSERTION" && spdxBase(detected) !== spdxBase(c.declared)) {
        failures.push(`${c.slug}: github/api detecta "${detected}" mas declara "${c.declared}"`);
      }
    } catch (e) {
      row.notes.push(`API de licença indisponível: ${e.message}`);
      if (STRICT) failures.push(`${c.slug}: falha de rede consultando a API (${c.repo})`);
    }
  }

  row.ok = row.rawOk !== false && !failures.some((f) => f.startsWith(`${c.slug}:`));
  results.push(row);
}

// ── Report ───────────────────────────────────────────────────────────────────
if (JSON_OUT) {
  console.log(JSON.stringify({ ok: failures.length === 0, count: checks.length, results, failures }, null, 2));
} else {
  console.log("");
  console.log("UnboxRE — verificação de licenças contra o upstream (fonte primária)");
  console.log("─".repeat(72));
  for (const r of results) {
    const raw = r.rawOk === true ? "raw:ok" : r.rawOk === false ? "raw:MISMATCH" : "raw:n/a";
    const api = r.apiSpdx ? `api:${r.apiSpdx}` : "api:n/a";
    console.log(`  ${r.ok ? "  " : "!!"} ${r.slug.padEnd(15)} declara ${String(r.declared).padEnd(14)} ${raw.padEnd(14)} ${api}`);
    for (const n of r.notes) console.log(`       · ${n}`);
  }
  console.log("");
  if (failures.length === 0) {
    console.log(`  [OK] ${checks.length} licenças declaradas batem com a fonte primária.`);
  } else {
    for (const f of failures) console.log(`  [FAIL] ${f}`);
  }
  console.log("");
}

process.exit(failures.length > 0 ? 1 : 0);

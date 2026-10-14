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
 * Host instável (retry limitado, medido em 2026-10-14)
 * ------------------------------------------------
 * O job ficou vermelho três vezes seguidas por causa de UM host de terceiro
 * (`http://www.rohitab.com/apimonitor`, a fonte primária do API Monitor) que responde
 * 503/erro de conexão de forma intermitente — e passa no re-run do mesmo SHA. Um gate
 * que depende de um site instável precisa tolerar a instabilidade: cada requisição é
 * tentada até 4 vezes, com espera de 1 s → 2 s → 4 s, e timeout de 20 s por tentativa
 * (sem timeout, um host pendurado trava o CI).
 *
 * O que o retry NÃO faz (isto é o ponto): ele não afrouxa verificação nenhuma.
 *   · só repete erro de REDE e status transitório (408, 425, 429, 5xx, 522, 524, 599);
 *   · 404/403/401 são RESPOSTA do servidor — repetir não mudaria nada, então não repete;
 *   · um LICENSE que responde e não contém os `needles` reprova na PRIMEIRA resposta
 *     (mismatch de licença nunca é confundido com falha de rede);
 *   · esgotadas as tentativas, o comportamento é o de antes: falha fatal sob --strict.
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

// Retry limitado para host instável: 1 tentativa + 3 retries (1 s, 2 s, 4 s).
const RETRY_ATTEMPTS = 4;
const RETRY_DELAYS_MS = [1000, 2000, 4000];
const REQUEST_TIMEOUT_MS = 20000;
// Status que podem passar sozinhos: 408 timeout, 425 too early, 429 rate limit, 5xx e os
// 5xx de borda do Cloudflare. 404/401/403 NÃO entram: são resposta, não instabilidade.
const RETRY_STATUS = new Set([408, 425, 429, 500, 502, 503, 504, 522, 524, 599]);
const retries = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Normalize SPDX so 'GPL-3.0', 'GPL-3.0-only' and 'GPL-3.0-or-later' compare equal. */
const spdxBase = (s) => (s || "").replace(/-(only|or-later)$/i, "").trim().toLowerCase();

// GITHUB_TOKEN raises the API rate limit from 60/h to 1000/h — CI passes it in.
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;

async function getOnce(url) {
  const headers = { "User-Agent": "UnboxRE-verify-licenses", Accept: "application/vnd.github+json" };
  if (GH_TOKEN && url.includes("api.github.com")) headers.Authorization = `Bearer ${GH_TOKEN}`;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { headers, redirect: "follow", signal: ac.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * GET com retry limitado. `notes` (opcional) recebe o registro das tentativas, para a
 * evidência mostrar que houve instabilidade e que ela foi absorvida — nunca escondida.
 */
async function get(url, notes) {
  for (let attempt = 1; ; attempt++) {
    let res = null;
    let err = null;
    try {
      res = await getOnce(url);
    } catch (e) {
      err = e?.name === "AbortError" ? new Error(`sem resposta em ${REQUEST_TIMEOUT_MS / 1000}s`) : e;
    }
    if (res?.ok) return res;
    const status = res ? res.status : null;
    const transient = status === null || RETRY_STATUS.has(status);
    if (!transient || attempt >= RETRY_ATTEMPTS) throw new Error(status ? `HTTP ${status}` : err.message);
    const wait = RETRY_DELAYS_MS[Math.min(attempt - 1, RETRY_DELAYS_MS.length - 1)];
    retries.push({ url, attempt, status, message: status ? `HTTP ${status}` : err.message, waitMs: wait });
    notes?.push(`tentativa ${attempt}/${RETRY_ATTEMPTS} falhou (${status ? `HTTP ${status}` : err.message}) — repetindo em ${wait / 1000}s`);
    await sleep(wait);
  }
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
      const text = await (await get(c.rawUrl, row.notes)).text();
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
      const data = await (await get(`https://api.github.com/repos/${c.repo}/license`, row.notes)).json();
      const detected = data.license?.spdx_id ?? "NOASSERTION";
      row.apiSpdx = detected;
      if (detected !== "NOASSERTION" && spdxBase(detected) !== spdxBase(c.declared)) {
        failures.push(`${c.slug}: github/api detecta "${detected}" mas declara "${c.declared}"`);
      }
    } catch (e) {
      // Um 404 NÃO é falha de rede: é o GitHub dizendo que não detecta um arquivo
      // de licença no branch default (ex.: capstone-engine/capstone, cujo
      // LICENSE.TXT só existe em master/v5). Nesse caso a evidência primária é o
      // LICENSE bruto — e é ele que precisa estar declarado (rawUrl + needles).
      if (/HTTP 404/.test(e.message ?? "")) {
        row.apiSpdx = "NOASSERTION";
        row.notes.push("GitHub não detecta licença no branch default (404) — validado pelo LICENSE bruto");
      } else {
        row.notes.push(`API de licença indisponível: ${e.message}`);
        if (STRICT) failures.push(`${c.slug}: falha de rede consultando a API (${c.repo})`);
      }
    }
  }

  row.ok = row.rawOk !== false && !failures.some((f) => f.startsWith(`${c.slug}:`));
  results.push(row);
}

// ── Report ───────────────────────────────────────────────────────────────────
if (JSON_OUT) {
  console.log(JSON.stringify({ ok: failures.length === 0, count: checks.length, retries: retries.length, retriesDetail: retries, results, failures }, null, 2));
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
  if (retries.length) {
    const hosts = [...new Set(retries.map((r) => new URL(r.url).host))].join(", ");
    console.log(`  [i ] ${retries.length} requisição(ões) precisou(aram) de retry (host instável: ${hosts})`);
    console.log("       as tentativas estão nas notas acima; a verificação em si não mudou — é o MESMO LICENSE, lido de novo.");
    console.log("");
  }
  if (failures.length === 0) {
    console.log(`  [OK] ${checks.length} licenças declaradas batem com a fonte primária.`);
  } else {
    for (const f of failures) console.log(`  [FAIL] ${f}`);
  }
  console.log("");
}

process.exit(failures.length > 0 ? 1 : 0);

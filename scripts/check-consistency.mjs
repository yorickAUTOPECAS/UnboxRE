#!/usr/bin/env node
/**
 * check-consistency.mjs — offline regression test for docs ↔ code ↔ license drift.
 *
 * Why this exists
 * ---------------
 * The recurring failure mode in this repo was NOT broken code: it was the docs
 * and the scripts quietly disagreeing — a `-Profile formats` in the guide that the
 * script never accepted, a `--write` flag that was really `--apply`, a tool that
 * got installed but never got a third-party credit line. Manual audits caught these
 * once; they came back on the next edit. This runs on every push and fails the build.
 *
 * It needs NO network and NO third-party tools — so it works in CI on a clean runner.
 * License ACCURACY (does the declared SPDX match the upstream?) is a separate,
 * networked check: scripts/verify-licenses.mjs.
 *
 * Checks
 * ------
 *   1. config/tools.json is valid and self-consistent.
 *   2. Every core tool (tools.json) and every bootstrap catalog tool appears in
 *      THIRD_PARTY_NOTICES.md  (license COMPLETENESS).
 *   3. Every `-Profile <x>` used in the docs is accepted by bootstrap-windows.ps1.
 *   4. Every `gen-mcp-config.mjs --<flag>` used in the docs is a real flag.
 *   5. Every scripts/*.(ps1|sh|mjs|py) referenced in the docs exists on disk.
 *      (.py entrou no round 8.1: o toolkit ganhou um caminho Python e uma referência a
 *       script inexistente tem de ser pega aqui, não na mão de quem analisa um alvo)
 *   6. Every JSON template under config/mcp/ parses.
 *   7. Every relative markdown link in README/docs resolves to a real file.
 *
 * Usage: node scripts/check-consistency.mjs [--json]
 * Exit:  0 all pass · 1 at least one check failed · 2 the checker itself crashed.
 */

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const JSON_OUT = process.argv.includes("--json");

const read = (p) => readFileSync(join(ROOT, p), "utf8");
const exists = (p) => existsSync(join(ROOT, p));

const failures = [];
const notes = [];
function ok(msg) { notes.push(msg); }
function fail(check, msg) { failures.push({ check, msg }); }
function check(cond, name, msg) {
  if (cond) ok(`${name}: ok`);
  else fail(name, msg);
}

/** Recursively collect files under a directory (repo-relative, forward slashes). */
function walkFiles(dir) {
  const out = [];
  const walk = (d) => {
    for (const name of readdirSync(join(ROOT, d))) {
      const rel = join(d, name);
      const st = statSync(join(ROOT, rel));
      if (st.isDirectory()) walk(rel);
      else out.push(rel.split(sep).join("/"));
    }
  };
  walk(dir);
  return out;
}

/** Recursively collect *.md under docs/ and scripts/, plus the root files. */
function collectDocs() {
  const files = ["README.md", "THIRD_PARTY_NOTICES.md", "LICENSE"];
  const walk = (dir) => {
    for (const name of readdirSync(join(ROOT, dir))) {
      const rel = join(dir, name);
      const st = statSync(join(ROOT, rel));
      if (st.isDirectory()) walk(rel);
      else if (name.endsWith(".md")) files.push(rel.split(sep).join("/"));
    }
  };
  walk("docs");
  walk("scripts");
  return files;
}

// ── 1. config/tools.json ─────────────────────────────────────────────────────
let manifest;
try {
  manifest = JSON.parse(read("config/tools.json"));
} catch (e) {
  fail("manifest", `config/tools.json não parseia: ${e.message}`);
}
const coreTools = manifest ? Object.entries(manifest.tools ?? {}) : [];
check(coreTools.length >= 4, "manifest:core-count",
  `esperados >=4 núcleo em tools.json, achei ${coreTools.length}`);

for (const [slug, t] of coreTools) {
  check(!!t.displayName, `manifest:${slug}:displayName`, `${slug} sem displayName`);
  check(!!t.license?.spdx, `manifest:${slug}:license`, `${slug} sem license.spdx`);
  check(/^https:\/\//.test(t.license?.rawUrl ?? ""), `manifest:${slug}:rawUrl`,
    `${slug} license.rawUrl deve ser https`);
  check(!!t.upstream?.type, `manifest:${slug}:upstream`, `${slug} sem upstream.type`);
  check(!!t.install?.marker, `manifest:${slug}:marker`, `${slug} sem install.marker`);
}

// ── 1b. config/licenses.json (the wider registry) ────────────────────────────
if (exists("config/licenses.json")) {
  try {
    const reg = JSON.parse(read("config/licenses.json"));
    check(Array.isArray(reg.tools) && reg.tools.length > 0, "registry:tools",
      "config/licenses.json sem array 'tools'");
    for (const t of reg.tools ?? []) {
      check(!!t.name && !!t.spdx, "registry:entry", `config/licenses.json: entrada sem name/spdx: ${JSON.stringify(t)}`);
      check(!!t.repo || !!t.rawUrl, "registry:source",
        `config/licenses.json: "${t.name}" precisa de repo ou rawUrl para ser verificável`);
    }
  } catch (e) {
    fail("registry", `config/licenses.json não parseia: ${e.message}`);
  }
}

// ── 2. License completeness (notices + matrix) ───────────────────────────────
const notices = exists("THIRD_PARTY_NOTICES.md") ? read("THIRD_PARTY_NOTICES.md") : "";
const matrix = exists("docs/03-licencas.md") ? read("docs/03-licencas.md") : "";
const lower = (s) => s.toLowerCase();

for (const [slug, t] of coreTools) {
  const needle = lower(t.displayName.split("(")[0].trim());
  check(lower(notices).includes(needle), `notices:${slug}`,
    `"${t.displayName}" (núcleo) não tem entrada em THIRD_PARTY_NOTICES.md`);
}

// Every tool the bootstrap INSTALLS must have a credit line.
let catalogNames = [];
if (exists("scripts/bootstrap-windows.ps1")) {
  const bs = read("scripts/bootstrap-windows.ps1");
  // Catalog entries are hashtables: @{ Name = 'X'; ... License = '...' }
  for (const m of bs.matchAll(/Name\s*=\s*'([^']+)'/g)) catalogNames.push(m[1]);
}
catalogNames = [...new Set(catalogNames)];
check(catalogNames.length > 0, "catalog:parsed",
  "não consegui extrair nenhuma ferramenta do catálogo do bootstrap");
const noticeLc = lower(notices);
for (const name of catalogNames) {
  // Match on the leading token, e.g. "Zig", "Detect It Easy", "Node.js LTS" → first word.
  const key = lower(name.split(/[ (/]/)[0]);
  const found = noticeLc.includes(lower(name)) || noticeLc.includes(key);
  if (!found) fail("completeness", `ferramenta do bootstrap sem crédito no NOTICES: "${name}"`);
}
if (!failures.some((f) => f.check === "completeness")) {
  ok(`completeness: ${catalogNames.length} ferramentas do bootstrap têm crédito`);
}

// ── 2b. PowerShell files must carry a UTF-8 BOM ──────────────────────────────
// Windows PowerShell 5.1 reads a BOM-less UTF-8 .ps1 as ANSI; a mojibake'd em
// dash inside a double-quoted string can decode to a smart quote and make the
// script FAIL TO PARSE. That happened for real (fetch-tools.ps1 shipped without
// the BOM while every sibling had it). This keeps the convention enforced.
const psFiles = walkFiles("scripts").filter((f) => f.endsWith(".ps1"));
for (const f of psFiles) {
  const buf = readFileSync(join(ROOT, f));
  const bom = buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf;
  check(bom, `bom:${f}`, `${f} não tem BOM UTF-8 (PS 5.1 lê UTF-8 sem BOM como ANSI e pode não parsear)`);
}

// ── 2c. License-registry coverage (informativo: mede o que ainda falta) ──────
// Não é gate: o objetivo é que o número visível diga o tamanho real do que ainda
// não tem linha verificada contra o upstream.
const registered = [];
if (manifest) for (const [, t] of coreTools) if (t.displayName) registered.push(t.displayName);
try {
  for (const t of JSON.parse(read("config/licenses.json")).tools ?? []) if (t.name) registered.push(t.name);
} catch { /* already reported above */ }
const norm = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, "");
const regNorm = registered.map(norm).filter(Boolean);
const uncovered = [];
for (const name of catalogNames) {
  const key = norm(name.split(/[ (/]/)[0]);
  if (!key || !regNorm.some((r) => r.includes(key) || key.includes(r))) uncovered.push(name);
}
if (uncovered.length) {
  ok(`licenças: ${catalogNames.length - uncovered.length}/${catalogNames.length} do bootstrap têm linha verificada; faltam ${uncovered.length}: ${uncovered.join(", ")}`);
} else {
  ok(`licenças: ${catalogNames.length}/${catalogNames.length} do bootstrap têm linha verificada`);
}

// ── 3. Bootstrap profile names ───────────────────────────────────────────────
let validProfiles = [];
if (exists("scripts/bootstrap-windows.ps1")) {
  const bs = read("scripts/bootstrap-windows.ps1");
  const vs = bs.match(/\[ValidateSet\(([^)]*)\)\]\s*\[string\[\]\]\$Profile/);
  if (vs) validProfiles = [...vs[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
}
check(validProfiles.length > 0, "profile:parsed",
  "não consegui extrair o ValidateSet de -Profile do bootstrap");

const docs = collectDocs();
for (const file of docs) {
  if (!exists(file)) continue;
  const text = read(file);
  for (const m of text.matchAll(/-Profile\s+([A-Za-z0-9_,]+)/g)) {
    for (const p of m[1].split(",")) {
      if (p && !validProfiles.includes(p)) {
        fail("profile", `${file}: "-Profile ${p}" não é um perfil válido (${validProfiles.join(", ")})`);
      }
    }
  }
}

// ── 4. gen-mcp-config.mjs flags ──────────────────────────────────────────────
let validFlags = [];
if (exists("scripts/gen-mcp-config.mjs")) {
  const src = read("scripts/gen-mcp-config.mjs");
  validFlags = [...new Set([
    ...[...src.matchAll(/\bhas\("(--[a-z-]+)"\)/g)].map((m) => m[1]),
    ...[...src.matchAll(/\bval\("(--[a-z-]+)"/g)].map((m) => m[1]),
  ])];
}
check(validFlags.length > 0, "mcpflags:parsed", "não extraí flags de gen-mcp-config.mjs");
for (const file of docs) {
  if (!exists(file)) continue;
  // Line-scoped: a flag can follow a value ("--client claude --write"), so we
  // scan every --flag on any line that invokes the generator, not just the ones
  // glued to the filename.
  for (const line of read(file).split(/\r?\n/)) {
    if (!line.includes("gen-mcp-config.mjs")) continue;
    for (const m of line.matchAll(/--[a-z][a-z-]+/g)) {
      if (!validFlags.includes(m[0])) {
        fail("mcpflags", `${file}: "gen-mcp-config.mjs ${m[0]}" — flag inexistente (válidas: ${validFlags.join(", ")})`);
      }
    }
  }
}

// ── 4b. gen-mcp-config.mjs client slugs ──────────────────────────────────────
let validClients = [];
if (exists("scripts/gen-mcp-config.mjs")) {
  const block = read("scripts/gen-mcp-config.mjs").match(/const CLIENTS = \{([\s\S]*?)\n\};/);
  if (block) validClients = [...block[1].matchAll(/^\s{2}"?([a-z][a-z0-9-]+)"?:\s*\{/gm)].map((m) => m[1]);
}
check(validClients.length > 0, "clients:parsed", "não extraí os clientes de gen-mcp-config.mjs");
for (const file of docs) {
  if (!exists(file)) continue;
  for (const line of read(file).split(/\r?\n/)) {
    if (!line.includes("gen-mcp-config.mjs")) continue;
    for (const m of line.matchAll(/--client\s+([a-z][a-z0-9-]+)/g)) {
      if (!validClients.includes(m[1])) {
        fail("clients", `${file}: "--client ${m[1]}" — cliente inexistente (válidos: ${validClients.join(", ")})`);
      }
    }
  }
}

// ── 5. Referenced scripts exist ──────────────────────────────────────────────
for (const file of docs) {
  if (!exists(file)) continue;
  const text = read(file);
  // A repo-relative script path starts at a boundary; a path like
  // "rea-main/scripts/rea.mjs" (a third-party entrypoint) must NOT be treated as
  // "scripts/rea.mjs", and neither must a placeholder path like
  // "work/<alvo>/scripts/patch-entry.py" (a script OF THE CASE, not of the toolkit).
  //
  // A lookbehind that merely rejects word chars is not enough: with the optional
  // "./"-style prefix, `/scripts/x.py` matches with the bare `/` consumed as prefix,
  // so the char before THAT is `>` in `work/<alvo>/scripts/x.py` — not a word char —
  // and the placeholder slipped through (measured: the .py extension landed this
  // class of false positive the first time it ran). So the rule is a whitelist: the
  // reference has to START at a line start or right after whitespace/a quote/a
  // backtick/a bracket/an `=`/a `:` — which is what every real doc reference does.
  for (const m of text.matchAll(/(?:^|[\s`'"(\[=:])((?:\.{0,2}[\\/])?scripts[\\/][A-Za-z0-9._-]+\.(?:ps1|sh|mjs|py))/gm)) {
    const rel = m[1].replace(/^\.{0,2}[\\/]/, "").replace(/\\/g, "/");
    if (!exists(rel)) fail("scripts", `${file}: referencia ${m[1]}, que não existe`);
  }
}

// ── 5b. Every script is cited somewhere in the docs ──────────────────────────
const docCorpus = docs.filter(exists).map(read).join("\n");
const scriptFiles = walkFiles("scripts")
  .filter((f) => /\.(ps1|sh|mjs|py)$/.test(f))
  .filter((f) => !f.includes("/lib/"));
const undocumented = scriptFiles.filter((f) => !docCorpus.includes(f.split("/").pop()));
for (const f of undocumented) {
  fail("documented", `${f} existe mas não é citado em nenhuma doc (README.md / scripts/README.md)`);
}
if (!undocumented.length) ok(`documented: ${scriptFiles.length} scripts citados na documentação`);

// ── 6. MCP JSON templates parse ──────────────────────────────────────────────
if (exists("config/mcp")) {
  for (const name of readdirSync(join(ROOT, "config/mcp"))) {
    if (!name.endsWith(".json")) continue;
    try {
      JSON.parse(read(`config/mcp/${name}`));
      ok(`mcp:${name}: ok`);
    } catch (e) {
      fail("mcp", `config/mcp/${name} não parseia: ${e.message}`);
    }
  }
}

// ── 7. Relative markdown links resolve ───────────────────────────────────────
// A link into a GITIGNORED path is not a broken link: the fetched third-party
// trees (ghidra/, x64dbg/, rea-main/, x64dbg-mcp-server-main/), work/, generated
// configs … are intentionally absent from a clean checkout and only appear after
// fetch-tools. On a local machine (where rea-main/ exists) this is invisible; it
// only surfaces in CI — which is exactly what happened, and is why we ask git
// which targets it ignores instead of guessing from a directory list.
const candidates = [];
for (const file of docs) {
  if (!exists(file)) continue;
  for (const m of read(file).matchAll(/\]\(([^)]+)\)/g)) {
    let target = m[1].trim();
    if (/^(https?:|mailto:|#)/.test(target)) continue;
    target = target.split("#")[0];
    if (!target) continue;
    const resolved = resolve(join(ROOT, dirname(file)), decodeURIComponent(target));
    const rel = relative(ROOT, resolved).split(sep).join("/");
    if (rel === ".." || rel.startsWith("../")) continue; // outside the repo
    candidates.push({ file, target, rel });
  }
}
const ignoredPaths = new Set();
if (candidates.length) {
  const res = spawnSync("git", ["check-ignore", "--stdin"], {
    cwd: ROOT,
    input: candidates.map((c) => c.rel).join("\n"),
    encoding: "utf8",
  });
  for (const line of (res.stdout || "").split(/\r?\n/)) if (line.trim()) ignoredPaths.add(line.trim());
}
for (const c of candidates) {
  if (ignoredPaths.has(c.rel)) continue;                 // absent by design (fetched/ignored)
  if (!existsSync(join(ROOT, c.rel))) fail("links", `${c.file}: link relativo quebrado → ${c.target}`);
}

// ── Report ───────────────────────────────────────────────────────────────────
const summary = {
  ok: notes.length,
  fail: failures.length,
  checks: {
    coreTools: coreTools.length,
    catalogTools: catalogNames.length,
    validProfiles,
    mcpFlags: validFlags,
  },
  licenseCoverage: {
    registered: registered.length,
    catalog: catalogNames.length,
    verified: catalogNames.length - uncovered.length,
    uncovered,
  },
};

if (JSON_OUT) {
  console.log(JSON.stringify({ summary, failures }, null, 2));
} else {
  console.log("");
  console.log("UnboxRE — verificação de consistência (docs ↔ código ↔ licenças)");
  console.log("─".repeat(66));
  console.log(`  núcleo: ${summary.checks.coreTools} · catálogo: ${summary.checks.catalogTools} · perfis: ${validProfiles.length} · flags MCP: ${validFlags.length}`);
  console.log(`  licenças com linha verificada: ${summary.licenseCoverage.verified}/${summary.licenseCoverage.catalog} do bootstrap · registradas: ${summary.licenseCoverage.registered}`);
  console.log("");
  if (failures.length === 0) {
    console.log(`  [OK] nenhuma divergência encontrada (${notes.length} verificações).`);
  } else {
    for (const f of failures) console.log(`  [FAIL] (${f.check}) ${f.msg}`);
    console.log("");
    console.log(`  ${failures.length} divergência(s). Corrija a doc OU o código — os dois devem concordar.`);
  }
  console.log("");
}

process.exit(failures.length > 0 ? 1 : 0);

#!/usr/bin/env node
/**
 * mcp-x64dbg-smoke.mjs — proves the x64dbg-MCP bridge answers LIVE.
 *
 * Why this exists
 * ---------------
 * "Plugin installed" is not "plugin works". The x64dbg-MCP server lives INSIDE
 * the x64dbg process: until the GUI is up, port 9094/9095 does not exist. This
 * script performs the real MCP session against that port — initialize →
 * notifications/initialized → tools/list → a real read-only tool call — and
 * fails if any step does not answer. It is the proof that was missing before
 * (previously the only evidence was "the .dp64 is on disk").
 *
 * It talks Streamable HTTP, tolerates both JSON and SSE responses, and echoes
 * the Mcp-Session-Id header when the server issues one.
 *
 * Token: $env:X64DBG_TOKEN, or the mcp_config.json the plugin writes on its
 * first run NEXT TO x64dbg.exe (x64dbg/release/x64|x32/mcp_config.json — it is
 * NOT in the x64dbg/ root). Never prints the token.
 *
 * Usage:
 *   node scripts/mcp-x64dbg-smoke.mjs [--port 9094] [--tool GetDebugState] [--json]
 * Exit:
 *   0 MCP answered (handshake + tools/list + the tool call)
 *   1 connected, but a protocol step failed
 *   2 could not connect / no token (x64dbg closed or plugin absent)
 *
 * Exit path: sets process.exitCode and lets the event loop drain. Calling
 * process.exit() while undici is closing sockets aborts on Windows with
 * "Assertion failed: !(handle->flags & UV_HANDLE_CLOSING)" and exit 127, which
 * would mask the real result.
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

const argv = process.argv.slice(2);
const val = (flag, dflt) => {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
};

const JSON_OUT = argv.includes("--json");
const PORT = Number(val("--port", "9094")) || 9094;
const REQUESTED_TOOL = val("--tool", "GetDebugState");
const TIMEOUT_MS = Number(val("--timeout", "15000")) || 15000;
const URL_BASE = `http://127.0.0.1:${PORT}/`;

// A tool that makes sense with no debuggee loaded, in order of preference.
const FALLBACK_TOOLS = ["GetDebugState", "GetEventLog", "GetAllRegisters", "ListModules", "GetMemoryMap"];

function findToken() {
  if (process.env.X64DBG_TOKEN) return { token: process.env.X64DBG_TOKEN, source: "env X64DBG_TOKEN" };
  // O plugin grava ao lado do x64dbg.exe (release/x64 ou release/x32). A raiz
  // x64dbg/ é fallback de layouts antigos — nunca foi onde o plugin escreve.
  const candidates = [
    join(ROOT, "x64dbg", "release", "x64", "mcp_config.json"),
    join(ROOT, "x64dbg", "release", "x32", "mcp_config.json"),
    join(ROOT, "x64dbg", "mcp_config.json"),
  ];
  const cfg = candidates.find((c) => existsSync(c));
  if (!cfg) {
    return { token: null, source: "x64dbg/release/{x64,x32}/mcp_config.json não existe (rode .\\scripts\\start-x64dbg.ps1 uma vez)" };
  }
  const shown = relative(ROOT, cfg).split(sep).join("/");
  try {
    const j = JSON.parse(readFileSync(cfg, "utf8"));
    const t = j.AuthToken ?? j.authToken ?? j.token ?? null;
    return t ? { token: t, source: shown } : { token: null, source: `${shown} sem AuthToken` };
  } catch (e) {
    return { token: null, source: `${shown} ilegível: ${e.message}` };
  }
}

const { token, source: TOKEN_SOURCE } = findToken();

/** Parse the body of an MCP response: plain JSON or one/more SSE frames. */
function parseBody(text, contentType, expectId) {
  if (contentType.includes("text/event-stream")) {
    for (const block of text.split(/\r?\n\r?\n/)) {
      const data = block
        .split(/\r?\n/)
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.slice(5).trim())
        .join("");
      if (!data) continue;
      try {
        const j = JSON.parse(data);
        if (expectId === null || j.id === expectId) return j;
      } catch {
        /* keep scanning */
      }
    }
    return null;
  }
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

let sessionId = null;

async function rpc(method, params, id) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    // Fecha a conexão a cada request: menos handles vivos até a hora de sair.
    Connection: "close",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (sessionId) headers["Mcp-Session-Id"] = sessionId;

  const body = id === null
    ? { jsonrpc: "2.0", method, ...(params !== undefined ? { params } : {}) }
    : { jsonrpc: "2.0", id, method, params: params ?? {} };

  // AbortController com clearTimeout (não AbortSignal.timeout): o timer
  // abandonado pelo segundo ainda dispara durante o exit.
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(URL_BASE, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: ac.signal,
    });
    const sid = res.headers.get("mcp-session-id");
    if (sid) sessionId = sid;
    const text = await res.text();
    return {
      status: res.status,
      contentType: res.headers.get("content-type") || "",
      json: parseBody(text, res.headers.get("content-type") || "", id),
      raw: text.slice(0, 300),
    };
  } finally {
    clearTimeout(timer);
  }
}

const steps = [];
const record = (name, ok, detail) => {
  steps.push({ step: name, ok, detail });
  return ok;
};

/** Sentinel: prints the report, then unwinds without process.exit(). */
class SmokeExit extends Error {
  constructor(code) {
    super(`smoke exit ${code}`);
    this.code = code;
  }
}

function finish(code, extra = {}) {
  const payload = {
    ok: code === 0,
    port: PORT,
    url: URL_BASE,
    tokenSource: TOKEN_SOURCE,
    steps,
    ...extra,
  };
  if (JSON_OUT) {
    console.log(JSON.stringify(payload, null, 2));
  } else {
    console.log("");
    console.log("UnboxRE — x64dbg-MCP smoke (chamada real)");
    console.log("─".repeat(66));
    console.log(`  endpoint: ${URL_BASE}   token: ${TOKEN_SOURCE}`);
    console.log("");
    for (const s of steps) {
      console.log(`  [${s.ok ? "OK  " : "FAIL"}] ${s.step.padEnd(24)} ${s.detail ?? ""}`);
    }
    console.log("");
    console.log(code === 0 ? "  [OK] o MCP do x64dbg respondeu ao vivo." : "  [FAIL] a sessão MCP não completou.");
    console.log("");
  }
  throw new SmokeExit(code);
}

async function main() {
  // ── 1. initialize (também é o teste de conexão) ────────────────────────────
  // Uma sonda sem Authorization responde 401 por design; a sessão autenticada
  // começa aqui, e é ela que distingue "porta fechada" de "token errado".
  let init;
  try {
    init = await rpc("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "unboxre-smoke", version: "1.0.0" },
    }, 1);
  } catch (e) {
    record("conexão", false, `porta ${PORT} não respondeu (${e.name === "TimeoutError" || e.name === "AbortError" ? "timeout" : e.message}) — x64dbg fechado ou plugin ausente`);
    finish(2);
  }
  if (init.status === 401) {
    record("conexão", false, `HTTP 401 — ${token ? "Bearer rejeitado; o plugin pode ter regenerado o token, reabra o x64dbg" : `token ausente (${TOKEN_SOURCE})`}`);
    finish(2);
  }
  const serverInfo = init.json?.result?.serverInfo;
  if (!serverInfo) {
    record("initialize", false, `sem serverInfo (HTTP ${init.status}): ${init.raw}`);
    finish(1);
  }
  record("initialize", true, `${serverInfo.name ?? "?"} ${serverInfo.version ?? ""} (protocolo ${init.json.result.protocolVersion ?? "?"})`);

  // ── 2. notifications/initialized ───────────────────────────────────────────
  try {
    const note = await rpc("notifications/initialized", undefined, null);
    record("notifications/initialized", note.status < 400, `HTTP ${note.status}${sessionId ? " (sessão emitida)" : ""}`);
  } catch (e) {
    if (e instanceof SmokeExit) throw e;
    record("notifications/initialized", false, e.message);
  }

  // ── 3. tools/list ──────────────────────────────────────────────────────────
  let tools = [];
  try {
    const list = await rpc("tools/list", {}, 2);
    tools = list.json?.result?.tools ?? [];
    if (!Array.isArray(tools) || tools.length === 0) {
      record("tools/list", false, `nenhuma tool retornada: ${list.raw}`);
      finish(1);
    }
    record("tools/list", true, `${tools.length} tools expostas`);
  } catch (e) {
    if (e instanceof SmokeExit) throw e;
    record("tools/list", false, e.message);
    finish(1);
  }

  // ── 4. A real tool call ────────────────────────────────────────────────────
  const names = tools.map((t) => t.name);
  const candidates = [REQUESTED_TOOL, ...FALLBACK_TOOLS];
  const tool = candidates.find((c) => names.includes(c)) ?? null;
  if (!tool) {
    record("tools/call", false, `nenhuma tool de leitura conhecida entre: ${candidates.join(", ")}`);
    finish(1);
  }
  let call;
  try {
    call = await rpc("tools/call", { name: tool, arguments: {} }, 3);
  } catch (e) {
    if (e instanceof SmokeExit) throw e;
    record(`tools/call ${tool}`, false, e.message);
    finish(1);
  }
  const result = call.json?.result;
  if (call.json?.error) {
    record(`tools/call ${tool}`, false, `erro JSON-RPC: ${call.json.error.message ?? JSON.stringify(call.json.error)}`);
    finish(1);
  }
  const text = (result?.content ?? [])
    .map((c) => (typeof c.text === "string" ? c.text : JSON.stringify(c)))
    .join(" ")
    .replace(/\s+/g, " ")
    .slice(0, 160);
  record(`tools/call ${tool}`, result?.isError !== true, result?.isError === true ? `isError: ${text}` : `${text || "(resposta vazia)"}`);
  finish(result?.isError === true ? 1 : 0, { tool });
}

// Saída de segurança: se um handle do Node ficar pendurado, força a saída 2s
// depois — sem isso um CI ficaria esperando para sempre. (unref: não segura o
// processo vivo por si só; só dispara se algo mais ainda estiver aberto.)
setTimeout(() => process.exit(process.exitCode ?? 0), 2000).unref();

try {
  await main();
  process.exitCode = 0;
} catch (e) {
  if (e instanceof SmokeExit) {
    process.exitCode = e.code;
  } else {
    console.error(`erro inesperado: ${e?.stack ?? e}`);
    process.exitCode = 1;
  }
}

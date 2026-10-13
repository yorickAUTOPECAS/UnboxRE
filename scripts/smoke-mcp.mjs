#!/usr/bin/env node
/**
 * smoke-mcp.mjs — proves an MCP server actually starts and answers a call.
 *
 * Why this exists
 * ---------------
 * "The bridge should work per the docs" is not evidence. This speaks the MCP
 * stdio protocol to a server process and asserts it replies to a real
 * `initialize` and a real `tools/list` — the same handshake any MCP client does.
 * It is used both manually (against rea-main) and in CI (against a freshly
 * installed rea-agents), so the REA bridge is verified, not assumed.
 *
 * The x64dbg-MCP server is NOT covered here: it is a plugin that only listens
 * with the x64dbg GUI open, which a headless CI runner cannot provide. That part
 * stays a manual step (docs/05-mcp.md).
 *
 * Usage:
 *   node scripts/smoke-mcp.mjs [<entry.mjs>] [--transport stdio]
 * Default entry: rea-main/scripts/rea.mjs
 * Exit: 0 handshake succeeded · 1 no valid reply · 2 could not start the server.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const entry = resolve(ROOT, args[0] || "rea-main/scripts/rea.mjs");

if (!existsSync(entry)) {
  console.error(`entrada do MCP não encontrada: ${entry}`);
  console.error("rode primeiro: node -e \"require('child_process')\"  — ou instale o REA (scripts/fetch-tools.ps1 -Tool rea -Apply)");
  process.exit(2);
}

const requests = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "unboxre-smoke", version: "1" } } },
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 2, method: "tools/list" },
];

const child = spawn(process.execPath, [entry, "mcp"], {
  cwd: dirname(entry),
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env },
});

let stdout = "";
let stderr = "";
const got = new Map(); // id -> parsed response

const TIMEOUT_MS = 45000;
const timer = setTimeout(() => {
  finish(`timeout de ${TIMEOUT_MS}ms sem resposta de tools/list`, 1);
}, TIMEOUT_MS);

function finish(message, code) {
  clearTimeout(timer);
  try { child.kill(); } catch {}
  if (code === 0) {
    console.log("");
    console.log("UnboxRE — smoke test do MCP (stdio)");
    console.log("─".repeat(60));
    console.log(`  entrada: ${entry}`);
    console.log(`  initialize → serverInfo: ${JSON.stringify(got.get(1).result.serverInfo)}`);
    const tools = got.get(2).result.tools ?? [];
    console.log(`  tools/list  → ${tools.length} ferramentas (ex.: ${tools.slice(0, 3).map((t) => t.name).join(", ")})`);
    console.log("");
    console.log("  [OK] a ponte MCP sobe e responde a uma chamada real.");
    console.log("");
  } else {
    console.error("");
    console.error(`  [FAIL] ${message}`);
    if (stderr) console.error("  stderr:\n" + stderr.split(/\r?\n/).slice(0, 8).map((l) => "    " + l).join("\n"));
    console.error("");
  }
  process.exit(code);
}

child.on("error", (e) => finish(`não consegui iniciar o servidor: ${e.message}`, 2));
child.on("exit", (code) => {
  // If it exited before answering, report that; otherwise the finish() path already ran.
  if (!got.has(2)) finish(`o servidor saiu (exit ${code}) antes de responder tools/list`, 1);
});

child.stdout.on("data", (chunk) => {
  stdout += chunk.toString("utf8");
  let nl;
  while ((nl = stdout.indexOf("\n")) >= 0) {
    const line = stdout.slice(0, nl).trim();
    stdout = stdout.slice(nl + 1);
    if (!line || line[0] !== "{") continue;
    try {
      const msg = JSON.parse(line);
      if (msg.id !== undefined && msg.result) got.set(msg.id, msg);
    } catch { /* partial line or non-JSON banner — ignore */ }
  }
  if (got.has(1) && got.has(2)) finish("", 0);
});

child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });

// Send the handshake. `notifications/initialized` is a notification (no id).
child.stdin.write(requests.map((r) => JSON.stringify(r)).join("\n") + "\n");

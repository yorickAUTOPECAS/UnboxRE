#!/usr/bin/env node
/**
 * x64dbg-drive.mjs — dirige o x64dbg VIVO pela ponte MCP, em sequência.
 *
 * Por que existe
 * --------------
 * `mcp-x64dbg-smoke.mjs` prova que a ponte responde. Faltava o passo seguinte: EXECUTAR
 * um plano no debugger — carregar o alvo, parar onde interessa e dumpar a memória — sem
 * abrir a GUI para clicar. É o que o fluxo "duro" de unpack precisa (Cenário 1 de
 * docs/06-workflows.md): parar no OEP, dumpar o módulo, reconstruir a IAT.
 *
 * O x64dbg precisa estar ABERTO com o plugin MCP (a ponte vive DENTRO do processo):
 *   PS> .\scripts\start-x64dbg.ps1
 *
 * As operações rodam na ORDEM em que aparecem na linha de comando, o que torna a
 * sequência auditável no próprio comando (e não escondida dentro do script):
 *
 *   node scripts/x64dbg-drive.mjs \
 *     --load work/<alvo>/packed.exe \
 *     --run-to "mod.entry(packed)" \
 *     --regs --disassemble 4 \
 *     --dump-module packed work/<alvo>/unpacked/dump.exe
 *
 * Uso:
 *   --list-tools                 imprime as ferramentas MCP disponíveis
 *   --load <exe>                 abre o binário no debugger (LoadBinary)
 *   --call 'Tool {json}'         chama qualquer ferramenta MCP com argumentos JSON
 *   --run-to <expressão>         RunToAddress (ex.: mod.entry(alvo), 0x140001000)
 *   --break <expressão>          SetBreakpoint
 *   --regs                       GetAllRegisters
 *   --modules                    ListModules
 *   --state                      GetDebugState
 *   --detect-oep <módulo>        DetectOEP
 *   --dump-module <mod> <saída>  DumpModule (memória → arquivo)
 *   --dump-module-mem <mod> <saída>  DumpMemory do módulo INTEIRO (base + SizeOfImage)
 *                                para o rebuild-iat resolver exports da imagem CARREGADA
 *                                (não do arquivo em disco: comctl32 v6 vem do WinSxS)
 *   --json                       saída em JSON (para encadear em script)
 *
 * Exit: 0 tudo respondeu · 1 uma chamada falhou · 2 sem ponte/token ou erro de uso.
 * Nunca usa sudo, nunca imprime o token.
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const argv = process.argv.slice(2);
const JSON_OUT = argv.includes("--json");
const val = (flag, dflt) => {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
};

if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) {
  console.log("uso: node scripts/x64dbg-drive.mjs [--load <exe>] [--run-to <expr>] [--regs] [--dump-module <mod> <arq>] [--json]");
  console.log("     --list-tools · --call 'Tool {json}' · --break <expr> · --modules · --state · --detect-oep <mod>");
  console.log("     --dump-module-mem <mod> <arq>  (imagem carregada do módulo, para resolver exports)");
  process.exit(argv.length === 0 ? 2 : 0);
}

// ── token/porta: o plugin grava ao lado do x64dbg.exe ───────────────────────
function findToken() {
  if (process.env.X64DBG_TOKEN) return { token: process.env.X64DBG_TOKEN, source: "env X64DBG_TOKEN" };
  const candidates = [
    join(ROOT, "x64dbg", "release", "x64", "mcp_config.json"),
    join(ROOT, "x64dbg", "release", "x32", "mcp_config.json"),
  ];
  const cfg = candidates.find((c) => existsSync(c));
  if (!cfg) return { token: null, source: "mcp_config.json não existe (rode start-x64dbg.ps1 uma vez)" };
  try {
    const j = JSON.parse(readFileSync(cfg, "utf8"));
    return { token: j.AuthToken ?? j.authToken ?? null, port: j.Port ?? 9094, source: relative(ROOT, cfg).split(sep).join("/") };
  } catch (e) {
    return { token: null, source: `mcp_config.json ilegível: ${e.message}` };
  }
}
const { token, port: cfgPort, source: TOKEN_SOURCE } = findToken();
if (!token) {
  console.error(`[!!] sem token do MCP: ${TOKEN_SOURCE}`);
  console.error("     o x64dbg está aberto? PS> .\\scripts\\start-x64dbg.ps1");
  process.exit(2);
}
const PORT = Number(val("--port", String(cfgPort ?? 9094)));
const URL_BASE = `http://127.0.0.1:${PORT}/`;
const TIMEOUT_MS = Number(val("--timeout", "60000"));

function parseBody(text, contentType, expectId) {
  if (contentType.includes("text/event-stream")) {
    for (const block of text.split(/\r?\n\r?\n/)) {
      const data = block.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("");
      if (!data) continue;
      try {
        const j = JSON.parse(data);
        if (expectId === null || j.id === expectId) return j;
      } catch { /* segue */ }
    }
    return null;
  }
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

let sessionId = null;
async function rpc(method, params, id) {
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Connection: "close", Authorization: `Bearer ${token}` };
  if (sessionId) headers["Mcp-Session-Id"] = sessionId;
  const body = id === null ? { jsonrpc: "2.0", method, ...(params !== undefined ? { params } : {}) } : { jsonrpc: "2.0", id, method, params: params ?? {} };
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(URL_BASE, { method: "POST", headers, body: JSON.stringify(body), signal: ac.signal });
    const sid = res.headers.get("mcp-session-id");
    if (sid) sessionId = sid;
    const text = await res.text();
    return parseBody(text, res.headers.get("content-type") || "", id);
  } finally {
    clearTimeout(timer);
  }
}

/** Resultado de uma ferramenta: o MCP devolve content[].text com o payload. */
function toolText(reply) {
  const c = reply?.result?.content;
  if (!Array.isArray(c)) return null;
  return c.map((x) => x.text ?? "").join("\n");
}

const results = [];
const failures = [];
let nextId = 10;

async function callTool(name, args = {}) {
  const reply = await rpc("tools/call", { name, arguments: args }, nextId++);
  const text = toolText(reply);
  const err = reply?.error?.message ?? reply?.result?.isError ? (reply?.error?.message ?? "isError") : null;
  const rec = { tool: name, args, ok: !err, text: text ?? JSON.stringify(reply ?? {}).slice(0, 400) };
  results.push(rec);
  if (!rec.ok) failures.push(`${name}: ${rec.text}`);
  if (!JSON_OUT) {
    console.log(`\n─ ${name} ${JSON.stringify(args)}`);
    console.log(err ? `  [!!] ${rec.text}` : rec.text.split("\n").map((l) => `  ${l}`).join("\n"));
  }
  return rec;
}

// ── handshake ───────────────────────────────────────────────────────────────
const init = await rpc("initialize", { protocolVersion: "2025-06-11", capabilities: {}, clientInfo: { name: "unboxre-x64dbg-drive", version: "1" } }, 1);
if (!init?.result) {
  console.error(`[!!] initialize falhou na porta ${PORT} (x64dbg está aberto e ouvindo?): ${JSON.stringify(init ?? {}).slice(0, 200)}`);
  process.exit(2);
}
await rpc("notifications/initialized", undefined, null);

// ── executa o plano NA ORDEM da linha de comando ────────────────────────────
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === "--load") await callTool("LoadBinary", { filePath: resolve(argv[++i] ?? "") });
  else if (a === "--call") {
    const spec = argv[++i] ?? "";
    const sp = spec.indexOf(" ");
    const name = sp < 0 ? spec : spec.slice(0, sp);
    let args = {};
    if (sp > 0) {
      try { args = JSON.parse(spec.slice(sp + 1)); }
      catch (e) { console.error(`[!!] --call '${name} {json}': JSON inválido (${e.message})`); process.exit(2); }
    }
    await callTool(name, args);
  }
  else if (a === "--run-to") await callTool("RunToAddress", { address: argv[++i] });
  else if (a === "--break") await callTool("SetBreakpoint", { target: argv[++i] });
  else if (a === "--regs") await callTool("GetAllRegisters");
  else if (a === "--modules") await callTool("ListModules");
  else if (a === "--state") await callTool("GetDebugState");
  else if (a === "--detect-oep") await callTool("DetectOEP", { module: argv[++i] });
  else if (a === "--dump-module") {
    const mod = argv[++i];
    const filePath = resolve(argv[++i] ?? "");
    await callTool("DumpModule", { module: mod, filePath });
  } else if (a === "--dump-module-mem") {
    // DumpMemory do módulo inteiro: base e tamanho vêm do ListModules. O MCP interpreta
    // `size` como HEX ("4096" = 0x4096) — por isso vai explícito com prefixo 0x.
    const mod = argv[++i];
    const filePath = resolve(argv[++i] ?? "");
    const list = await callTool("ListModules");
    const line = (list.text ?? "").split(/\r?\n/).find((l) => l.trim().toLowerCase().endsWith((mod ?? "").toLowerCase()));
    const m = line?.match(/0x([0-9a-f]+)\s*\|\s*0x([0-9a-f]+)/i);
    if (!m) {
      failures.push(`--dump-module-mem ${mod}: módulo não está na lista (carregado?)`);
      console.error(`[!!] módulo "${mod}" não está na lista de módulos`);
    } else {
      await callTool("DumpMemory", { address: `0x${m[1]}`, size: `0x${m[2]}`, filePath });
    }
  } else if (a === "--list-tools") {
    const tools = await rpc("tools/list", {}, nextId++);
    const names = (tools?.result?.tools ?? []).map((t) => t.name);
    if (JSON_OUT) results.push({ tool: "tools/list", ok: true, tools: names });
    else console.log(`\n${names.length} ferramentas:\n  ${names.join(" ")}`);
  } else if (a.startsWith("--") && !["--json", "--port", "--timeout"].includes(a)) {
    console.error(`[!!] flag desconhecida: ${a}`);
    process.exit(2);
  }
}

if (JSON_OUT) {
  console.log(JSON.stringify({ port: PORT, tokenSource: TOKEN_SOURCE, ok: failures.length === 0, calls: results, failures }, null, 2));
} else if (failures.length) {
  console.log(`\n[!!] ${failures.length} chamada(s) falharam`);
}

// Sai deixando o event loop drenar (matar o processo com sockets abertos aborta no Windows).
process.exitCode = failures.length ? 1 : 0;

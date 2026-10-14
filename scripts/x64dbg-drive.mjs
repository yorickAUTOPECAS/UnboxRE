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
 *   --break <expressão>          SetBreakpoint — SOFTWARE (int3 NA MEMÓRIA)
 *   --hw-break <endereço>        SetHardwareBreakpoint — HARDWARE (DR0-DR3, NÃO escreve na memória)
 *   --hw-type x|r|w              tipo do breakpoint de hardware (default x = execução)
 *   --hw-size 1|2|4|8            tamanho observado pelo breakpoint de hardware (default 1)
 *   --list-breaks                ListBreakpoints (software, hardware e memória)
 *   --bp-log <arquivo.jsonl>     grava cada --break/--hw-break/--run-to (endereço + tipo) para o
 *                                `verify-dump.mjs` usar no modo sem original
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
 * Breakpoint: qual usar (armadilha medida, caso iat-hardcase)
 * ---------------------------------------------------------
 * Breakpoint de SOFTWARE grava `int3` (0xCC) NA MEMÓRIA do alvo. Se o stub do packer
 * ainda vai decriptar/reescrever aquela seção, o debugger guarda o byte que estava lá
 * NAQUELE momento (o cifrado) e, quando o alvo para, "restaura" o byte SALVO — não o
 * decifrado. Resultado medido: o dump sai com uma instrução trocada (RVA 0x1f98:
 * 0x48 `mov [rsp+18h],rbx` → 0x51 `push rcx`; 0x51 = 0x48 ^ 0x19, o byte que existia
 * no arquivo EMPACOTADO) e o loader ACEITA o arquivo: o programa morre depois, no CRT.
 *
 *   * a seção ainda pode ser escrita pelo packer? Use `--hw-break` (DR0-DR3: não há byte
 *     na memória para "restaurar errado");
 *   * `--run-to` (RunToAddress) usa um breakpoint TEMPORÁRIO DE SOFTWARE por baixo — vale
 *     a mesma restrição; ele passa pelo log do `--bp-log` como tipo `sw-temp`;
 *   * `--break` só depois que a seção está no estado final (é o caso de parar no OEP de
 *     um alvo já decifrado).
 *
 * Limite do hardware (medido nesta máquina, x86-64): DR0-DR3 = **4** breakpoints de
 * hardware por thread. O 5º não cabe e — pior — o x64dbg responde **"Hardware breakpoint
 * set."** e simplesmente NÃO arma o endereço (falha silenciosa, medida duas vezes: o
 * endereço nunca aparece no `ListBreakpoints`). Por isso este driver confere a lista depois
 * de cada `--hw-break` e falha explicitamente (exit 1) quando o endereço não foi armado;
 * o `--bp-log` grava `armed: true|false`.
 * Para mais pontos que isso: `SetMemoryBreakpoint` (guard page, sem limite de DR, mais
 * lento) ou breakpoint de software DEPOIS que a seção estiver em claro.
 *
 * Exit: 0 tudo respondeu · 1 uma chamada falhou · 2 sem ponte/token ou erro de uso.
 * Nunca usa sudo, nunca imprime o token.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
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
  console.log("     --list-tools · --call 'Tool {json}' · --modules · --state · --detect-oep <mod>");
  console.log("     --hw-break <endereço> [--hw-type x|r|w] [--hw-size 1|2|4|8]  BREAKPOINT DE HARDWARE (DR0-DR3)");
  console.log("     --break <endereço>        breakpoint de SOFTWARE (int3 NA MEMÓRIA: só com a seção em claro)");
  console.log("     --list-breaks · --bp-log <arq.jsonl>   (grava os breakpoints para o verify-dump sem original)");
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

// ── breakpoints de hardware: tipo/tamanho e o log da captura ────────────────
// O log (JSONL) é o que o `verify-dump.mjs` consome no modo SEM original: sem saber ONDE
// havia breakpoint, um byte restaurado com o valor pré-modificação fica invisível (ele é
// igual ao do arquivo empacotado, e 1 byte em 256 coincide por acaso).
const HW_TYPE = val("--hw-type", "x");
const HW_SIZE = Number(val("--hw-size", "1"));
const BP_LOG = val("--bp-log", null);
function logBp(kind, address, extra) {
  if (!BP_LOG) return;
  const file = resolve(BP_LOG);
  mkdirSync(dirname(file), { recursive: true });
  appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), kind, address, ...extra })}\n`);
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
  else if (a === "--run-to") {
    const address = argv[++i];
    await callTool("RunToAddress", { address });
    logBp("sw-temp", address, { tool: "RunToAddress" });
  }
  else if (a === "--break") {
    const target = argv[++i];
    await callTool("SetBreakpoint", { target });
    logBp("sw", target, { tool: "SetBreakpoint" });
  }
  else if (a === "--hw-break") {
    const address = argv[++i];
    const args = { address, type: HW_TYPE, size: HW_SIZE };
    await callTool("SetHardwareBreakpoint", args);
    // O x64dbg responde "Hardware breakpoint set." mesmo com os 4 slots (DR0-DR3) ocupados e
    // descarta o endereço em silêncio (medido). Sem esta conferência, a captura seguiria
    // achando que existe um breakpoint que não existe.
    const list = await callTool("ListBreakpoints");
    let want = null;
    try { want = BigInt(address.trim()).toString(16).toLowerCase(); } catch { want = null; }
    const armed = want ? (list.text ?? "").toLowerCase().includes(`0x${want}`) : null;
    if (armed === false) {
      const msg = `breakpoint de hardware NÃO foi armado em ${address}: a lista não mostra esse endereço (DR0-DR3 = 4 por thread, já ocupados) — o x64dbg respondeu \"set\" mesmo assim`;
      failures.push(msg);
      console.error(`[!!] ${msg}`);
    }
    logBp("hw", address, { ...args, armed, tool: "SetHardwareBreakpoint" });
  }
  else if (a === "--list-breaks") await callTool("ListBreakpoints");
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
  } else if (a.startsWith("--") && !["--json", "--port", "--timeout", "--hw-type", "--hw-size", "--bp-log"].includes(a)) {
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

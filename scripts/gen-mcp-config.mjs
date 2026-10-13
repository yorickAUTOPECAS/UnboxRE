#!/usr/bin/env node
/**
 * gen-mcp-config.mjs — gera (e valida) a configuração MCP concreta para cada
 * cliente de IA, a partir dos templates em config/mcp/.
 *
 * Por que existe
 * --------------
 * Cada cliente MCP inventou seu próprio dialeto: `mcpServers` (Claude, Cursor,
 * Gemini, Windsurf), `servers` (VS Code/Copilot), `mcp_servers` em TOML (Codex).
 * Manter quatro arquivos à mão garante que três fiquem obsoletos. Aqui existe
 * UMA fonte de verdade — a topologia em TOPOLOGY, abaixo — e um renderizador
 * por dialeto.
 *
 * Uso
 * ---
 *   node scripts/gen-mcp-config.mjs                      # mostra o que geraria (dry-run)
 *   node scripts/gen-mcp-config.mjs --client cursor      # só um cliente
 *   node scripts/gen-mcp-config.mjs --apply              # grava em config/mcp/generated/
 *   node scripts/gen-mcp-config.mjs --apply --install    # grava também no local real do cliente
 *   node scripts/gen-mcp-config.mjs --check              # valida os configs já instalados
 *
 * Segurança
 * ---------
 * O token do x64dbg é lido de x64dbg/mcp_config.json. Ele é um segredo LOCAL de
 * loopback: escrever no config do cliente é o uso pretendido, mas os arquivos
 * gerados ficam em config/mcp/generated/ (ignorado pelo Git) e o script avisa
 * sempre que o token for impresso.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

// ───────────────────────────────────────────────────────────────────────────
//  Argumentos
// ───────────────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => {
  const i = argv.indexOf(f);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : d;
};

const OPTS = {
  apply: has("--apply"),
  install: has("--install"),
  check: has("--check"),
  list: has("--list"),
  json: has("--json"),
  transport: val("--transport", "http"), // http | sse
  only: val("--client", null),
  outDir: val("--out-dir", join(ROOT, "config", "mcp", "generated")),
  port: Number(val("--port", "0")) || 0,
};

// ───────────────────────────────────────────────────────────────────────────
//  Descoberta do ambiente
// ───────────────────────────────────────────────────────────────────────────

/** Lê config/env/unboxre.env (ou o .example) sem dependência externa. */
function loadEnvFile() {
  const candidates = [
    join(ROOT, "config", "env", "unboxre.env"),
    join(ROOT, "config", "env", "unboxre.env.example"),
  ];
  const out = {};
  for (const file of candidates) {
    if (!existsSync(file)) continue;
    for (const raw of readFileSync(file, "utf8").split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq < 1) continue;
      const k = line.slice(0, eq).trim();
      const v = line.slice(eq + 1).trim();
      if (!(k in out)) out[k] = v;
    }
  }
  return out;
}

/** Localiza a instalação do Ghidra, preferindo a variável de ambiente. */
function findGhidraDir() {
  const env = loadEnvFile();
  const candidates = [
    process.env.GHIDRA_INSTALL_DIR,
    env.GHIDRA_INSTALL_DIR,
    join(ROOT, "ghidra", "ghidra_12.1.4_PUBLIC"),
  ].filter(Boolean);
  for (const c of candidates) {
    if (existsSync(join(c, "support", "analyzeHeadless.bat"))) return c;
  }
  return candidates[candidates.length - 1];
}

/**
 * Lê o token do x64dbg-MCP. O plugin grava `AuthToken` no primeiro run;
 * até isso acontecer, não há token — e o config gerado fica com placeholder,
 * porque um config com token errado falha de forma mais confusa que um sem.
 */
function findX64dbgToken() {
  if (process.env.X64DBG_TOKEN) {
    return { token: process.env.X64DBG_TOKEN, source: "variável de ambiente X64DBG_TOKEN" };
  }
  const cfg = join(ROOT, "x64dbg", "mcp_config.json");
  if (!existsSync(cfg)) {
    return { token: null, source: "x64dbg/mcp_config.json ausente (abra o x64dbg uma vez)" };
  }
  try {
    const j = JSON.parse(readFileSync(cfg, "utf8"));
    const t = j.AuthToken ?? j.authToken ?? j.token ?? null;
    return t
      ? { token: t, source: "x64dbg/mcp_config.json" }
      : { token: null, source: "x64dbg/mcp_config.json sem AuthToken" };
  } catch (e) {
    return { token: null, source: `x64dbg/mcp_config.json ilegível: ${e.message}` };
  }
}

const ENVFILE = loadEnvFile();
const GHIDRA_DIR = findGhidraDir();
const JAVA_HOME = process.env.JAVA_HOME || ENVFILE.JAVA_HOME || "";
const REA_ENTRY = join(ROOT, "rea-main", "scripts", "rea.mjs");
const { token: TOKEN, source: TOKEN_SOURCE } = findX64dbgToken();
const PORT_X64 = OPTS.port || Number(ENVFILE.X64DBG_MCP_PORT_X64 || 9094);

// ───────────────────────────────────────────────────────────────────────────
//  Topologia — a única fonte de verdade
// ───────────────────────────────────────────────────────────────────────────

/**
 * Cada servidor é descrito uma vez, de forma neutra. Os renderizadores abaixo
 * traduzem para o dialeto de cada cliente.
 */
const SERVERS = [
  {
    name: "x64dbg",
    kind: "http",
    url: `http://127.0.0.1:${PORT_X64}/${OPTS.transport === "sse" ? "sse" : ""}`,
    headers: { Authorization: `Bearer ${TOKEN ?? "<TOKEN-PENDENTE>"}` },
    note: "debugger dinâmico (precisa do x64dbg aberto)",
  },
  {
    name: "rea",
    kind: "stdio",
    command: "node",
    args: [REA_ENTRY, "mcp"],
    env: {
      GHIDRA_INSTALL_DIR: GHIDRA_DIR,
      ...(JAVA_HOME ? { JAVA_HOME } : {}),
    },
    note: "orquestrador de análise estática (Ghidra/IDA/JEB/Hopper)",
  },
];

// ───────────────────────────────────────────────────────────────────────────
//  Dialetos de cliente
// ───────────────────────────────────────────────────────────────────────────

const APPDATA = process.env.APPDATA || join(homedir(), "AppData", "Roaming");
const HOME = homedir();

/**
 * `format`:
 *   json       — objeto JSON; `serversKey` indica onde os servidores vivem
 *   toml       — Codex: [mcp_servers.<nome>]
 * `transportField`:
 *   "type"     — emite { "type": "http" | "stdio" }
 *   "none"     — não emite (cliente infere por url/command)
 */
const CLIENTS = {
  "claude-desktop": {
    label: "Claude Desktop",
    format: "json",
    serversKey: "mcpServers",
    transportField: "type",
    path: join(APPDATA, "Claude", "claude_desktop_config.json"),
  },
  "claude-code": {
    label: "Claude Code",
    format: "json",
    serversKey: "mcpServers",
    transportField: "type",
    path: join(HOME, ".claude.json"),
  },
  cursor: {
    label: "Cursor",
    format: "json",
    serversKey: "mcpServers",
    transportField: "type",
    path: join(HOME, ".cursor", "mcp.json"),
  },
  windsurf: {
    label: "Windsurf",
    format: "json",
    serversKey: "mcpServers",
    transportField: "type",
    path: join(HOME, ".codeium", "windsurf", "mcp_config.json"),
  },
  gemini: {
    label: "Gemini CLI",
    format: "json",
    serversKey: "mcpServers",
    transportField: "none",
    path: join(HOME, ".gemini", "settings.json"),
  },
  vscode: {
    label: "VS Code / Copilot",
    format: "json",
    serversKey: "servers",
    transportField: "type",
    path: join(ROOT, ".vscode", "mcp.json"),
    urlField: "url",
  },
  codex: {
    label: "Codex CLI",
    format: "toml",
    serversKey: "mcp_servers",
    path: join(HOME, ".codex", "config.toml"),
  },
};

// ───────────────────────────────────────────────────────────────────────────
//  Renderizadores
// ───────────────────────────────────────────────────────────────────────────

/** Traduz um servidor neutro para o objeto de um cliente JSON. */
function toJsonServer(server, client) {
  if (server.kind === "http") {
    const out = { type: OPTS.transport === "sse" ? "sse" : "http", url: server.url };
    if (server.headers && Object.keys(server.headers).length) out.headers = server.headers;
    if (client.transportField === "none") delete out.type;
    return out;
  }
  // stdio
  const out = { command: server.command, args: server.args };
  if (server.env && Object.keys(server.env).length) out.env = server.env;
  if (client.transportField === "type") out.type = "stdio";
  return out;
}

/** Escapa uma string para TOML básico. */
const tomlStr = (s) => `"${String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
const tomlArr = (a) => `[${a.map(tomlStr).join(", ")}]`;
const tomlInline = (o) =>
  `{ ${Object.entries(o)
    .map(([k, v]) => `${k} = ${tomlStr(v)}`)
    .join(", ")} }`;

/** Renderiza o bloco TOML do Codex. */
function renderToml() {
  const parts = [
    "# UnboxRE — gerado por scripts/gen-mcp-config.mjs",
    "# Mescle com o seu ~/.codex/config.toml; não substitua o arquivo inteiro.",
    "",
  ];
  for (const s of SERVERS) {
    parts.push(`[mcp_servers.${s.name}]`);
    if (s.kind === "http") {
      parts.push(`url = ${tomlStr(s.url)}`);
      if (s.headers) parts.push(`http_headers = ${tomlInline(s.headers)}`);
    } else {
      parts.push(`command = ${tomlStr(s.command)}`);
      parts.push(`args = ${tomlArr(s.args)}`);
      if (s.env && Object.keys(s.env).length) parts.push(`env = ${tomlInline(s.env)}`);
    }
    parts.push("");
  }
  return parts.join("\n");
}

/** Renderiza o documento JSON de um cliente. */
function renderJson(client) {
  const servers = {};
  for (const s of SERVERS) servers[s.name] = toJsonServer(s, client);
  return { [client.serversKey]: servers };
}

function render(client) {
  if (client.format === "toml") return renderToml();
  return JSON.stringify(renderJson(client), null, 2) + "\n";
}

// ───────────────────────────────────────────────────────────────────────────
//  Validação
// ───────────────────────────────────────────────────────────────────────────

/**
 * Valida um arquivo de config já instalado. Retorna lista de problemas.
 * Só reporta o que é objetivamente errado — nada de estilo.
 */
function validateInstalled(name, client) {
  const problems = [];
  const file = client.path;
  if (!existsSync(file)) return [`não existe: ${file}`];

  const text = readFileSync(file, "utf8");

  if (client.format === "toml") {
    for (const s of SERVERS) {
      if (!text.includes(`[mcp_servers.${s.name}]`)) {
        problems.push(`falta a seção [mcp_servers.${s.name}]`);
      }
    }
    if (SERVERS[0].kind === "http" && TOKEN && !text.includes(TOKEN)) {
      problems.push("token do x64dbg ausente ou diferente do mcp_config.json");
    }
    return problems;
  }

  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return [`JSON inválido: ${e.message}`];
  }
  const table = doc[client.serversKey];
  if (!table) return [`objeto "${client.serversKey}" ausente`];

  for (const s of SERVERS) {
    const entry = table[s.name];
    if (!entry) {
      problems.push(`servidor "${s.name}" ausente`);
      continue;
    }
    if (s.kind === "stdio") {
      const expected = s.args[0];
      const args = entry.args ?? [];
      if (!args.includes(expected)) {
        problems.push(`"${s.name}": args não aponta para ${expected}`);
      } else if (!existsSync(expected)) {
        problems.push(`"${s.name}": entrypoint não existe (${expected}) — rode npm install no rea-main`);
      }
      const ghidra = entry.env?.GHIDRA_INSTALL_DIR;
      if (!ghidra || !existsSync(join(ghidra, "support", "analyzeHeadless.bat"))) {
        problems.push(`"${s.name}": GHIDRA_INSTALL_DIR inválido`);
      }
    } else {
      if (!entry.url || !entry.url.includes(String(PORT_X64))) {
        problems.push(`"${s.name}": url deveria apontar para a porta ${PORT_X64}`);
      }
      const auth = entry.headers?.Authorization ?? "";
      if (TOKEN && !auth.includes(TOKEN)) {
        problems.push(`"${s.name}": Authorization com token diferente do mcp_config.json`);
      }
      if (!auth) {
        problems.push(`"${s.name}": sem header Authorization (o plugin exige Bearer)`);
      }
    }
  }
  return problems;
}

// ───────────────────────────────────────────────────────────────────────────
//  Execução
// ───────────────────────────────────────────────────────────────────────────

// --list: lista os clientes suportados e sai. Existe porque a documentação já o
// citava; uma doc que aponta para um comando inexistente é exatamente o tipo de
// divergência que scripts/check-consistency.mjs reprova.
if (OPTS.list) {
  if (OPTS.json) {
    console.log(JSON.stringify(
      Object.entries(CLIENTS).map(([slug, c]) => ({ slug, label: c.label, format: c.format, path: c.path })),
      null, 2));
  } else {
    console.log("\nClientes MCP suportados (--client <slug>):\n");
    for (const [slug, c] of Object.entries(CLIENTS)) {
      console.log(`  ${slug.padEnd(16)} ${c.label.padEnd(22)} ${c.path}`);
    }
    console.log("");
  }
  process.exit(0);
}

const names = Object.keys(CLIENTS).filter((n) => !OPTS.only || n === OPTS.only);
if (names.length === 0) {
  console.error(`Cliente desconhecido: ${OPTS.only}`);
  console.error(`Disponíveis: ${Object.keys(CLIENTS).join(", ")}`);
  process.exit(2);
}

const report = {
  root: ROOT,
  ghidra: GHIDRA_DIR,
  reaEntry: REA_ENTRY,
  port: PORT_X64,
  transport: OPTS.transport,
  token: TOKEN ? "presente" : "pendente",
  tokenSource: TOKEN_SOURCE,
  clients: {},
};

if (!OPTS.json && !OPTS.check) {
  console.log("");
  console.log("UnboxRE — gerador de configuração MCP");
  console.log("─".repeat(66));
  console.log(`  raiz          ${ROOT}`);
  console.log(`  ghidra        ${GHIDRA_DIR}`);
  console.log(`  rea entry     ${REA_ENTRY}${existsSync(REA_ENTRY) ? "" : "  (AUSENTE)"}`);
  console.log(`  porta x64dbg  ${PORT_X64}  (transporte ${OPTS.transport})`);
  console.log(`  token         ${TOKEN ? "presente" : "PENDENTE"} — ${TOKEN_SOURCE}`);
  if (TOKEN) {
    console.log("  aviso         o token será escrito nos arquivos abaixo (segredo de loopback)");
  }
  console.log("");
}

for (const name of names) {
  const client = CLIENTS[name];
  const content = render(client);
  report.clients[name] = { label: client.label, path: client.path };

  if (OPTS.check) {
    const problems = validateInstalled(name, client);
    report.clients[name].problems = problems;
    if (!OPTS.json) {
      if (problems.length === 0) {
        console.log(`  [OK  ] ${client.label.padEnd(20)} ${client.path}`);
      } else {
        console.log(`  [WARN] ${client.label.padEnd(20)} ${client.path}`);
        for (const p of problems) console.log(`         · ${p}`);
      }
    }
    continue;
  }

  if (!OPTS.apply) {
    if (!OPTS.json) {
      console.log(`  [DRY ] ${client.label} → ${join(OPTS.outDir, `${name}${client.format === "toml" ? ".toml" : ".json"}`)}`);
      console.log("        (use --apply para gravar; --install para gravar no local real do cliente)");
    }
    report.clients[name].content = content;
    continue;
  }

  const ext = client.format === "toml" ? ".toml" : ".json";
  const outFile = join(OPTS.outDir, `${name}${ext}`);
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, content, "utf8");
  report.clients[name].written = outFile;
  if (!OPTS.json) console.log(`  [WROTE] ${outFile}`);

  if (OPTS.install) {
    mkdirSync(dirname(client.path), { recursive: true });
    if (existsSync(client.path)) {
      // Nunca sobrescrevemos um config de cliente em uso: backup ao lado.
      const backup = `${client.path}.unboxre.bak`;
      writeFileSync(backup, readFileSync(client.path, "utf8"), "utf8");
      if (!OPTS.json) console.log(`          backup: ${backup}`);
    }
    writeFileSync(client.path, content, "utf8");
    if (!OPTS.json) console.log(`  [INST ] ${client.path}`);
  }
}

if (OPTS.json) {
  console.log(JSON.stringify(report, null, 2));
} else if (OPTS.check) {
  const bad = Object.values(report.clients).filter((c) => (c.problems ?? []).length > 0);
  console.log("");
  console.log(`  ${Object.keys(report.clients).length - bad.length} ok · ${bad.length} com problema`);
  console.log("");
  if (bad.length) process.exit(1);
} else if (OPTS.apply) {
  console.log("");
  console.log("  Próximo passo: reinicie o cliente de IA para ele reler a configuração.");
  console.log("  O servidor x64dbg só responde com o x64dbg aberto (porta " + PORT_X64 + ").");
  console.log("");
}

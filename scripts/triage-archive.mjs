#!/usr/bin/env node
/**
 * triage-archive.mjs — o que É este container, e o que tem dentro (sem abrir debugger).
 *
 * Por que existe
 * --------------
 * O escopo validado do toolkit é Windows, mas os quatro leitores dele (triage-static,
 * disasm-range, pe-read, identify-protections) respondem sobre **formatos de imagem**:
 * PE e ELF. Um alvo embrulhado (zipapp, .whl, .jar, .nupkg) não é imagem — é container —
 * e no round 8.4 isso parou a triagem de novo: os cinco comandos do Cenário 0 devolveram
 * `formato não reconhecido` / `não é um PE` e a análise só andou porque o zip foi aberto
 * à mão com `unzip`. Recusar não é triagem (a mesma lição dos rounds 8.3 e 8.4): aqui o
 * container é reconhecido, os membros são listados e o **formato de cada membro** é dito.
 *
 * O que ele resolve que o `unzip -l` não resolve
 * ----------------------------------------------
 *   1. **formato de cada membro por assinatura** — um `.pyz` com um `.so` ELF dentro, um
 *      `.bin` que é marshal de code object, um `__main__.py` que é o launcher: `unzip -l`
 *      mostra nome e tamanho, não o que é cada coisa;
 *   2. **dica de ABI/versão de interpretador** — procurar `python3.13` dentro de um membro
 *      ELF/PE foi o que fixou a versão do alvo do round 8.4 (a runtime nativa dizia
 *      `/usr/local/include/python3.13/object.h`). Sem isso, três interpretadores diferentes
 *      aceitam o MESMO payload;
 *   3. **o aviso do marshal** — marshal não tem cabeçalho de versão. `marshal.loads()` com a
 *      versão errada não dá erro: devolve um code object corrompido e o processo morre com
 *      access violation (medido no round 8.4, 3.11 e 3.12 sobre payload 3.13 → exit 139,
 *      sem mensagem). O script diz isso onde o analista vai ler.
 *
 * Formatos reconhecidos: ZIP (com ou sem preâmbulo de shebang = zipapp), `.pyc` (magic +
 * 0d 0a + campos), marshal de code object (0x63/0xE3) e pickle/manifest (0x7b `{`/0x80).
 *
 * Uso: node scripts/triage-archive.mjs <arquivo|.pyz|.whl|.jar|.nupkg|.pyc|.bin>
 *        [--min N] [--no-members] [--json]
 * Exit: 0 analisado · 2 arquivo ilegível ou container/formato não reconhecido. Nunca usa sudo.
 *
 * Sem dependência: Node puro, nenhum perfil do bootstrap precisa instalar nada para ele rodar.
 */

import { readFileSync, statSync } from "node:fs";
import { basename } from "node:path";
import { inflateRawSync } from "node:zlib";

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);
if (argv.length === 0 || has("--help") || has("-h")) {
  console.log("uso: node scripts/triage-archive.mjs <arquivo> [--min N] [--no-members] [--json]");
  console.log("  containers: ZIP, zipapp (shebang + ZIP), .whl/.jar/.nupkg (são ZIP)");
  console.log("  payloads:   .pyc (bytecode compilado), marshal de code object, pickle/manifest");
  console.log("  --min N     tamanho mínimo das strings de dica de ABI (default 4)");
  console.log("  --no-members  só o cabeçalho do container");
  console.log("  --json      saída JSON");
  process.exit(0);
}
const file = argv.find((a) => !a.startsWith("--"));
if (!file) {
  console.error("uso: node scripts/triage-archive.mjs <arquivo> [--min N] [--no-members] [--json]");
  process.exit(2);
}
const JSON_OUT = has("--json");
const NO_MEMBERS = has("--no-members");
const MIN = Number(val("--min", "4")) || 4;

let buf;
try {
  buf = readFileSync(file);
} catch (e) {
  console.error(`[!!] não consegui ler ${file}: ${e.message}`);
  process.exit(2);
}
const size = statSync(file).size;

// ── helpers ──────────────────────────────────────────────────────────────────

/** Entropia de Shannon dos bytes de um buffer (0..8). */
function entropyFromBuf(b) {
  if (!b.length) return 0;
  const freq = new Array(256).fill(0);
  for (const x of b) freq[x]++;
  let h = 0;
  for (const c of freq) if (c) {
    const p = c / b.length;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 100) / 100;
}

/** Formato pelos primeiros bytes — o mesmo critério que os leitores do toolkit usam. */
function magicOf(b) {
  if (b.length >= 0x14 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) {
    const cls = b[4] === 2 ? "ELF64" : "ELF32";
    const le = b[5] === 1;                                  // EI_DATA: little-endian na pratica
    const machine = le ? b.readUInt16LE(18) : b.readUInt16BE(18);
    const mach = { 0x03: "x86", 0x3e: "x64", 0x28: "ARM", 0xb7: "ARM64", 0xf3: "RISC-V" }[machine]
      ?? `0x${machine.toString(16)}`;
    return { kind: "ELF", detail: `${cls} ${mach}` };
  }
  if (b.length >= 2 && b[0] === 0x4d && b[1] === 0x5a) return { kind: "PE", detail: "MZ" };
  if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return { kind: "ZIP", detail: "container aninhado" };
  if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) return { kind: "gzip", detail: "" };
  if (b.length >= 1 && (b[0] === 0x63 || b[0] === 0xe3)) {
    // `c` = TYPE_CODE no marshal; com FLAG_REF (0x80) vira 0xe3. Sem cabeçalho nenhum.
    return { kind: "marshal:code", detail: "code object — SEM cabeçalho de versão (ver aviso abaixo)" };
  }
  if (b.length >= 2 && b[0] === 0x7b) return { kind: "pickle/marshal:dict", detail: "manifest ({...})" };
  if (b.length >= 2 && b[0] === 0x80 && b[1] <= 5) return { kind: "pickle", detail: `protocolo ${b[1]}` };
  // fonte Python: ASCII imprimível dominante nas primeiras linhas
  let printable = 0;
  const n = Math.min(b.length, 256);
  for (let i = 0; i < n; i++) if (b[i] === 9 || b[i] === 10 || b[i] === 13 || (b[i] >= 32 && b[i] < 127)) printable++;
  if (n > 0 && printable / n > 0.9) {
    const text = b.subarray(0, Math.min(b.length, 4096)).toString("latin1");
    const kind = /^\s*(#.*\n)?\s*(import |from |def |class |[A-Za-z_][A-Za-z0-9_]*\s*=|@)/.test(text) ? "texto:Python" : "texto";
    return { kind, detail: "" };
  }
  return { kind: "dados", detail: "" };
}

/** `.pyc`: magic (2 bytes) + CRLF + flags/mtime/tamanho. A versão sai do magic, não do arquivo. */
function pycInfo(b) {
  if (b.length < 16 || b[2] !== 0x0d || b[3] !== 0x0a) return null;
  return {
    magic: b.readUInt16LE(0),
    magicHex: `0x${b.readUInt16LE(0).toString(16)}`,
    flags: b.readUInt32LE(4),
    // 3.7+: flags no offset 4; 3.6 e antes: mtime no 4 e tamanho no 8
    stamp: b.readUInt32LE(8),
    bytecode: b.readUInt32LE(12),
  };
}

/** Procura `python3.X` (e afins) no conteúdo: é o que diz de qual interpretador é o binário. */
function abiHints(bytes) {
  const text = bytes.toString("latin1");
  const out = new Set();
  for (const m of text.matchAll(/python3\.[0-9]{1,2}/g)) out.add(m[0]);
  for (const m of text.matchAll(/cp3[0-9]{2}-[a-z0-9_]+/g)) out.add(m[0]);
  for (const m of text.matchAll(/PyInit_[A-Za-z0-9_]+/g)) out.add(m[0]);
  return [...out].slice(0, 6);
}

/** Lista as strings ASCII >= MIN de um intervalo (limitado, para não virar um `strings`). */
function strings(bytes, min) {
  const text = bytes.toString("latin1");
  const out = [];
  for (const m of text.matchAll(new RegExp(`[ -~]{${min},}`, "g"))) {
    out.push(m[0]);
    if (out.length >= 40) break;
  }
  return out;
}

// ── ZIP: central directory (EOCD) ────────────────────────────────────────────

function findEOCD(b) {
  const max = Math.min(b.length, 0x10000 + 22);
  for (let i = b.length - 22; i >= b.length - max; i--) {
    if (i < 0) break;
    if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 0x05 && b[i + 3] === 0x06) {
      return {
        count: b.readUInt16LE(i + 10),
        cdSize: b.readUInt32LE(i + 12),
        cdOff: b.readUInt32LE(i + 16),
        commentLen: b.readUInt16LE(i + 20),
        at: i,
      };
    }
  }
  return null;
}

function zipMembers(b) {
  const eocd = findEOCD(b);
  if (!eocd) return null;
  const members = [];
  let p = eocd.cdOff;
  for (let i = 0; i < eocd.count && p + 46 <= b.length; i++) {
    if (b.readUInt32LE(p) !== 0x02014b50) break;          // PK\x01\x02
    const nameLen = b.readUInt16LE(p + 28);
    const extraLen = b.readUInt16LE(p + 30);
    const cmtLen = b.readUInt16LE(p + 32);
    const name = b.subarray(p + 46, p + 46 + nameLen).toString("latin1");
    const mode = (b.readUInt32LE(p + 38) >>> 16) & 0xffff; // atributos externos (UNIX)
    members.push({
      name,
      method: b.readUInt16LE(p + 10),
      crc: b.readUInt32LE(p + 16),
      compSize: b.readUInt32LE(p + 20),
      size: b.readUInt32LE(p + 24),
      mtime: b.readUInt32LE(p + 12),
      localOff: b.readUInt32LE(p + 42),
      executable: (mode & 0o111) !== 0,
      isDir: name.endsWith("/"),
    });
    p += 46 + nameLen + extraLen + cmtLen;
  }
  return { eocd, members };
}

/** Bytes de um membro (method 0 = guardado, 8 = deflate). Devolve null se não der. */
function memberBytes(b, m) {
  if (m.isDir || m.size === 0) return Buffer.alloc(0);
  const lo = m.localOff;
  if (b.readUInt32LE(lo) !== 0x04034b50) return null;     // PK\x03\x04
  const nameLen = b.readUInt16LE(lo + 26);
  const extraLen = b.readUInt16LE(lo + 28);
  const start = lo + 30 + nameLen + extraLen;
  const raw = b.subarray(start, start + m.compSize);
  if (m.method === 0) return raw.subarray(0, m.size);
  if (m.method === 8) {
    if (m.size > 8 * 1024 * 1024) return null;             // não infla 100 MB por curiosidade
    try {
      return inflateRawSync(raw);
    } catch {
      return null;
    }
  }
  return null;
}

// ── análise ──────────────────────────────────────────────────────────────────

/** Offset do primeiro cabeçalho local do ZIP: 0, ou o tamanho do preâmbulo (zipapp). */
function firstLocalHeaderOffset(b) {
  const i = b.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  return i > 0 ? i : 0;
}

const notes = [];
const top = magicOf(buf);
// O ZIP nao comeca necessariamente no byte 0: num zipapp ha um preambulo de shebang antes
// do primeiro `PK\x03\x04` (23 bytes no alvo do round 8.4). Por isso o container e
// reconhecido pelo diretorio central (EOCD), nao pela assinatura no offset 0.
const zip = zipMembers(buf);
const shebang = buf.length > 2 && buf[0] === 0x23 && buf[1] === 0x21
  ? buf.subarray(0, buf.indexOf(0x0a) >= 0 ? buf.indexOf(0x0a) : 64).toString("latin1").trim()
  : null;
const pyc = pycInfo(buf);

let kind = "desconhecido";
if (zip && shebang) kind = "zipapp (shebang + ZIP)";
else if (zip) kind = "ZIP";
else if (pyc && top.kind === "dados") kind = "pyc (bytecode compilado)";
else if (top.kind.startsWith("marshal")) kind = "payload marshal";
else if (top.kind.startsWith("pickle")) kind = "pickle/manifest";

if (kind === "desconhecido") {
  if (!JSON_OUT) {
    console.error(`[!!] ${file}: nem ZIP, nem zipapp, nem pyc, nem marshal/pickle — formato não reconhecido`);
    console.error(`     (primeiros bytes: ${buf.subarray(0, 8).toString("hex").replace(/(..)/g, "$1 ").trim()})`);
    console.error("     para imagem PE/ELF use: node scripts/triage-static.mjs <arquivo>");
  } else {
    console.log(JSON.stringify({ file: basename(file), size, format: "desconhecido",
      firstBytes: buf.subarray(0, 8).toString("hex"), exit: 2 }));
  }
  process.exit(2);
}

const report = {
  file: basename(file),
  size,
  format: kind,
  shebang,
  zipPreambleBytes: zip ? firstLocalHeaderOffset(buf) : 0,
  pyc,
  members: [],
  notes,
};

if (zip) {
  for (const m of zip.members) {
    if (NO_MEMBERS && m.isDir) continue;
    const entry = {
      name: m.name,
      size: m.size,
      compSize: m.compSize,
      method: m.method,
      crc: `0x${(m.crc >>> 0).toString(16)}`,
      executable: m.executable,
      isDir: m.isDir,
      entropy: 0,
      kind: m.isDir ? "diretório" : "",
      detail: "",
      abi: [],
      sample: [],
    };
    if (!m.isDir && !NO_MEMBERS) {
      const bytes = memberBytes(buf, m);
      if (bytes) {
        entry.entropy = entropyFromBuf(bytes);
        const inner = magicOf(bytes);
        entry.kind = inner.kind;
        entry.detail = inner.detail;
        entry.abi = abiHints(bytes);
        if (inner.kind === "texto:Python" || inner.kind === "texto") entry.sample = strings(bytes, Math.max(MIN, 8)).slice(0, 6);
      } else {
        entry.kind = "(não descomprimido)";
      }
    }
    report.members.push(entry);
  }
}

// ── leitura / avisos ─────────────────────────────────────────────────────────

const hasMarshal = report.members.some((m) => m.kind.startsWith("marshal"));
const natives = report.members.filter((m) => m.kind === "ELF" || m.kind === "PE");
const hasMain = report.members.some((m) => /(^|\/)__main__\.py$/.test(m.name));
if (top.kind.startsWith("marshal")) {
  const inner = abiHints(buf);
  if (inner.length) notes.push(`dica de ABI no proprio payload -> ${inner.join(", ")}`);
}

if (hasMarshal) {
  notes.push("marshal NAO tem cabecalho de versao: carregar com o interpretador errado nao da " +
    "erro — devolve code object corrompido e o processo morre com access violation (medido no " +
    "round 8.4: 3.11/3.12 sobre payload 3.13 -> exit 139, sem mensagem). Use a dica de ABI dos " +
    "membros nativos para escolher o interpretador ANTES de tentar `marshal.loads`.");
}
for (const n of natives) {
  if (n.kind === "ELF") {
    notes.push(`membro nativo ELF: ${n.name} — extensao do CPython compilada para Linux. O Windows ` +
      "nao carrega ELF como modulo (o erro e 193, ERROR_BAD_EXE_FORMAT); rodar exige Linux/WSL.");
  }
  if (n.abi.length) {
    notes.push(`${n.name}: dica de ABI -> ${n.abi.join(", ")} (e o que diz de qual ` +
      "interpretador o binario/bytecode e, quando o payload e marshal sem versao).");
  }
}
if (zip && hasMain) notes.push("tem __main__.py no topo: o container e executavel como zipapp (`python <arquivo>`).");

// ── saída ────────────────────────────────────────────────────────────────────

if (JSON_OUT) {
  console.log(JSON.stringify({ ...report, notes }, null, 2));
  process.exit(0);
}

console.log("");
console.log(`UnboxRE — triagem de container: ${report.file}`);
console.log("─".repeat(70));
console.log(`  ${size} bytes · ${kind}`);
if (shebang) console.log(`  preâmbulo (shebang): ${shebang}`);
if (pyc) console.log(`  pyc: magic ${pyc.magicHex} · flags=0x${pyc.flags.toString(16)} · bytecode=${pyc.bytecode} bytes`);
if (zip) {
  const pre = report.zipPreambleBytes;
  console.log(`  entradas: ${zip.members.length}${pre ? ` · preâmbulo de ${pre} bytes antes do primeiro PK` : ""}`);
  console.log("");
  if (!NO_MEMBERS) {
    console.log("  membros:");
    for (const m of report.members) {
      const flags = [m.executable ? "x" : "-", m.method === 8 ? "deflate" : "store"].join(" ");
      const abi = m.abi.length ? `  abi=${m.abi.join(",")}` : "";
      console.log(`    ${m.name.padEnd(30)} ${String(m.size).padStart(9)} B  ${flags.padEnd(12)} ${m.kind}${m.detail ? ` (${m.detail})` : ""}${m.entropy ? ` ent=${m.entropy}` : ""}${abi}`);
      for (const s of m.sample) console.log(`        | ${s.slice(0, 100)}`);
    }
  }
}
console.log("");
if (notes.length) {
  console.log("  o que isso decide:");
  for (const n of notes) console.log(`    * ${n}`);
  console.log("");
}
console.log("");
process.exit(0);

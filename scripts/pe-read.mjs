#!/usr/bin/env node
/**
 * pe-read.mjs — lê os BYTES de um RVA (ou de um offset do arquivo) sem abrir GUI.
 *
 * Por que existe
 * --------------
 * `disasm-range.py` termina cada linha que importa com `; -> rva 0x4000` / `"texto"` e
 * `triage-static.mjs` lista as strings com a RVA de cada uma. O passo seguinte — "e o que
 * TEM nesse endereço?" — não tinha caminho no toolkit: em duas rodadas seguidas (8.1 e 8.2)
 * a resposta foi um script avulso de parser de PE escrito na hora, um deles com bug próprio
 * (BigInt em JSON.stringify). Este script é esse passo, permanente:
 *
 *   1. sem `--rva`/`--off`: mostra o MAPA (seções com RVA, offset no arquivo, tamanho e
 *      permissões) — é a tabela que diz qual RVA pertence a qual seção;
 *   2. com `--rva`/`--off`: hexdump com o gutter ASCII e a RVA anotada por linha;
 *   3. leitura TIPADA dos bytes (`--as u32,u64,float,...`), que é o que o caso de verdade
 *      pede: uma semente `dword` em `.data`, uma máscara `movdqa` em `.rdata`, um
 *      `movabs` de 8 bytes conferido contra o disassembly.
 *
 * Os dois erros que este script existe para não repetir (medidos):
 *   · comparar bytes "no olho" entre o dump e o `movabs` do disassembly — ler o mesmo trecho
 *     nas duas formas (`u32`/`u64` little-endian) tira a dúvida de bit de uma vez;
 *   · tratar RVA como offset de arquivo. São coisas diferentes, e o erro só aparece com
 *     `--off` explícito para comparar: o mapa do passo 1 mostra os dois lado a lado.
 *
 * Uso:
 *   node scripts/pe-read.mjs <arquivo> [--rva 0x4000 | --off 0x3000] [--len 64]
 *        [--section .data] [--as u8,u32,u64,float,ascii,utf16,cstring] [--json]
 * Exit: 0 lido · 2 arquivo ilegível, não-PE, RVA fora de seção ou erro de uso. Nunca usa sudo.
 */

import { readFileSync } from "node:fs";

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d = null) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);
if (argv.length === 0 || has("--help") || has("-h")) {
  console.log("uso: node scripts/pe-read.mjs <arquivo> [--rva 0x4000 | --off 0x3000] [--len 64]");
  console.log("        [--section .data] [--as u8,u32,u64,float,ascii,utf16,cstring] [--json]");
  console.log("  sem --rva/--off/--section  → mostra o MAPA de seções (RVA ↔ offset do arquivo)");
  console.log("  --rva <hex>                → leitura pela RVA (o que o disassembly e o triage citam)");
  console.log("  --off <hex>                → leitura pelo offset no arquivo (para comparar com o mapa)");
  console.log("  --section <.data>          → lê a seção inteira (limitada por --len, default 4096)");
  console.log("  --as <lista>               → leituras tipadas: u8,i8,u16,i16,u32,i32,u64,i64,f32,f64,");
  console.log("                               ascii,utf16,cstring,wcstring,hex (default: u8,u32,u64)");
  process.exit(argv.length === 0 ? 2 : 0);
}
const JSON_OUT = has("--json");
const file = argv.find((a) => !a.startsWith("--") && ![val("--rva"), val("--off"), val("--len"), val("--section"), val("--as")].includes(a));

// `--as` é validado aqui, ANTES do modo mapa: com `--as u9` e sem --rva, a validação lá
// embaixo nunca rodava (o mapa sai e termina com exit 0) e o erro de uso passava batido —
// é o tipo de coisa que só aparece quando se testa o exit code em separado. Medido assim.
const AS_NAMES = ["u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "f32", "f64", "hex", "ascii", "utf16", "cstring", "wcstring"];
const asList = (val("--as", "u8,u32,u64")).split(",").map((s) => s.trim()).filter(Boolean);
const unknownAs = asList.filter((a) => !AS_NAMES.includes(a));
if (unknownAs.length) {
  console.error(`[!!] --as desconhecido: ${unknownAs.join(", ")} (válidos: ${AS_NAMES.join(", ")})`);
  process.exit(2);
}

let buf;
try {
  buf = readFileSync(file);
} catch (e) {
  console.error(`[!!] não consegui ler ${file}: ${e.message}`);
  process.exit(2);
}
if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) {
  console.error(`[!!] ${file}: sem assinatura MZ — não é um PE`);
  process.exit(2);
}
const u16 = (o) => buf.readUInt16LE(o);
const u32 = (o) => buf.readUInt32LE(o);
const pe = u32(0x3c);
if (u32(pe) !== 0x00004550) {
  console.error(`[!!] ${file}: assinatura PE ausente em 0x${pe.toString(16)}`);
  process.exit(2);
}
const nsec = u16(pe + 6);
const osz = u16(pe + 20);
const is64 = u16(pe + 24) === 0x20b;
const imageBase = is64 ? Number(buf.readBigUInt64LE(pe + 24 + 24)) : u32(pe + 24 + 28);
const sections = [];
for (let i = 0; i < nsec; i++) {
  const s = pe + 24 + osz + i * 40;
  sections.push({
    name: buf.subarray(s, s + 8).toString("latin1").replace(/\0+$/, ""),
    va: u32(s + 12),
    virtualSize: u32(s + 8),
    raw: u32(s + 20),
    rawSize: u32(s + 16),
    characteristics: u32(s + 36),
  });
}
const span = (s) => Math.max(s.virtualSize, s.rawSize);
const rva2off = (rva) => {
  for (const s of sections) if (rva >= s.va && rva < s.va + span(s)) return s.raw + (rva - s.va);
  return -1;
};
const off2rva = (off) => {
  for (const s of sections) if (off >= s.raw && off < s.raw + s.rawSize) return s.va + (off - s.raw);
  return -1;
};
const sectionOf = (rva) => sections.find((s) => rva >= s.va && rva < s.va + span(s)) ?? null;
const perms = (s) =>
  `${s.characteristics & 0x40000000 ? "R" : "-"}${s.characteristics & 0x80000000 ? "W" : "-"}${s.characteristics & 0x20000000 ? "X" : "-"}`;
const pad = (s, n) => String(s).padEnd(n);
const hex = (n, w = 0) => `0x${n.toString(16).padStart(w, "0")}`;

// ── localizar o intervalo pedido ─────────────────────────────────────────────
const sectName = val("--section");
const rvaArg = val("--rva");
const offArg = val("--off");
const num = (txt, oque) => {
  const n = Number(txt);
  if (!Number.isFinite(n)) {
    console.error(`[!!] ${oque} precisa ser numérico (ex.: 0x4000)`);
    process.exit(2);
  }
  return n;
};

let startOff = null;
let startRva = null;
let how = "mapa";
// Um RVA fora de seção NÃO é "sem argumento": é erro de uso, e o exit code tem de dizer
// isso mesmo mostrando o mapa como ajuda (quem encadeia em script depende do código).
let erro = false;
if (sectName) {
  const s = sections.find((x) => x.name === sectName);
  if (!s) {
    console.error(`[!!] seção ${sectName} não existe (tem: ${sections.map((x) => x.name).join(", ")})`);
    process.exit(2);
  }
  startOff = s.raw;
  startRva = s.va;
  how = `seção ${s.name}`;
} else if (rvaArg !== null) {
  startRva = num(rvaArg, "--rva");
  startOff = rva2off(startRva);
  how = `rva ${hex(startRva)}`;
  if (startOff < 0) {
    console.error(`[!!] rva ${hex(startRva)} não pertence a nenhuma seção (mapa abaixo)`);
    erro = true;
    how = "mapa";
    startOff = null;
    startRva = null;
  }
} else if (offArg !== null) {
  startOff = num(offArg, "--off");
  startRva = off2rva(startOff);
  how = `offset ${hex(startOff)}`;
  if (startOff >= buf.length) {
    console.error(`[!!] offset ${hex(startOff)} além do fim do arquivo (${buf.length} bytes)`);
    process.exit(2);
  }
}

// ── modo mapa (sem --rva/--off/--section) ────────────────────────────────────
if (startOff === null) {
  if (JSON_OUT) {
    console.log(JSON.stringify({ file, size: buf.length, imageBase: hex(imageBase), sections: sections.map((s) => ({ name: s.name, rva: hex(s.va), offset: hex(s.raw), virtualSize: s.virtualSize, rawSize: s.rawSize, perms: perms(s) })) }, null, 2));
    process.exit(erro ? 2 : 0);
  }
  console.log("");
  console.log(`UnboxRE — mapa de seções: ${file}`);
  console.log("─".repeat(78));
  console.log(`  ${buf.length} bytes · ImageBase=${hex(imageBase)}`);
  console.log(`  ${pad("seção", 9)} ${pad("rva", 10)} ${pad("offset", 10)} ${pad("virt", 7)} ${pad("raw", 7)} perms`);
  for (const s of sections) {
    console.log(`  ${pad(s.name, 9)} ${pad(hex(s.va, 6), 10)} ${pad(hex(s.raw, 6), 10)} ${pad(s.virtualSize, 7)} ${pad(s.rawSize, 7)} ${perms(s)}`);
  }
  console.log("");
  console.log("  Use --rva <hex> (o que o disassembly cita) ou --off <hex> (posição no arquivo).");
  console.log("");
  process.exit(erro ? 2 : 0);
}

// ── leitura ──────────────────────────────────────────────────────────────────
const lenArg = Number(val("--len", sectName ? "4096" : "64"));
if (!Number.isFinite(lenArg) || lenArg <= 0) {
  console.error("[!!] --len precisa ser um inteiro positivo");
  process.exit(2);
}
const maxEnd = Math.min(buf.length, (sectionOf(startRva) ? sectionOf(startRva).raw + sectionOf(startRva).rawSize : buf.length));
const len = Math.min(lenArg, maxEnd - startOff);
const data = buf.subarray(startOff, startOff + len);

const READERS = {
  u8: { size: 1, read: (o) => `${data[o]}` },
  i8: { size: 1, read: (o) => `${data.readInt8(o)}` },
  u16: { size: 2, read: (o) => `${data.readUInt16LE(o)}` },
  i16: { size: 2, read: (o) => `${data.readInt16LE(o)}` },
  u32: { size: 4, read: (o) => `${data.readUInt32LE(o)} (${hex(data.readUInt32LE(o), 8)})` },
  i32: { size: 4, read: (o) => `${data.readInt32LE(o)}` },
  // BigInt direto: converter para Number antes do toString(16) perde precisão acima de 2^53
  // e imprime um hexadecimal que NÃO é o valor lido (medido: 0xfffffffe00001000 virava
  // 0xfffffffe00001000 em vez do valor de 64 bits real). É exatamente o erro que o script
  // existe para evitar, e foi o teste deste script que o pegou.
  u64: { size: 8, read: (o) => { const v = data.readBigUInt64LE(o); return `${v} (0x${v.toString(16).padStart(16, "0")})`; } },
  i64: { size: 8, read: (o) => `${data.readBigInt64LE(o)}` },
  f32: { size: 4, read: (o) => `${data.readFloatLE(o)}` },
  f64: { size: 8, read: (o) => `${data.readDoubleLE(o)}` },
  hex: { size: 1, read: null },            // tratado no dump
  ascii: { size: 1, read: null },          // tratado abaixo (string inteira)
  utf16: { size: 2, read: null },
  cstring: { size: 1, read: null },
  wcstring: { size: 2, read: null },
};
// `file` pode ser indefinido se todas as flags vieram antes do arquivo; falha clara.
if (!file) {
  console.error("[!!] informe o arquivo antes das flags (ex.: node scripts/pe-read.mjs alvo.exe --rva 0x4000)");
  process.exit(2);
}
function cstring(o, wide, stopAtEnd = true) {
  const chars = [];
  if (wide) {
    for (let i = o; i + 1 < data.length; i += 2) {
      if (data[i] === 0 && data[i + 1] === 0) break;
      chars.push(String.fromCharCode(data.readUInt16LE(i)));
      if (chars.length > 4096) break;
    }
  } else {
    for (let i = o; i < data.length; i++) {
      if (data[i] === 0) break;
      chars.push(String.fromCharCode(data[i]));
      if (chars.length > 4096) break;
    }
  }
  const s = chars.join("");
  if (s === "" && stopAtEnd) return null;
  return s;
}

const typed = {};
for (const a of asList) {
  if (a === "hex" || a === "ascii") continue;
  if (a === "cstring" || a === "wcstring") {
    const s = cstring(0, a === "wcstring");
    typed[a] = s === null ? "(sem terminador no intervalo — aumente --len)" : s;
    continue;
  }
  if (a === "utf16") {
    typed[a] = cstring(0, true) ?? "";
    continue;
  }
  const r = READERS[a];
  const vals = [];
  for (let o = 0; o + r.size <= data.length; o += r.size) vals.push(r.read(o));
  typed[a] = vals;
}

const lines = [];
for (let i = 0; i < data.length; i += 16) {
  const chunk = data.subarray(i, i + 16);
  const hexs = Array.from(chunk, (b) => b.toString(16).padStart(2, "0")).join(" ");
  const txt = Array.from(chunk, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
  const rva = startRva !== null ? `rva ${hex(startRva + i, 6)}` : `rva ?      `;
  lines.push(`  off ${hex(startOff + i, 6)}  ${rva}  ${pad(hexs, 47)}  ${txt}`);
}

if (JSON_OUT) {
  console.log(JSON.stringify({
    file, imageBase: hex(imageBase), from: startRva !== null ? hex(startRva) : null,
    offset: hex(startOff), length: len, section: sectionOf(startRva)?.name ?? null,
    bytes: Array.from(data, (b) => b.toString(16).padStart(2, "0")).join(" "),
    typed,
  }, null, 2));
} else {
  console.log("");
  console.log(`UnboxRE — leitura de bytes: ${file}`);
  console.log("─".repeat(78));
  const s = sectionOf(startRva);
  console.log(`  ${how} · ${len} byte(s)${s ? ` · seção ${s.name} (${perms(s)}, offset no arquivo ${hex(s.raw, 6)})` : ""}`);
  console.log("");
  for (const l of lines) console.log(l);
  console.log("");
  console.log("  leitura tipada (little-endian):");
  for (const [k, v] of Object.entries(typed)) {
    if (Array.isArray(v)) {
      const shown = v.slice(0, 16).join(", ") + (v.length > 16 ? `, … (+${v.length - 16})` : "");
      console.log(`    ${pad(k, 8)} [${v.length}] ${shown}`);
    } else {
      console.log(`    ${pad(k, 8)} ${JSON.stringify(v)}`);
    }
  }
  console.log("");
}

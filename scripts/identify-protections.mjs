#!/usr/bin/env node
/**
 * identify-protections.mjs — first-pass packer/protector triage for PE **and ELF** files.
 *
 * Why this exists
 * ---------------
 * The first question in any triage is "is this binary packed, and with what?" —
 * it decides whether you decompile the real code or a stub. Die (Detect It Easy)
 * answers it well, but it is a third-party tool the bootstrap installs separately.
 * This script gives the toolkit a built-in, dependency-free FIRST pass: it reads
 * the PE headers and section table directly and matches packer/protector
 * signatures (UPX, VMProtect, Themida/WinLicense, ASPack, PECompact, MPRESS,
 * Petite, Enigma, and the .NET CLR header), plus entropy and structural
 * heuristics. It is a triage signal, not a verdict: it points you at the payload
 * extractor, it does not replace dynamic confirmation.
 *
 * Confidence levels, and what the verdict actually means
 * -----------------------------------------------------
 *   high   a signature or structure that identifies a protector
 *   medium evidence of a rebuilt/relocated image (EP outside .text, section
 *          without file data) — suspicious, not conclusive
 *   low    statistics (high entropy)
 *   info   a fact about the FORMAT, not a protection: the CLR header means
 *          "managed assembly", which is true of every .NET binary. It is
 *          reported, but it must never by itself produce "PROVAVELMENTE
 *          PROTEGIDO" — that false positive fired on powershell.exe (and every
 *          other managed binary) until this note and the verdict rule below.
 *
 * ELF
 * ---
 * Added in round 8.3, after an ELF target was refused here with "not a PE". The same
 * order of evidence applies, with the ELF equivalents: section names come from
 * `.shstrtab` (so a stripped binary still names its sections), the W+X **LOAD segment**
 * replaces the W+X section, the entry point outside any LOAD replaces EP outside .text,
 * and `ptrace` in the dynamic strings is a Linux anti-debug signal worth reporting.
 *
 * Usage: node scripts/identify-protections.mjs <file[.exe]> [--json]
 * Exit:  0 analysed (even if packed) · 2 could not read the file / unknown format.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";

const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const file = args.find((a) => !a.startsWith("--"));
if (!file) {
  console.error("uso: node scripts/identify-protections.mjs <arquivo> [--json]   (PE ou ELF)");
  process.exit(2);
}

let buf;
try {
  buf = readFileSync(file);
} catch (e) {
  console.error(`não consegui ler ${file}: ${e.message}`);
  process.exit(2);
}

const u16 = (o) => buf.readUInt16LE(o);
const u32 = (o) => buf.readUInt32LE(o);

function shannonEntropy(bytes) {
  if (!bytes.length) return 0;
  const freq = new Array(256).fill(0);
  for (const b of bytes) freq[b]++;
  let h = 0;
  for (const f of freq) {
    if (!f) continue;
    const p = f / bytes.length;
    h -= p * Math.log2(p);
  }
  return h; // 0..8
}

const findings = [];
const add = (name, confidence, detail) => findings.push({ name, confidence, detail });

// ── ELF (Linux) ──────────────────────────────────────────────────────────────
// O escopo validado do toolkit é Windows, mas "está protegido? com o quê?" é a PRIMEIRA
// pergunta de qualquer triagem — e um alvo ELF (round 8.3) não tinha caminho aqui: este
// script saía em "não é um PE (sem assinatura MZ)", que não responde nada. A lógica é a
// mesma (assinatura > estrutura > estatística) com os equivalentes de ELF: o segmento LOAD
// gravável+executável no lugar da seção W+X, o entrypoint fora do LOAD no lugar do EP fora
// de .text, e as seções vindo da .shstrtab.
if (buf.length >= 0x40 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
  if (buf[5] !== 1 || (buf[4] !== 1 && buf[4] !== 2)) {
    console.error(`${file}: ELF não lido aqui (EI_CLASS=${buf[4]}, EI_DATA=${buf[5]}) — este script lê ELF32/ELF64 little-endian`);
    process.exit(2);
  }
  const is64 = buf[4] === 2;
  const u64 = (o) => Number(buf.readBigUInt64LE(o));
  const eType = u16(16);
  const eEntry = is64 ? u64(24) : u32(24);
  const phoff = is64 ? u64(0x20) : u32(0x1c);
  const phentsize = u16(is64 ? 0x36 : 0x2a);
  const phnum = u16(is64 ? 0x38 : 0x2c);
  const shoff = is64 ? u64(0x28) : u32(0x20);
  const shentsize = u16(is64 ? 0x3a : 0x2e);
  const shnum = u16(is64 ? 0x3c : 0x30);
  const shstrndx = u16(is64 ? 0x3e : 0x32);
  const SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4;

  const shRaw = [];
  for (let i = 0; i < shnum; i++) {
    const o = shoff + i * shentsize;
    if (o + shentsize > buf.length) break;
    shRaw.push(is64
      ? { nameOff: u32(o), type: u32(o + 4), flags: u64(o + 8), addr: u64(o + 16), off: u64(o + 24), size: u64(o + 32) }
      : { nameOff: u32(o), type: u32(o + 4), flags: u32(o + 8), addr: u32(o + 12), off: u32(o + 16), size: u32(o + 20) });
  }
  const shstr = shRaw[shstrndx];
  const nameAt = (off) => {
    const o = shstr ? shstr.off + off : -1;
    if (!(o >= 0 && o < buf.length)) return "";
    let e = o;
    while (e < buf.length && buf[e] !== 0) e++;
    return buf.subarray(o, e).toString("latin1");
  };
  const elfSections = shRaw.map((s) => ({
    name: nameAt(s.nameOff) || "(sem nome)",
    virtualSize: s.size,
    sizeRaw: s.type === 8 ? 0 : s.size,          // SHT_NOBITS (.bss): memória, não arquivo
    virtualAddress: s.addr,
    // .bss não tem byte nenhum no arquivo: entropia sobre bytes que não existem é ruído
    // (a versão anterior deste branch imprimia 3.94 para um `.bss` vazio).
    entropy: s.type === 8 ? 0 : Number(shannonEntropy(buf.subarray(s.off, s.off + Math.min(s.size, 0x40000))).toFixed(2)),
    writable: !!(s.flags & SHF_WRITE),
    executable: !!(s.flags & SHF_EXECINSTR),
    rawSizeZero: s.type === 8,
  }));

  const segs = [];
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize;
    if (o + phentsize > buf.length) break;
    segs.push(is64
      ? { type: u32(o), flags: u32(o + 4), off: u64(o + 8), vaddr: u64(o + 16), filesz: u64(o + 32), memsz: u64(o + 40) }
      : { type: u32(o), off: u32(o + 4), vaddr: u32(o + 8), filesz: u32(o + 16), memsz: u32(o + 20), flags: u32(o + 24) });
  }
  const loads = segs.filter((s) => s.type === 1);
  const inLoad = (a) => loads.some((s) => a >= s.vaddr && a < s.vaddr + s.memsz);

  // ── assinaturas ──
  const lowerNames = elfSections.map((s) => s.name.toLowerCase());
  const text = buf.toString("latin1");
  if (shnum === 0) {
    add("Sem tabela de seções", "medium", "ELF sem section headers — o UPX (`--strip-sections`) e packers que reescrevem a imagem fazem exatamente isso; a triagem por nome de seção deixa de valer e sobra a via estrutural");
  }
  if (lowerNames.some((n) => n.includes("upx")) || /UPX!/.test(text)) {
    add("UPX", "high", "seção UPX* ou marcador UPX! — packer UPX (o mesmo dos alvos PE; o binário empacotado traz um stub que desempacota em memória)");
  }
  if (lowerNames.includes(".vmp0") || lowerNames.includes(".vmp1") || /VMProtect/i.test(text)) {
    add("VMProtect", "high", "seção .vmpN ou string VMProtect — proteção por virtualização");
  }
  if (/SHC_MARKER|shc_marker|shc_arc/i.test(text)) {
    add("Shc (shell script compiler)", "medium", "marcadores do shc — script shell compilado em ELF (o código real é um script " +
      "cifrado, não este binário)");
  }

  // ── estrutura ──
  const wxLoads = segs.filter((s) => s.type === 1 && (s.flags & 2) && (s.flags & 1));
  if (wxLoads.length) {
    add("Segmento LOAD gravável E executável", "medium", `LOAD W+X em ${wxLoads.map((s) => `0x${s.vaddr.toString(16)}`).join(", ")} — compilador normal não emite isso; stub que se desempacota e VMProtect fazem`);
  }
  if (!inLoad(eEntry)) {
    add("Entrypoint fora de qualquer LOAD", "medium", `e_entry=0x${eEntry.toString(16)} não cai em nenhum segmento carregado — só o loader do kernel roda assim`);
  }
  if (!segs.some((s) => s.type === 3)) {
    add("Sem PT_INTERP", "info", "sem interpreter: binário estático (não é proteção — muda quem é o libc)");
  }
  if (!segs.some((s) => s.type === 2)) {
    add("Sem PT_DYNAMIC", "info", "sem .dynamic: estático ou já reescrito por um packer (cruze com as seções)");
  }
  const highEnt = elfSections.filter((s) => s.entropy >= 7.2 && s.sizeRaw > 0);
  if (highEnt.length) {
    add("Alta entropia", "low", `seções com entropia >= 7.2: ${highEnt.map((s) => s.name).join(", ")} — dado comprimido/cifrado (em ELF, `.rodata` de tabela também entra aqui)`);
  }
  if (!lowerNames.includes(".symtab")) {
    add("Sem .symtab", "info", "stripped: os nomes de função/símbolo não estão no arquivo; a leitura vem do disassembly (ptrace/anti-debug também conta com isso)");
  }
  if (/\bptrace\b/.test(text)) {
    add("Importa ptrace", "medium", "o binário chama `ptrace` — anti-debug clássico em Linux (PTRACE_TRACEME faz o próprio processo recusar um depurador já anexado)");
  }

  const notable = findings.filter((f) => f.confidence !== "info");
  const packed = findings.some((f) => f.confidence === "high");
  const MACH = { 0x03: "x86", 0x3e: "x64", 0x28: "ARM", 0xb7: "ARM64", 0xf3: "RISC-V" }[u16(18)] ?? `0x${u16(18).toString(16)}`;
  const TYPE = { 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN (PIE/shared)", 4: "ET_CORE" }[eType] ?? `e_type=0x${eType.toString(16)}`;
  const report = {
    file: basename(file),
    size: buf.length,
    format: is64 ? "ELF64" : "ELF32",
    type: TYPE,
    machine: MACH,
    entryPoint: `0x${eEntry.toString(16)}`,
    sections: elfSections.map((s) => ({ name: s.name, virtualSize: s.virtualSize, rawSize: s.sizeRaw, entropy: s.entropy, flags: `${s.writable ? "W" : "-"}${s.executable ? "X" : "-"}` })),
    segments: segs.map((s) => ({ type: s.type, vaddr: `0x${s.vaddr.toString(16)}`, filesz: s.filesz, memsz: s.memsz, perms: `${s.flags & 4 ? "R" : "-"}${s.flags & 2 ? "W" : "-"}${s.flags & 1 ? "X" : "-"}` })),
    findings,
    verdict: notable.length === 0 ? "sem assinatura conhecida" : packed ? "PROVAVELMENTE PROTEGIDO" : "possivelmente incomum",
  };

  if (JSON_OUT) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }
  console.log("");
  console.log(`UnboxRE — triagem de proteção: ${report.file}`);
  console.log("─".repeat(66));
  console.log(`  tamanho: ${report.size} bytes · ${report.format} · ${report.type} · arq: ${report.machine} · entrypoint: ${report.entryPoint}`);
  console.log(`  segmentos (program headers): ${segs.length} · seções: ${elfSections.length}`);
  console.log("  seções:");
  for (const s of report.sections) {
    console.log(`    ${s.name.padEnd(10)} virt=${String(s.virtualSize).padEnd(8)} raw=${String(s.rawSize).padEnd(8)} entropia=${s.entropy} ${s.flags}`);
  }
  console.log("");
  const tag = { high: "!!", medium: "? ", low: "? ", info: "i " };
  for (const f of report.findings) console.log(`  [${tag[f.confidence] ?? "? "}] ${f.name} (${f.confidence}) — ${f.detail}`);
  if (report.verdict === "sem assinatura conhecida") console.log("  [ok] nenhuma assinatura de packer/protetor conhecida.");
  console.log(`\n  Veredito: ${report.verdict}`);
  console.log("");
  process.exit(0);
}

if (u16(0) !== 0x5a4d) {
  console.error(`${file}: nem assinatura "MZ" (PE) nem "\\x7fELF" — formato não reconhecido`);
  process.exit(2);
}
const peOff = u32(0x3c);
if (u32(peOff) !== 0x00004550) {
  console.error(`${file}: assinatura PE ausente em 0x${peOff.toString(16)}`);
  process.exit(2);
}

const machine = u16(peOff + 4);
const nSections = u16(peOff + 6);
const sizeOpt = u16(peOff + 20);
const optOff = peOff + 24;
const magic = u16(optOff);
const is64 = magic === 0x20b;
const entryPoint = u32(optOff + 16);
const numDirsOff = is64 ? optOff + 108 : optOff + 92;
const nDirs = u32(numDirsOff);
const dirsOff = is64 ? optOff + 112 : optOff + 96;

function dataDir(i) {
  if (i >= nDirs) return { rva: 0, size: 0 };
  return { rva: u32(dirsOff + i * 8), size: u32(dirsOff + i * 8 + 4) };
}
const clrDir = dataDir(14); // COM descriptor / .NET
const importDir = dataDir(1);

const secOff = optOff + sizeOpt;
const sections = [];
for (let i = 0; i < nSections; i++) {
  const o = secOff + i * 40;
  if (o + 40 > buf.length) break;
  const name = buf.toString("latin1", o, o + 8).replace(/\0+$/, "");
  const virtualSize = u32(o + 8);
  const virtualAddress = u32(o + 12);
  const sizeRaw = u32(o + 16);
  const ptrRaw = u32(o + 20);
  const characteristics = u32(o + 36);
  const raw = buf.subarray(ptrRaw, ptrRaw + Math.min(sizeRaw, 0x40000)); // cap for speed
  sections.push({
    name,
    virtualSize,
    virtualAddress,
    sizeRaw,
    characteristics,
    entropy: Number(shannonEntropy(raw).toFixed(2)),
    writable: !!(characteristics & 0x80000000),
    executable: !!(characteristics & 0x20000000),
    rawSizeZero: sizeRaw === 0,
  });
}

const secNames = sections.map((s) => s.name);
const lowerNames = secNames.map((n) => n.toLowerCase());
const strings = buf.toString("latin1"); // coarse; enough for ASCII markers

// ── Signature table ──────────────────────────────────────────────────────────
function anySection(pred) { return sections.some(pred); }
function nameIs(...names) { return names.some((n) => lowerNames.includes(n.toLowerCase())); }

if (nameIs("UPX0", "UPX1", "UPX2") || lowerNames.some((n) => n.startsWith(".upx")) || /UPX!/.test(strings)) {
  add("UPX", "high", "seções UPX0/UPX1 ou marcador UPX! — packer UPX"); 
}
if (nameIs(".vmp0", ".vmp1", ".vmp2") || /VMProtect|\.vmp\d/i.test(strings)) {
  add("VMProtect", "high", "seções .vmpN ou string VMProtect — proteção por virtualização");
}
if (nameIs(".themida", ".winlice", ".tmd") || /Themida|WinLicense|Oreans/i.test(strings)) {
  add("Themida / WinLicense", "high", "seção ou marcador Themida/WinLicense");
}
if (nameIs(".aspack", ".adata") || /ASPack/i.test(strings)) {
  add("ASPack", "medium", "seção .aspack/.adata");
}
if (nameIs(".pec") || /PECompact/i.test(strings)) {
  add("PECompact", "medium", "seção .pec/marcador PECompact");
}
if (nameIs(".MPRESS1", ".MPRESS2")) {
  add("MPRESS", "high", "seções .MPRESS1/.MPRESS2");
}
if (nameIs(".petite")) {
  add("Petite", "medium", "seção .petite");
}
if (nameIs(".enigma1", ".enigma2")) {
  add("Enigma Protector", "high", "seções .enigmaN");
}
if (clrDir.rva !== 0 || /mscoree\.dll/i.test(strings)) {
  add(".NET (CLR)", "info", "cabeçalho CLR (COM descriptor) presente — assembly gerenciado (não é proteção; se estiver ofuscado, use de4dot/NETReactorSlayer)");
}

// ── Structural heuristics ────────────────────────────────────────────────────
const epSection = sections.find((s) => entryPoint >= s.virtualAddress && entryPoint < s.virtualAddress + Math.max(s.virtualSize, s.sizeRaw));

// Padrão estrutural de protetor moderno (VMProtect 3.x).
//
// Achado com amostra real (VMProtect 3.11 demo protegendo um PE): as seções
// ORIGINAIS ficam sem dados no arquivo (rawSize 0, virtualSize > 0) e todo o
// conteúdo vai para seções novas de alta entropia com nomes fora do padrão
// (".4/.", ".xS&", ".i^-"), uma delas contendo o entry point. O VMProtect 3.x
// NÃO deixa mais ".vmpN" nem marcador em texto/UTF-16 — a tabela por nome/marcador
// não o vê; esta combinação vê. É um padrão estrutural, não uma assinatura de
// bytes, e é por isso que o achado explica a evidência em vez de só nomear.
const standardName = (n) => /^\.(text|code|rdata|data|pdata|idata|didat|rsrc|reloc|sdata|bss|tls|debug|CRT|itext|edata|ndata|xdata)/i.test(n);
const emptiedStandard = sections.filter((s) => s.rawSizeZero && s.virtualSize > 0x1000 && standardName(s.name));
const junkCarrier = sections.filter((s) => s.sizeRaw > 0 && s.entropy >= 7.0 && !standardName(s.name));
if (epSection && !standardName(epSection.name) && epSection.entropy >= 7.0 &&
    emptiedStandard.length >= 2 && junkCarrier.length >= 1) {
  add("VMProtect 3.x (padrão estrutural)", "high",
    `seções originais esvaziadas (${emptiedStandard.map((s) => s.name).join(", ")}); conteúdo em seção nova de alta entropia, com o entry point em "${epSection.name}" (entropia ${epSection.entropy}, nome fora do padrão) — envelope típico de VMProtect 3.x, que não deixa marcador textual`);
}
if (epSection && !/\.text|\.code/i.test(epSection.name)) {
  add("Entry point fora de .text", "medium", `entrypoint cai em "${epSection.name}"`);
}
if (epSection && epSection.writable) {
  add("Seção de código gravável", "medium", `"${epSection.name}" é W+X — típico de stub que se desempacota`);
}
const highEntropy = sections.filter((s) => s.entropy >= 7.2 && s.sizeRaw > 0);
if (highEntropy.length) {
  add("Alta entropia", "low", `seções com entropia >= 7.2: ${highEntropy.map((s) => s.name).join(", ")}`);
}
if (importDir.rva === 0 || importDir.size === 0) {
  add("Sem tabela de imports", "medium", "imports quase ausentes — comum em binários empacotados");
}
const lowRawHighVirt = sections.filter((s) => s.rawSizeZero && s.virtualSize > 0x1000);
if (lowRawHighVirt.length) {
  add("Seções virtuais sem dados no arquivo", "medium", lowRawHighVirt.map((s) => s.name).join(", "));
}

// A verdict must be driven by evidence of PROTECTION, never by a format marker.
// 'info' findings are reported (they are useful) but cannot, on their own, turn a
// clean binary into "PROVAVELMENTE PROTEGIDO" — that is the whole point of the
// level existing.
//
// Measured against 60 stock Windows binaries: treating high entropy alone as
// "PROVAVELMENTE PROTEGIDO" flagged 5 of them (Windows Update binaries with a
// compressed resource, Defrag, ClipUp…). A low-confidence statistic is not a
// protection verdict, so the top verdict now requires a HIGH finding (a real
// signature/structure); entropy and medium signals land on "possivelmente
// incomum", which is the honest label for "something is off, look closer".
const notable = findings.filter((f) => f.confidence !== "info");
const packed = findings.some((f) => f.confidence === "high");

const report = {
  file: basename(file),
  size: buf.length,
  machine: is64 ? "x64" : "x86",
  entryPoint: `0x${entryPoint.toString(16)}`,
  sections: sections.map((s) => ({ name: s.name, virtualSize: s.virtualSize, rawSize: s.sizeRaw, entropy: s.entropy, flags: `${s.writable ? "W" : "-"}${s.executable ? "X" : "-"}` })),
  findings,
  verdict: notable.length === 0 ? "sem assinatura conhecida" : packed ? "PROVAVELMENTE PROTEGIDO" : "possivelmente incomum",
};

if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log("");
  console.log(`UnboxRE — triagem de proteção: ${report.file}`);
  console.log("─".repeat(66));
  console.log(`  tamanho: ${report.size} bytes · arq: ${report.machine} · entrypoint: ${report.entryPoint}`);
  console.log("  seções:");
  for (const s of report.sections) {
    console.log(`    ${s.name.padEnd(10)} virt=${String(s.virtualSize).padEnd(8)} raw=${String(s.rawSize).padEnd(8)} entropia=${s.entropy} ${s.flags}`);
  }
  console.log("");
  const tag = { high: "!!", medium: "? ", low: "? ", info: "i " };
  for (const f of report.findings) {
    console.log(`  [${tag[f.confidence] ?? "? "}] ${f.name} (${f.confidence}) — ${f.detail}`);
  }
  if (report.verdict === "sem assinatura conhecida") {
    console.log("  [ok] nenhuma assinatura de packer/protetor conhecida.");
  }
  console.log(`\n  Veredito: ${report.verdict}`);
  console.log("");
}

process.exit(0);

#!/usr/bin/env node
/**
 * identify-protections.mjs — first-pass packer/protector triage for PE files.
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
 * Usage: node scripts/identify-protections.mjs <file.exe> [--json]
 * Exit:  0 analysed (even if packed) · 2 could not read the file.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";

const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const file = args.find((a) => !a.startsWith("--"));
if (!file) {
  console.error("uso: node scripts/identify-protections.mjs <arquivo.exe> [--json]");
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

if (u16(0) !== 0x5a4d) {
  console.error(`${file}: não é um PE (sem assinatura MZ)`);
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
  add(".NET (CLR)", "high", "cabeçalho CLR (COM descriptor) presente — assembly gerenciado");
}

// ── Structural heuristics ────────────────────────────────────────────────────
const epSection = sections.find((s) => entryPoint >= s.virtualAddress && entryPoint < s.virtualAddress + Math.max(s.virtualSize, s.sizeRaw));
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

const packed = findings.some((f) => f.confidence === "high") || highEntropy.length > 0;

const report = {
  file: basename(file),
  size: buf.length,
  machine: is64 ? "x64" : "x86",
  entryPoint: `0x${entryPoint.toString(16)}`,
  sections: sections.map((s) => ({ name: s.name, virtualSize: s.virtualSize, rawSize: s.sizeRaw, entropy: s.entropy, flags: `${s.writable ? "W" : "-"}${s.executable ? "X" : "-"}` })),
  findings,
  verdict: findings.length === 0 ? "sem assinatura conhecida" : packed ? "PROVAVELMENTE PROTEGIDO" : "possivelmente incomum",
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
  if (report.findings.length === 0) {
    console.log("  [ok] nenhuma assinatura de packer/protetor conhecida.");
  } else {
    for (const f of report.findings) console.log(`  [${f.confidence === "high" ? "!!" : "? "}] ${f.name} (${f.confidence}) — ${f.detail}`);
  }
  console.log(`\n  Veredito: ${report.verdict}`);
  console.log("");
}

process.exit(0);

#!/usr/bin/env node
/**
 * diagnose-load.mjs — "por que este .exe não carrega?" (falha de loader, ex. 0xC000007B).
 *
 * Por que existe
 * --------------
 * `identify-protections.mjs` responde "está protegido?". Este responde a pergunta
 * seguinte, que aparece logo depois: **"então por que ele sai com 0xC000007B antes
 * de qualquer análise dinâmica ser possível?"**. `STATUS_INVALID_IMAGE_FORMAT`
 * (0xC000007B) é o loader rejeitando a imagem — e o motivo costuma estar em duas
 * coisas que empacotadores/protetores mexem quando remontam o arquivo:
 *
 *   1. seções ORIGINAIS esvaziadas (SizeOfRawData = 0) — inclusive `.rdata`/`.data`;
 *   2. o mapa de relocações / o load config, que deixam de cobrir o que precisam.
 *
 * O caso real que originou este script: builds DEMO de VMProtect 3.11 e Themida
 * 3.2.4 esvaziam as seções originais do alvo e o Windows 11 (build 26200) passa a
 * rejeitar a imagem com 0xC000007B, ANTES do entrypoint. A investigação completa,
 * com a reprodução mínima e a matriz de experimentos, está em
 * `reports/root-cause-0xc000007b.md`.
 *
 * O que ele faz
 * -------------
 *   1. lê o PE sem dependência externa e aponta os vícios conhecidos (seções
 *      vazias, data directories apontando para seção sem dados, DYNAMIC_BASE sem
 *      relocações, alvos de relocação em seção sem dados);
 *   2. EXECUTA o alvo (a menos que --no-run) e reporta o status real do loader;
 *      no Windows o status é o NTSTATUS completo (ex. 3221225595 = 0xC000007B).
 *
 * Uso: node scripts/diagnose-load.mjs <arquivo.exe> [--no-run] [--json]
 * Exit: 0 analisado e o alvo carregou (ou --no-run) · 1 o loader rejeitou ·
 *       2 não consegui ler/executar. Nunca usa sudo.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h") || args.length === 0) {
  console.log("uso: node scripts/diagnose-load.mjs <arquivo.exe> [--no-run] [--json]");
  console.log("  --no-run  só a análise estática (não executa o alvo)");
  process.exit(args.length === 0 ? 2 : 0);
}
const JSON_OUT = args.includes("--json");
const NO_RUN = args.includes("--no-run");
const file = args.find((a) => !a.startsWith("--"));

let buf;
try {
  buf = readFileSync(file);
} catch (e) {
  console.error(`não consegui ler ${file}: ${e.message}`);
  process.exit(2);
}
if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) {
  console.error(`${file}: não é um PE (sem assinatura MZ)`);
  process.exit(2);
}
const u16 = (o) => buf.readUInt16LE(o);
const u32 = (o) => buf.readUInt32LE(o);
const pe = u32(0x3c);
if (u32(pe) !== 0x00004550) {
  console.error(`${file}: assinatura PE ausente em 0x${pe.toString(16)}`);
  process.exit(2);
}
const is64 = u16(pe + 24) === 0x20b;
const opt = pe + 24;
const nSec = u16(pe + 6);
const dirsOff = is64 ? opt + 112 : opt + 96;
const secOff = opt + u16(pe + 20);
const sizeOfImage = u32(opt + 56);
const dllChar = u16(opt + 70);

const DIRNAME = ["export", "import", "resource", "exception", "security(fileoff)", "basereloc", "debug", "arch", "globalptr", "tls", "loadconfig", "boundimport", "iat", "delayimport", "clr", "reserved"];

const sections = [];
for (let i = 0; i < nSec; i++) {
  const o = secOff + i * 40;
  if (o + 40 > buf.length) break;
  sections.push({
    index: i,
    name: buf.toString("latin1", o, o + 8).replace(/\0+$/, "") || "<sem nome>",
    virtualSize: u32(o + 8),
    virtualAddress: u32(o + 12),
    sizeRaw: u32(o + 16),
    ptrRaw: u32(o + 20),
    characteristics: u32(o + 36),
  });
}
const findSection = (rva) =>
  sections.find((s) => rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.sizeRaw));
const rva2off = (rva) => {
  const s = findSection(rva);
  if (!s) return -1;
  const off = s.ptrRaw + (rva - s.virtualAddress);
  return off >= 0 && off < buf.length ? off : -1;
};

// ── Findings ────────────────────────────────────────────────────────────────
const findings = [];
const add = (level, code, detail) => findings.push({ level, code, detail });

const emptied = sections.filter((s) => s.virtualSize > 0 && s.sizeRaw === 0);
if (emptied.length) {
  add("medium", "secoes-esvaziadas",
    `${emptied.length} seção(ões) com VirtualSize > 0 e SizeOfRawData = 0 (dados removidos do arquivo): ${emptied.map((s) => s.name).join(", ")}`);
}

// Data directories that land in a section with no file data (or run past its raw end)
for (let i = 0; i < 16; i++) {
  const rva = u32(dirsOff + i * 8), size = u32(dirsOff + i * 8 + 4);
  if (!rva || !size) continue;
  if (i === 4) continue; // SECURITY is a file offset, not an RVA
  const s = findSection(rva);
  if (!s) { add("high", "dir-fora-de-secao", `data directory ${i} (${DIRNAME[i]}) rva=0x${rva.toString(16)} não cai em nenhuma seção`); continue; }
  if (s.sizeRaw === 0) {
    // Esperado em empacotadores (o stub restaura o dado em tempo de execução) — por
    // isso NÃO é "high". Virou achado só depois de medir: zerar esses diretórios no
    // output do UPX não fez o binário carregar, então marcar isto como causa seria
    // um falso positivo. Fica como sinal a olhar junto com o resto.
    add("medium", "dir-em-secao-vazia", `data directory ${i} (${DIRNAME[i]}) rva=0x${rva.toString(16)} aponta para "${s.name}", que não tem dados no arquivo (normal em empacotadores; suspeito se não houver stub de unpack)`);
  } else if (rva - s.virtualAddress + size > s.sizeRaw) {
    add("medium", "dir-passa-do-raw", `data directory ${i} (${DIRNAME[i]}) rva=0x${rva.toString(16)}/0x${size.toString(16)} passa do fim dos dados de "${s.name}" (rawSize=0x${s.sizeRaw.toString(16)})`);
  }
}

// DYNAMIC_BASE without relocations => the loader must relocate but cannot
const reloc = { rva: u32(dirsOff + 5 * 8), size: u32(dirsOff + 5 * 8 + 4) };
const dynamicBase = (dllChar & 0x0040) !== 0;
if (dynamicBase && !reloc.rva) {
  add("high", "aslr-sem-reloc",
    "DLLCHARACTERISTICS_DYNAMIC_BASE definido mas o data directory BASERELOC está vazio: o loader é obrigado a relocar e não tem mapa — sai com STATUS_INVALID_IMAGE_FORMAT");
}
if (reloc.rva) {
  const rs = findSection(reloc.rva);
  if (rs && rs.sizeRaw === 0) {
    add(dynamicBase ? "high" : "medium", "reloc-em-secao-vazia",
      dynamicBase
        ? `.reloc aponta para "${rs.name}", que não tem dados, com DYNAMIC_BASE ligado: o loader é obrigado a relocar e não tem o mapa — sai com STATUS_INVALID_IMAGE_FORMAT`
        : `.reloc aponta para "${rs.name}", sem dados no arquivo`);
  }
}

// Relocation targets that land in sections with no file data
if (reloc.rva && reloc.size) {
  const base = rva2off(reloc.rva);
  if (base < 0) add("high", "reloc-ilegivel", `.reloc rva=0x${reloc.rva.toString(16)} não é legível no arquivo`);
  else {
    let p = base, end = base + reloc.size, count = 0;
    const badTargets = new Map();
    while (p + 8 <= end && p + 8 <= buf.length) {
      const pageRva = u32(p), blockSize = u32(p + 4);
      if (blockSize < 8) break;
      for (let i = 0; i + 1 < (blockSize - 8) / 2; i++) {
        const e = u16(p + 8 + i * 2);
        if (!(e >> 12)) continue;
        count++;
        const t = pageRva + (e & 0xfff);
        const s = findSection(t);
        if (!s || s.sizeRaw === 0) {
          const k = s ? `${s.name} (sem dados)` : "<fora de seção>";
          badTargets.set(k, (badTargets.get(k) || 0) + 1);
        }
      }
      p += blockSize;
    }
    if (badTargets.size) {
      add("high", "reloc-alvo-sem-dados",
        `${[...badTargets.values()].reduce((a, b) => a + b, 0)} de ${count} entradas de relocação apontam para seção SEM dados (é o gatilho medido em reports/root-cause-0xc000007b.md §4): ${[...badTargets.entries()].map(([k, v]) => `${k}×${v}`).join(", ")}`);
    } else if (count) {
      add("info", "reloc-ok", `${count} entradas de relocação, todas em seções com dados`);
    }
  }
}

// ── Run the target ──────────────────────────────────────────────────────────
const NTSTATUS = {
  0x0: "ok",
  0xc000007b: "STATUS_INVALID_IMAGE_FORMAT (loader rejeitou a imagem)",
  0xc0000135: "STATUS_DLL_NOT_FOUND",
  0xc0000138: "STATUS_ORDINAL_NOT_FOUND",
  0xc0000139: "STATUS_ENTRYPOINT_NOT_FOUND",
  0xc0000142: "STATUS_DLL_INIT_FAILED",
  0xc0000409: "STATUS_STACK_BUFFER_OVERRUN (__fastfail — comum com CFG)",
  0xc0000005: "STATUS_ACCESS_VIOLATION",
  0xc000001d: "STATUS_ILLEGAL_INSTRUCTION",
  0x80000003: "STATUS_BREAKPOINT",
};
let run = { skipped: true };
if (!NO_RUN) {
  const r = spawnSync(file, [], { timeout: 8000 });
  const status = r.status === null ? null : r.status >>> 0;
  run = {
    skipped: false,
    exit: status,
    hex: status === null ? null : `0x${status.toString(16)}`,
    meaning: status === null ? (r.error ? r.error.code : "sem status (timeout/sinal)") : (NTSTATUS[status] || "status não catalogado"),
  };
  if (run.exit === 0xc000007b) {
    add("high", "loader-rejeitou", "a execução terminou com 0xC000007B: o loader rejeitou a imagem ANTES do entrypoint (é isto que este script diagnostica)");
  }
}

const verdict =
  findings.some((f) => f.level === "high") ? "imagem com vícios de loader conhecidos"
  : findings.some((f) => f.level === "medium") ? "sinais de remontagem, sem vício crítico"
  : "sem vício de loader conhecido";

const report = {
  file: basename(file),
  size: buf.length,
  machine: is64 ? "x64" : "x86",
  sizeOfImage: `0x${sizeOfImage.toString(16)}`,
  dllCharacteristics: `0x${dllChar.toString(16)}`,
  sections: sections.map((s) => ({ name: s.name, virtualSize: `0x${s.virtualSize.toString(16)}`, sizeRaw: `0x${s.sizeRaw.toString(16)}` })),
  findings,
  run,
  verdict,
};

if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log("");
  console.log(`UnboxRE — diagnóstico de carga: ${report.file}`);
  console.log("─".repeat(70));
  console.log(`  ${report.size} bytes · ${report.machine} · SizeOfImage=${report.sizeOfImage} · DllCharacteristics=${report.dllCharacteristics}`);
  console.log(`  seções: ${sections.map((s) => `${s.name}${s.sizeRaw === 0 ? "*" : ""}`).join(" ")}   (* = sem dados no arquivo)`);
  console.log("");
  const tag = { high: "!!", medium: "? ", info: "i " };
  for (const f of findings) console.log(`  [${tag[f.level]}] ${f.code} — ${f.detail}`);
  if (run.skipped) console.log("  [i ] run — pulado (--no-run)");
  else console.log(`  [${run.exit === 0xc000007b ? "!!" : "i "}] run — exit=${run.hex} (${run.meaning})`);
  console.log(`\n  Veredito: ${verdict}`);
  console.log("");
}

process.exit(run.skipped ? 0 : run.exit === 0xc000007b ? 1 : 0);

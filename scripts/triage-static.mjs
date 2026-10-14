#!/usr/bin/env node
/**
 * triage-static.mjs — o que este PE É, sem abrir Ghidra nem debugger.
 *
 * Por que existe
 * --------------
 * A primeira pergunta sobre um alvo novo ("o que ele importa? o que ele imprime? onde
 * isso é usado?") não tinha caminho no toolkit: `GetStrings`/`GetImports` são ferramentas do
 * MCP do x64dbg (exigem o debugger vivo com a GUI aberta) e `identify-protections.mjs`
 * responde outra pergunta ("está empacotado?"). Num crackme de 13 KB (round 8.1) isso
 * obrigou a escrever um parser na mão. Este script é esse parser, agora permanente:
 *
 *   1. cabeçalho: PE32/PE32+, machine, ImageBase, entrypoint, DllCharacteristics, seções
 *      (tamanho virtual/físico, flags R/W/X, entropia) e data directories presentes;
 *   2. **TLS callbacks** — código que o loader roda ANTES do entrypoint (packers, MinGW e
 *      anti-debug usam isso); é um ponto de parada que o analista precisa saber que existe;
 *   3. imports agrupados por DLL (por nome; `#N` quando é por ordinal);
 *   4. strings ASCII e UTF-16 **somente em seções NÃO executáveis**, com a RVA de cada uma;
 *   5. com `--refs`, onde cada string é referenciada no código (uma passada no código, com
 *      índice por destino — varredura por string não escala em alvo grande).
 *
 * A lição que este script carrega (medida no round 8.1)
 * ----------------------------------------------------
 * Varrer o arquivo inteiro atrás de "bytes imprimíveis" produz lixo: num alvo de 13 KB saíram
 * 116 "strings", quase todas instruções de `.text` disfarçadas de texto (`"fffff."`,
 * `"AWAVAUATVWUSH"`), e a string que importava ficou diluída. String de verdade mora em seção
 * **não executável** — é por isso que o filtro existe e é obrigatório aqui. O mesmo cuidado
 * vale para as referências: a varredura de RIP-relativo é heurística (acha candidatos, não
 * monta a instrução) — para ler a instrução exata use `scripts/disasm-range.py`.
 *
 * Uso:
 *   node scripts/triage-static.mjs <arquivo> [--min N] [--refs] [--no-strings] [--json]
 *     --min N        tamanho mínimo da string (default 4)
 *     --refs         procura onde as strings são usadas (código)
 *     --no-strings   só cabeçalho/imports/TLS (arquivo grande: economiza tempo)
 *     --json         saída JSON (para encadear em script/IA)
 *
 * Exit: 0 analisado · 2 arquivo ilegível, não-PE ou erro de uso. Nunca usa sudo.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);
if (argv.length === 0 || has("--help") || has("-h")) {
  console.log("uso: node scripts/triage-static.mjs <arquivo.exe> [--min N] [--refs] [--no-strings] [--json]");
  console.log("  --min N        tamanho mínimo da string (default 4)");
  console.log("  --refs         onde cada string é referenciada no código (RIP-relativo e ponteiro absoluto)");
  console.log("  --no-strings   só cabeçalho, seções, TLS e imports");
  console.log("  --json         saída JSON");
  console.log("");
  console.log("  Triagem ESTÁTICA (sem debugger): o contrário de GetStrings/GetImports do MCP, que");
  console.log("  precisam do x64dbg vivo. Strings só em seção NÃO executável — ver o cabeçalho.");
  process.exit(argv.length === 0 ? 2 : 0);
}
const JSON_OUT = has("--json");
const WANT_REFS = has("--refs");
const NO_STRINGS = has("--no-strings");
const MIN = Number(val("--min", "4"));
const file = argv.find((a) => !a.startsWith("--"));

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
const u64 = (o) => buf.readBigUInt64LE(o);

const pe = u32(0x3c);
if (u32(pe) !== 0x00004550) {
  console.error(`[!!] ${file}: assinatura PE ausente em 0x${pe.toString(16)}`);
  process.exit(2);
}
const machine = u16(pe + 4);
const nsec = u16(pe + 6);
const optSize = u16(pe + 20);
const opt = pe + 24;
const is64 = u16(opt) === 0x20b;
const MAGIC = { 0x10b: "PE32", 0x20b: "PE32+", 0x107: "ROM" }[u16(opt)] ?? `magic 0x${u16(opt).toString(16)}`;
const MACHINE = { 0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64" }[machine] ?? `0x${machine.toString(16)}`;
const imageBase = is64 ? Number(u64(opt + 24)) : u32(opt + 28);
const entry = u32(opt + 16);
const sizeOfImage = u32(opt + 56);
const dllChar = u16(opt + (is64 ? 0x46 : 0x46));
const dirsOff = opt + (is64 ? 112 : 96);
const DIRS = [
  "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION(.pdata)", "CERTIFICADO", "RELOC",
  "DEBUG", "ARCH", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT",
  "DELAY_IMPORT", "CLR(.NET)", "RESERVADO",
];
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_READ = 0x40000000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;

const sections = [];
for (let i = 0; i < nsec; i++) {
  const s = pe + 24 + optSize + i * 40;
  sections.push({
    name: buf.subarray(s, s + 8).toString("latin1").replace(/\0+$/, ""),
    virtualSize: u32(s + 8),
    va: u32(s + 12),
    rawSize: u32(s + 16),
    raw: u32(s + 20),
    characteristics: u32(s + 36),
  });
}
const rva2off = (rva) => {
  for (const s of sections) {
    const span = Math.max(s.virtualSize, s.rawSize);
    if (rva >= s.va && rva < s.va + span) return s.raw + (rva - s.va);
  }
  return -1;
};
const off2rva = (off) => {
  for (const s of sections) if (off >= s.raw && off < s.raw + s.rawSize) return s.va + (off - s.raw);
  return -1;
};
const cstrAt = (rva) => {
  const o = rva2off(rva);
  if (o < 0) return null;
  let e = o;
  while (e < buf.length && buf[e] !== 0 && buf[e] >= 0x20 && buf[e] < 0x7f) e++;
  return e > o ? buf.subarray(o, e).toString("latin1") : null;
};

/** Entropia de Shannon dos bytes de um intervalo (0..8). */
function entropy(from, size) {
  if (size <= 0) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < size; i++) freq[buf[from + i]]++;
  let h = 0;
  for (const c of freq) if (c) {
    const p = c / size;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 100) / 100;
}

// ── data directories e TLS ───────────────────────────────────────────────────
const directories = [];
for (let i = 0; i < 16; i++) {
  const rva = u32(dirsOff + i * 8);
  const size = u32(dirsOff + i * 8 + 4);
  if (rva || size) directories.push({ index: i, name: DIRS[i], rva, size });
}

let tls = null;
const tlsDir = directories.find((d) => d.name === "TLS");
if (tlsDir?.rva) {
  const o = rva2off(tlsDir.rva);
  if (o >= 0 && o + 40 <= buf.length) {
    const callbacksVa = Number(u64(o + 24));
    const callbacksRva = callbacksVa - imageBase;
    const cbOff = callbacksRva >= 0 ? rva2off(callbacksRva) : -1;
    const callbacks = [];
    if (cbOff >= 0) {
      for (let i = 0; i < 32; i++) {
        if (cbOff + i * 8 + 8 > buf.length) break;
        const v = u64(cbOff + i * 8);
        if (v === 0n) break;
        callbacks.push({ va: `0x${v.toString(16)}`, rva: Number(v) - imageBase });
      }
    }
    tls = {
      directoryRva: tlsDir.rva,
      startOfRawData: `0x${u64(o).toString(16)}`,
      addressOfCallbacks: `0x${callbacksVa.toString(16)}`,
      callbacks,
    };
  }
}

// ── imports ──────────────────────────────────────────────────────────────────
const imports = [];
const impDir = directories.find((d) => d.name === "IMPORT");
if (impDir?.rva) {
  for (let d = rva2off(impDir.rva); d >= 0 && d + 20 <= buf.length; d += 20) {
    const oft = u32(d);
    const nameRva = u32(d + 12);
    const ft = u32(d + 16);
    if (!oft && !nameRva && !ft) break;
    const dll = nameRva ? cstrAt(nameRva) : "(sem nome)";
    const thunkOff = rva2off(oft || ft);
    const functions = [];
    if (thunkOff >= 0) {
      for (let t = thunkOff; t + 8 <= buf.length; t += is64 ? 8 : 4) {
        const v = is64 ? u64(t) : BigInt(u32(t));
        if (v === 0n) break;
        const isOrdinal = is64 ? (v >> 63n) & 1n : (v >> 31n) & 1n;
        if (isOrdinal) {
          functions.push(`#${Number(v & 0xffffn)}`);
        } else {
          const nameOff = rva2off(Number(v & 0x7fffffffn));
          if (nameOff >= 0) functions.push(cstrAt(Number(v & 0x7fffffffn) + 2) ?? "(ilegível)");
        }
      }
    }
    imports.push({ dll, count: functions.length, functions });
  }
}

// ── strings (só em seções NÃO executáveis) ───────────────────────────────────
const dataRanges = sections
  .filter((s) => !(s.characteristics & IMAGE_SCN_MEM_EXECUTE))
  .map((s) => ({ from: s.raw, to: s.raw + s.rawSize, name: s.name }));
const inData = (off) => dataRanges.find((r) => off >= r.from && off < r.to);

const strings = [];
if (!NO_STRINGS) {
  const seen = new Set();
  const push = (text, off, wide) => {
    const key = `${wide ? "w" : "a"}:${off}`;
    if (seen.has(key) || text.length < MIN) return;
    seen.add(key);
    strings.push({ rva: off2rva(off), off, wide, text });
  };
  for (const range of dataRanges) {
    for (let o = range.from; o < range.to && o < buf.length; o++) {
      const c = buf[o];
      if (c >= 0x20 && c < 0x7f) {
        let e = o;
        while (e < buf.length && buf[e] >= 0x20 && buf[e] < 0x7f) e++;
        if (e - o >= MIN) {
          push(buf.subarray(o, e).toString("latin1"), o, false);
          o = e;
          continue;
        }
      }
      // UTF-16LE: caractere imprimível seguido de 0x00
      if (c >= 0x20 && c < 0x7f && buf[o + 1] === 0) {
        let w = o;
        const chars = [];
        while (w + 1 < buf.length && buf[w] >= 0x20 && buf[w] < 0x7f && buf[w + 1] === 0) {
          chars.push(String.fromCharCode(buf[w]));
          w += 2;
        }
        if (chars.length >= MIN) {
          push(chars.join(""), o, true);
          o = w - 1;
        }
      }
    }
  }
}

// ── referências às strings no código ─────────────────────────────────────────
// Heurística declarada: procura as duas formas usuais — instrução com ModRM RIP-relativo
// (`lea`/`mov`/`cmp`/`call`, com REX opcional) e ponteiro absoluto de 8 bytes (tabelas,
// vtables). Não é um desmontador: dá CANDIDATOS.
//
// UMA passada no código, indexada por destino — não uma varredura por string. Medido: a
// versão por string é O(strings × bytes de código) e num alvo grande (milhares de strings,
// MBs de .text) vira minutos; indexando, é O(bytes) uma vez. O salto `o = p + 6` evita
// reportar a MESMA instrução duas vezes (achada uma vez pela REX, outra pelo opcode).
const REX = new Set([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f]);
const RIP_OPS = new Set([0x8d, 0x8b, 0x89, 0x3b, 0x39, 0x38, 0x3a, 0xff, 0x0f]);
const refIndex = new Map();
if (WANT_REFS) {
  const add = (targetRva, entry) => {
    if (targetRva < 0) return;
    if (!refIndex.has(targetRva)) refIndex.set(targetRva, []);
    refIndex.get(targetRva).push(entry);
  };
  for (const s of sections) {
    if (!(s.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
    const from = s.raw;
    const to = Math.min(s.raw + s.rawSize, buf.length);
    for (let o = from; o < to; ) {
      if (o + 8 <= to) {
        const abs = Number(u64(o));
        if (abs >= imageBase && abs < imageBase + sizeOfImage) add(abs - imageBase, { rva: off2rva(o), how: "ponteiro absoluto (8 bytes)", section: s.name });
      }
      let p = o;
      if (REX.has(buf[p])) p++;
      const opcode = buf[p];
      const modrm = buf[p + 1];
      if (opcode !== undefined && modrm !== undefined && RIP_OPS.has(opcode) && (modrm & 0xc7) === 0x05 && p + 6 <= to) {
        const disp = buf.readInt32LE(p + 2);
        const insnStartRva = off2rva(o) ?? 0;
        add(insnStartRva + (p + 6 - o) + disp, {
          rva: insnStartRva,
          how: opcode === 0x8d ? "RIP-relativo (lea)" : `RIP-relativo (op 0x${opcode.toString(16)})`,
          section: s.name,
        });
        o = p + 6;
        continue;
      }
      o++;
    }
  }
}

const withRefs = strings.map((s) => (WANT_REFS && s.rva >= 0 ? { ...s, refs: refIndex.get(s.rva) ?? [] } : s));

const report = {
  file: file.split(/[\\/]/).pop(),
  size: buf.length,
  format: MAGIC,
  machine: MACHINE,
  imageBase: `0x${imageBase.toString(16)}`,
  entryPoint: `0x${entry.toString(16)}`,
  sizeOfImage: `0x${sizeOfImage.toString(16)}`,
  dllCharacteristics: `0x${dllChar.toString(16)}`,
  sections: sections.map((s) => ({
    name: s.name,
    rva: `0x${s.va.toString(16)}`,
    virtualSize: s.virtualSize,
    rawSize: s.rawSize,
    perms: `${s.characteristics & IMAGE_SCN_MEM_READ ? "R" : "-"}${s.characteristics & IMAGE_SCN_MEM_WRITE ? "W" : "-"}${s.characteristics & IMAGE_SCN_MEM_EXECUTE ? "X" : "-"}`,
    entropy: entropy(s.raw, s.rawSize),
  })),
  directories: directories.map((d) => ({ name: d.name, rva: `0x${d.rva.toString(16)}`, size: `0x${d.size.toString(16)}` })),
  tls,
  imports,
  strings: withRefs,
};

if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log("");
  console.log(`UnboxRE — triagem estática: ${report.file}`);
  console.log("─".repeat(70));
  console.log(`  ${report.size} bytes · ${report.format} · ${report.machine} · ImageBase=${report.imageBase} · EP=0x${entry.toString(16)} · SizeOfImage=${report.sizeOfImage}`);
  console.log(`  DllCharacteristics=${report.dllCharacteristics}`);
  console.log("  seções:");
  for (const s of report.sections) {
    console.log(`    ${s.name.padEnd(9)} rva=${s.rva.padEnd(9)} virt=${String(s.virtualSize).padEnd(8)} raw=${String(s.rawSize).padEnd(8)} ${s.perms} entropia=${s.entropy}`);
  }
  console.log(`  diretórios: ${report.directories.map((d) => d.name).join(" ") || "(nenhum)"}`);
  if (tls) {
    console.log(`  TLS: callbacks=${tls.callbacks.length} (${tls.callbacks.map((c) => `rva 0x${c.rva.toString(16)}`).join(", ") || "nenhum"}) — o loader roda isto ANTES do entrypoint`);
  }
  console.log("");
  console.log(`  imports (${imports.length} DLL):`);
  for (const i of imports) console.log(`    ${i.dll} (${i.count}): ${i.functions.join(", ")}`);
  if (!NO_STRINGS) {
    console.log("");
    console.log(`  strings em seções de dados (>=${MIN} chars): ${strings.length}`);
    for (const s of withRefs) {
      const refs = s.refs?.length ? `   <- usada em ${s.refs.map((r) => `0x${r.rva.toString(16)} (${r.how})`).join(", ")}` : WANT_REFS ? "   <- (nenhuma referência encontrada no código)" : "";
      console.log(`    rva 0x${s.rva.toString(16).padStart(6, "0")} ${s.wide ? "[utf16]" : "[ascii]"} ${JSON.stringify(s.text)}${refs}`);
    }
  }
  console.log("");
}

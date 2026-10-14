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
 *   node scripts/triage-static.mjs <arquivo> [--min N] [--refs] [--data-refs] [--no-strings] [--json]
 *     --min N        tamanho mínimo da string (default 4)
 *     --refs         procura onde as strings são usadas (código)
 *     --data-refs    lista as referências do código a DADOS que não são strings (as
 *                    constantes: sementes em `.data`, máscaras `movdqa` em `.rdata`)
 *     --no-strings   só cabeçalho, imports/TLS (arquivo grande: economiza tempo)
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
  console.log("uso: node scripts/triage-static.mjs <arquivo.exe> [--min N] [--refs] [--data-refs] [--no-strings] [--json]");
  console.log("  --min N        tamanho mínimo da string (default 4)");
  console.log("  --refs         onde cada string é referenciada no código (RIP-relativo e ponteiro absoluto)");
  console.log("  --data-refs    referências a dados que NÃO são strings: as constantes (seed, máscara, tabela)");
  console.log("  --no-strings   só cabeçalho, seções, TLS e imports");
  console.log("  --json         saída JSON");
  console.log("");
  console.log("  Triagem ESTÁTICA (sem debugger): o contrário de GetStrings/GetImports do MCP, que");
  console.log("  precisam do x64dbg vivo. Strings só em seção NÃO executável — ver o cabeçalho.");
  process.exit(argv.length === 0 ? 2 : 0);
}
const JSON_OUT = has("--json");
const WANT_REFS = has("--refs") || has("--data-refs");
const WANT_DATA_REFS = has("--data-refs");
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

// ── referências no código (strings e constantes) ─────────────────────────────
// Heurística declarada: procura as duas formas usuais — instrução com ModRM RIP-relativo e
// ponteiro absoluto de 8 bytes (tabelas, vtables). Não é um desmontador: dá CANDIDATOS.
//
// UMA passada no código, indexada por destino — não uma varredura por string. Medido: a
// versão por string é O(strings × bytes de código) e num alvo grande (milhares de strings,
// MBs de .text) vira minutos; indexando, é O(bytes) uma vez.
//
// PREFIXOS e OPCODE DE DOIS BYTES (corrigido no round 8.2, com o erro medido)
// -------------------------------------------------------------------------
// A primeira versão só pulava REX. Isso perdia silenciosamente toda instrução com prefixo
// 66/F2/F3 — e é justamente nelas que moram as CONSTANTES de um crackme: o `66 0f 6f 1d`
// (`movdqa xmm3, [rip+…]`, a máscara do pipeline SSE) e o `f3 0f 7e`/`66 0f 7e` (`movq`). O
// `0f` estava na lista de opcodes, mas como se o ModRM viesse em `p+1`: em opcode de dois
// bytes ele vem em `p+2`, então o teste `(modrm & 0xc7) === 0x05` nunca fechava. Resultado:
// as duas máscaras do alvo do round 8.2 não apareciam em referência nenhuma (achadas lendo o
// disassembly na mão). Agora: prefixos são pulados, `0f xx` é tratado como opcode de dois
// bytes e o comprimento até o fim do deslocamento é calculado a partir daí.
const REX = new Set([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f]);
const PREFIXOS = new Set([0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65]);
const RIP_OPS = new Set([
  0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f, 0x38, 0x39, 0x3a, 0x3b, 0x63, 0x80, 0x81, 0x83, 0x85, 0xc6, 0xc7, 0xd1, 0xd3, 0xf7, 0xff,
]);
// Opcodes de dois bytes (0x0f xx) com operando de memória — lista CURADA, não exaustiva:
// 6f/7f movdqa·movdqu, 10/11 movups, 28/29 movaps, 6e/7e movd·movq, 7c/7d haddps,
// d6 movq, 2e/2f ucomiss, 12–17 movlps/hps/lpd/hpd, b6/b7 movzx, be/bf movsx, 45/4a… cmov.
const RIP_OPS_0F = new Set([
  0x6f, 0x7f, 0x10, 0x11, 0x28, 0x29, 0x6e, 0x7e, 0x7c, 0x7d, 0xd6, 0x2e, 0x2f,
  0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xb6, 0xb7, 0xbe, 0xbf, 0x45, 0x4a, 0x40, 0x41, 0x42, 0x43, 0x44, 0x46, 0x47, 0x48, 0x49, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
]);
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
      let guarda = 0;
      while (p < to && PREFIXOS.has(buf[p]) && guarda++ < 4) p++;   // 66/67/F2/F3…
      if (p < to && REX.has(buf[p])) p++;
      const b0 = buf[p];
      const doisBytes = b0 === 0x0f;
      const opcode = doisBytes ? 0x0f00 | buf[p + 1] : b0;
      const modrm = buf[p + (doisBytes ? 2 : 1)];
      const dispOff = p + (doisBytes ? 3 : 2);
      const fim = dispOff + 4;
      const casa = doisBytes ? RIP_OPS_0F.has(buf[p + 1]) : RIP_OPS.has(b0);
      if (b0 !== undefined && modrm !== undefined && casa && (modrm & 0xc7) === 0x05 && fim <= to) {
        const disp = buf.readInt32LE(dispOff);
        const insnStartRva = off2rva(o) ?? 0;
        add(insnStartRva + (fim - o) + disp, {
          rva: insnStartRva,
          how: b0 === 0x8d ? "RIP-relativo (lea)"
            : doisBytes ? `RIP-relativo (0f ${buf[p + 1].toString(16).padStart(2, "0")})`
            : `RIP-relativo (op 0x${b0.toString(16)})`,
          section: s.name,
        });
        o = fim;
        continue;
      }
      o++;
    }
  }
}

const withRefs = strings.map((s) => (WANT_REFS && s.rva >= 0 ? { ...s, refs: refIndex.get(s.rva) ?? [] } : s));

// ── referências a dados que NÃO são strings (as constantes) ──────────────────
// O refIndex já tem TODO alvo RIP-relativo/absoluto achado no código; o relatório de strings
// mostrava só os que caem em string — ou seja, ficava de fora justamente o passo seguinte:
// a semente `dword` em `.data` que o `imul` multiplica e a máscara de 16 bytes que o `movdqa`
// carrega. Medido no round 8.2: esses dois foram achados lendo o disassembly na mão, com o
// dado já calculado aqui dentro.
const dataRefs = [];
if (WANT_DATA_REFS) {
  const stringRvas = new Set(strings.map((s) => s.rva));
  const dataSectionAt = (rva) => sections.find((s) => !(s.characteristics & IMAGE_SCN_MEM_EXECUTE) && rva >= s.va && rva < s.va + Math.max(s.virtualSize, s.rawSize));
  for (const [rva, entries] of [...refIndex.entries()].sort((a, b) => a[0] - b[0])) {
    if (stringRvas.has(rva)) continue;
    const sec = dataSectionAt(rva);
    if (!sec) continue;
    const o = rva2off(rva);
    const peek = o >= 0 ? buf.subarray(o, o + 16) : buf.subarray(0, 0);
    // Sem classificação isto afoga o sinal: num binário MinGW a maioria dos alvos é a tabela
    // de ponteiros do CRT (8 bytes que apontam para dentro da própria imagem). O que se
    // procura num crackme é outro tipo: máscara (`movdqa` com 00/ff) e inteiro pequeno
    // (semente/contador). O rótulo é heurística declarada, e a ordenação põe o útil primeiro.
    const d0 = peek.length >= 4 ? peek.readUInt32LE(0) : -1;
    const q0 = peek.length >= 8 ? Number(peek.readBigUInt64LE(0)) : -1;
    const soPonteiro = q0 >= imageBase && q0 < imageBase + sizeOfImage;
    const vals = new Set(Array.from(peek));
    const soZero = peek.length > 0 && vals.size === 1 && vals.has(0x00);   // global não inicializada
    // Máscara de verdade tem os DOIS bytes (ff e 00) e nada mais: só 00 é global zerada —
    // a primeira versão classificava .data zerada como "máscara" e enchia a lista de ruído
    // (medido: 11 dos 12 primeiros alvos eram globais zeradas do CRT).
    const soMascara = peek.length > 0 && vals.has(0xff) && [...vals].every((b) => b === 0x00 || b === 0xff);
    const tipo = soMascara ? "máscara"
      : soPonteiro ? "ponteiro/tabela"
      : soZero ? "zero (não inicializado)"
      : d0 >= 0 && d0 < 0x01000000 ? "inteiro pequeno"
      : "dados";
    dataRefs.push({
      rva,
      section: sec.name,
      tipo,
      refs: entries.length,
      firstRef: entries[0]?.rva ?? null,
      how: entries[0]?.how ?? null,
      bytes: Array.from(peek, (b) => b.toString(16).padStart(2, "0")).join(" "),
      ascii: Array.from(peek, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join(""),
    });
  }
  const ordem = { "máscara": 0, "inteiro pequeno": 1, dados: 2, "ponteiro/tabela": 3, "zero (não inicializado)": 4 };
  dataRefs.sort((a, b) => (ordem[a.tipo] - ordem[b.tipo]) || (b.refs - a.refs) || (a.rva - b.rva));
}

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
  dataRefs: WANT_DATA_REFS ? dataRefs : undefined,
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
  if (WANT_DATA_REFS) {
    console.log("");
    console.log(`  referências a DADOS que não são strings (constantes): ${dataRefs.length} alvo(s)`);
    for (const d of dataRefs.slice(0, 20)) {
      console.log(`    rva 0x${d.rva.toString(16).padStart(6, "0")} ${d.section} [${d.tipo}] <- ${d.refs} ref(s), 1a em 0x${(d.firstRef ?? 0).toString(16)} (${d.how})`);
      console.log(`        bytes: ${d.bytes}   ${d.ascii}`);
    }
    if (dataRefs.length > 20) console.log(`    … (+${dataRefs.length - 20} alvo(s); use --json para a lista completa)`);
  }
  console.log("");
}

#!/usr/bin/env node
/**
 * triage-static.mjs — o que este arquivo É, sem abrir Ghidra nem debugger.
 *
 * Formatos: **PE (Windows)** e **ELF (Linux)**. O escopo validado do toolkit é Windows, mas
 * um alvo Linux apareceu (round 8.3) e as ferramentas de leitura recusavam o arquivo com a
 * mesma mensagem ("sem assinatura MZ") sem oferecer caminho nenhum. Recusar não é triagem:
 * aqui o formato é reconhecido e o que é comum aos dois é reportado no mesmo lugar.
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
 *      em ELF: ELF32/ELF64, e_type, e_machine, e_entry, program headers (segmentos LOAD e
 *      suas permissões), seções por nome (via `.shstrtab`), `.dynamic` (DT_NEEDED,
 *      DT_INIT/DT_INIT_ARRAY) e sinais de empacotamento (segmento W+X, entry fora do LOAD,
 *      pilha executável, entropia alta em seção executável);
 *   2. **código que roda ANTES do main** — em PE, TLS callbacks; em ELF, DT_INIT/DT_INIT_ARRAY
 *      (packers, MinGW e anti-debug usam isso); é um ponto de parada que o analista precisa
 *      saber que existe;
 *   3. imports agrupados por biblioteca: no PE por DLL (por nome; `#N` quando é por ordinal),
 *      no ELF DT_NEEDED + os símbolos INDEFINIDOS do `.dynsym` (o "o que ele chama?");
 *   4. strings ASCII e UTF-16 **somente em seções NÃO executáveis**, com o endereço de cada
 *      uma (e a seção onde está — em ELF é isso que separa dado do programa de tabela de
 *      relocação);
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
 * Exit: 0 analisado · 2 arquivo ilegível, formato não reconhecido ou erro de uso. Nunca usa sudo.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);
if (argv.length === 0 || has("--help") || has("-h")) {
  console.log("uso: node scripts/triage-static.mjs <arquivo> [--min N] [--refs] [--data-refs] [--no-strings] [--json]");
  console.log("  formatos: PE32/PE32+ (Windows) e ELF32/ELF64 (Linux)");
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
// ── formato: PE (Windows) ou ELF (Linux) ─────────────────────────────────────
// O toolkit nasceu com escopo Windows e as quatro ferramentas de leitura recusavam
// qualquer arquivo que não fosse PE — cada uma com a MESMA mensagem ("sem assinatura MZ")
// e nenhum caminho alternativo (medido no round 8.3, com um alvo ELF na mão). Reconhecer
// o formato é o primeiro passo da triagem, então aqui ele é explícito: PE e ELF.
const isELF = buf.length >= 0x40 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46;
const isPE = buf.length >= 0x40 && buf.readUInt16LE(0) === 0x5a4d;
if (!isPE && !isELF) {
  console.error(`[!!] ${file}: nem assinatura "MZ" (PE) nem "\\x7fELF" — formato não reconhecido`);
  process.exit(2);
}
const u16 = (o) => buf.readUInt16LE(o);
const u32 = (o) => buf.readUInt32LE(o);
const u64 = (o) => buf.readBigUInt64LE(o);

// Estado comum aos dois formatos. Em ELF, `va` é o vaddr de link (absoluto, como no
// readelf), não um RVA; o campo `rva` da saída é esse endereço.
const sections = [];
let FMT = "";
let MACHINE_STR = "";
let imageBase = 0;
let entry = 0;
let sizeOfImage = 0;
let imgLo = 0;              // faixa de endereços da imagem (reconhecer ponteiro para dentro dela)
let imgHi = 0;
let directories = [];       // PE: data directories
let tls = null;             // PE: TLS callbacks
let imports = [];           // PE: por DLL · ELF: DT_NEEDED
let HEAD = {};              // o resto do cabeçalho, específico do formato

const rva2off = (rva) => {
  for (const s of sections) {
    if (s.va < 0 || s.rawSize === 0) continue;   // seção sem vaddr ou sem bytes no arquivo
    const span = Math.max(s.virtualSize, s.rawSize);
    if (rva >= s.va && rva < s.va + span) return s.raw + (rva - s.va);
  }
  return -1;
};
const off2rva = (off) => {
  for (const s of sections) {
    if (s.va < 0 || s.rawSize === 0) continue;
    if (off >= s.raw && off < s.raw + s.rawSize) return s.va + (off - s.raw);
  }
  return -1;
};
const cstrAt = (rva) => {
  const o = rva2off(rva);
  if (o < 0) return null;
  let e = o;
  while (e < buf.length && buf[e] !== 0 && buf[e] >= 0x20 && buf[e] < 0x7f) e++;
  return e > o ? buf.subarray(o, e).toString("latin1") : null;
};
/** String C num offset de ARQUIVO (ELF: tabelas de nomes de seção/símbolo). */
const cstrAtOff = (off) => {
  if (off < 0 || off >= buf.length) return null;
  let e = off;
  while (e < buf.length && buf[e] !== 0) e++;
  return e > off ? buf.subarray(off, e).toString("latin1") : null;
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

if (isPE) {
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
FMT = MAGIC;
MACHINE_STR = MACHINE;
imageBase = is64 ? Number(u64(opt + 24)) : u32(opt + 28);
imgLo = imageBase;
entry = u32(opt + 16);
sizeOfImage = u32(opt + 56);
imgHi = imageBase + sizeOfImage;
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

for (let i = 0; i < nsec; i++) {
  const s = pe + 24 + optSize + i * 40;
  sections.push({
    name: buf.subarray(s, s + 8).toString("latin1").replace(/\0+$/, ""),
    virtualSize: u32(s + 8),
    va: u32(s + 12),
    rawSize: u32(s + 16),
    raw: u32(s + 20),
    characteristics: u32(s + 36),
    // vocabulário normalizado (o resto do script usa isto, não as flags de PE)
    exec: !!(u32(s + 36) & IMAGE_SCN_MEM_EXECUTE),
    write: !!(u32(s + 36) & IMAGE_SCN_MEM_WRITE),
    read: !!(u32(s + 36) & IMAGE_SCN_MEM_READ),
    alloc: true,
    nobits: false,
    shType: null,
  });
}

// ── data directories e TLS ───────────────────────────────────────────────────
for (let i = 0; i < 16; i++) {
  const rva = u32(dirsOff + i * 8);
  const size = u32(dirsOff + i * 8 + 4);
  if (rva || size) directories.push({ index: i, name: DIRS[i], rva, size });
}

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

HEAD = {
  magic: MAGIC,
  dllCharacteristics: `0x${dllChar.toString(16)}`,
  directories: directories.map((d) => ({ name: d.name, rva: `0x${d.rva.toString(16)}`, size: `0x${d.size.toString(16)}` })),
};
} else {
// ── ELF (Linux) ──────────────────────────────────────────────────────────────
// Sem esta seção o script morria em "sem assinatura MZ" para QUALQUER arquivo Linux —
// inclusive para a pergunta mais básica ("quais são as seções e o que ele chama?").
const ELF_MACHINE = new Map([
  [0x03, "x86"], [0x3e, "x86-64"], [0x28, "ARM"], [0xb7, "AArch64"],
  [0xf3, "RISC-V"], [0x08, "MIPS"], [0x14, "PowerPC"], [0x16, "S390"],
]);
const ELF_TYPE = new Map([[1, "ET_REL (relocável)"], [2, "ET_EXEC (executável de endereço fixo)"], [3, "ET_DYN (PIE/shared)"], [4, "ET_CORE (core dump)"]]);
const PT_TYPE = new Map([[1, "LOAD"], [2, "DYNAMIC"], [3, "INTERP"], [4, "NOTE"], [6, "PHDR"], [7, "TLS"], [0x6474e550, "GNU_EH_FRAME"], [0x6474e551, "GNU_STACK"], [0x6474e552, "GNU_RELRO"]]);
const SHT = { NULL: 0, PROGBITS: 1, SYMTAB: 2, STRTAB: 3, RELA: 4, HASH: 5, DYNAMIC: 6, NOTE: 7, NOBITS: 8, REL: 9, DYNSYM: 11, INIT_ARRAY: 14, FINI_ARRAY: 15, GNU_HASH: 0x6ffffff6, GNU_VERDEF: 0x6ffffffd, GNU_VERNEED: 0x6ffffffe, GNU_VERSYM: 0x6fffffff };
const SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4;
if (buf[5] !== 1) {
  console.error(`[!!] ${file}: ELF big-endian (EI_DATA=${buf[5]}) — este script lê little-endian`);
  process.exit(2);
}
if (buf[4] !== 2 && buf[4] !== 1) {
  console.error(`[!!] ${file}: EI_CLASS=${buf[4]} inválido (esperado 1=32 bits ou 2=64 bits)`);
  process.exit(2);
}
const is64 = buf[4] === 2;
const eType = u16(16);
const eMachine = u16(18);
const phoff = is64 ? Number(u64(0x20)) : u32(0x1c);
const shoff = is64 ? Number(u64(0x28)) : u32(0x20);
const phentsize = u16(is64 ? 0x36 : 0x2a);
const phnum = u16(is64 ? 0x38 : 0x2c);
const shentsize = u16(is64 ? 0x3a : 0x2e);
const shnum = u16(is64 ? 0x3c : 0x30);
const shstrndx = u16(is64 ? 0x3e : 0x32);
entry = is64 ? Number(u64(24)) : u32(24);
FMT = `ELF${is64 ? "64" : "32"}`;
MACHINE_STR = ELF_MACHINE.get(eMachine) ?? `0x${eMachine.toString(16)}`;

// seções — o NOME de cada uma mora na .shstrtab (sh_name é um offset nela)
const shRaw = [];
for (let i = 0; i < shnum; i++) {
  const o = shoff + i * shentsize;
  if (o + shentsize > buf.length) break;
  shRaw.push(is64
    ? { nameOff: u32(o), type: u32(o + 4), flags: Number(u64(o + 8)), addr: Number(u64(o + 16)), off: Number(u64(o + 24)), size: Number(u64(o + 32)) }
    : { nameOff: u32(o), type: u32(o + 4), flags: u32(o + 8), addr: u32(o + 12), off: u32(o + 16), size: u32(o + 20) });
}
const shstrSec = shRaw[shstrndx];
for (const s of shRaw) {
  const alloc = !!(s.flags & SHF_ALLOC);
  const nobits = s.type === SHT.NOBITS;                 // .bss: existe na memória, não no arquivo
  sections.push({
    name: (shstrSec ? cstrAtOff(shstrSec.off + s.nameOff) : null) || "(sem nome)",
    va: alloc ? s.addr : -1,                            // seção não carregada não tem endereço
    virtualSize: s.size,
    rawSize: nobits ? 0 : s.size,
    raw: s.off,
    characteristics: 0,
    exec: !!(s.flags & SHF_EXECINSTR),
    write: !!(s.flags & SHF_WRITE),
    read: alloc,
    alloc,
    nobits,
    shType: s.type,
  });
}

// segmentos (program headers): o que o LOADER leva para a memória
const segs = [];
for (let i = 0; i < phnum; i++) {
  const o = phoff + i * phentsize;
  if (o + phentsize > buf.length) break;
  segs.push(is64
    ? { type: u32(o), flags: u32(o + 4), off: Number(u64(o + 8)), vaddr: Number(u64(o + 16)), filesz: Number(u64(o + 32)), memsz: Number(u64(o + 40)) }
    : { type: u32(o), off: u32(o + 4), vaddr: u32(o + 8), filesz: u32(o + 16), memsz: u32(o + 20), flags: u32(o + 24) });
}
const loads = segs.filter((s) => s.type === 1);
if (loads.length) {
  imgLo = Math.min(...loads.map((s) => s.vaddr));
  imgHi = Math.max(...loads.map((s) => s.vaddr + s.memsz));
}
imageBase = imgLo;
sizeOfImage = imgHi - imgLo;
const permsOf = (f) => `${f & 4 ? "R" : "-"}${f & 2 ? "W" : "-"}${f & 1 ? "X" : "-"}`;
const interpSeg = segs.find((s) => s.type === 3);
HEAD = {
  elfType: ELF_TYPE.get(eType) ?? `e_type=0x${eType.toString(16)}`,
  segments: segs.map((s) => ({
    type: PT_TYPE.get(s.type) ?? `0x${s.type.toString(16)}`,
    vaddr: `0x${s.vaddr.toString(16)}`,
    offset: `0x${s.off.toString(16)}`,
    filesz: s.filesz,
    memsz: s.memsz,
    perms: permsOf(s.flags),
  })),
  interpreter: interpSeg ? cstrAtOff(interpSeg.off) : null,
  dynamic: null,
  undefinedSymbols: [],
  signals: [],
};

// .dynamic → DT_NEEDED (as bibliotecas) e o código que roda ANTES do main
// (DT_INIT/DT_INIT_ARRAY é o análogo ELF do TLS callback do PE: um ponto que o analista
// precisa saber que existe).
const dynSec = sections.find((s) => s.shType === SHT.DYNAMIC);
const strtabSec = sections.find((s) => s.name === ".dynstr") ?? sections.find((s) => s.shType === SHT.STRTAB);
if (dynSec && dynSec.rawSize > 0) {
  const entsize = is64 ? 16 : 8;
  const d = { needed: [], soname: null, rpath: null, runpath: null, init: null, initArray: null, finiArray: null, bindNow: false, textrel: false, flags1: 0, strtab: null };
  for (let o = dynSec.raw; o + entsize <= dynSec.raw + dynSec.rawSize; o += entsize) {
    const tag = is64 ? Number(buf.readBigInt64LE(o)) : buf.readInt32LE(o);
    const v = is64 ? Number(u64(o + 8)) : u32(o + 4);
    if (tag === 0) break;
    if (tag === 1) d.needed.push(v);                       // DT_NEEDED
    else if (tag === 5) d.strtab = v;                      // DT_STRTAB
    else if (tag === 12) d.init = v;                       // DT_INIT
    else if (tag === 14) d.soname = v;
    else if (tag === 15) d.rpath = v;
    else if (tag === 24) d.bindNow = true;                 // DT_BIND_NOW
    else if (tag === 25) d.initArray = v;                  // DT_INIT_ARRAY
    else if (tag === 26) d.finiArray = v;
    else if (tag === 22) d.textrel = true;                 // DT_TEXTREL
    else if (tag === 0x6ffffffb) d.flags1 = v;             // DT_FLAGS_1 (DF_1_PIE)
  }
  const strOff = (v) => (strtabSec ? strtabSec.raw + v : rva2off(v));
  const sAt = (v) => (v === null || v === undefined ? null : cstrAtOff(strOff(v)));
  HEAD.dynamic = {
    needed: d.needed.map(sAt).filter(Boolean),
    soname: sAt(d.soname),
    rpath: sAt(d.rpath),
    runpath: sAt(d.runpath),
    init: d.init ? `0x${d.init.toString(16)}` : null,
    initArray: d.initArray ? `0x${d.initArray.toString(16)}` : null,
    finiArray: d.finiArray ? `0x${d.finiArray.toString(16)}` : null,
    bindNow: d.bindNow,
    pie: (d.flags1 & 0x08000000) !== 0,
    textrel: d.textrel,
  };
  imports = HEAD.dynamic.needed.map((lib) => ({ dll: lib, count: 0, functions: [] }));
}

// símbolos INDEFINIDOS (.dynsym, st_shndx == SHN_UNDEF): é o "o que ele chama?" do ELF —
// a lista de funções que ele importa do libc (puts, printf…), que no PE são os imports.
const dynsymSec = sections.find((s) => s.shType === SHT.DYNSYM);
if (dynsymSec && dynsymSec.rawSize > 0 && strtabSec) {
  const esz = is64 ? 24 : 16;
  const undef = new Set();
  for (let o = dynsymSec.raw; o + esz <= dynsymSec.raw + dynsymSec.rawSize; o += esz) {
    const nameOff = u32(o);
    const shndx = u16(o + (is64 ? 6 : 14));
    if (shndx !== 0 || nameOff === 0) continue;
    const nm = cstrAtOff(strtabSec.raw + nameOff);
    if (nm) undef.add(nm);
  }
  HEAD.undefinedSymbols = [...undef].sort();
}

// sinais de empacotamento/proteção — heurística DECLARADA, do mesmo tipo que o
// identify-protections.mjs usa em PE (segmento W+X, entry fora do que é carregado, entropia).
if (!segs.some((s) => s.type === 1 && entry >= s.vaddr && entry < s.vaddr + s.memsz)) {
  HEAD.signals.push(`entrypoint 0x${entry.toString(16)} está FORA de qualquer segmento LOAD (só o loader do kernel faz isso; packer/VM costuma fazer)`);
}
for (const s of HEAD.segments) {
  if (s.type === "LOAD" && s.perms.includes("W") && s.perms.includes("X")) {
    HEAD.signals.push(`segmento LOAD gravável E executável (${s.perms} em ${s.vaddr}) — compilador normal não emite isso`);
  }
}
const gnuStack = HEAD.segments.find((s) => s.type === "GNU_STACK");
if (gnuStack && gnuStack.perms.includes("X")) HEAD.signals.push("GNU_STACK com X: pilha executável (mitigação desligada)");
}

// ── strings (só em seções NÃO executáveis) ───────────────────────────────────
// PE: toda seção sem IMAGE_SCN_MEM_EXECUTE. ELF: só seção CARREGADA (SHF_ALLOC) e do tipo
// conteúdo/strings (PROGBITS/STRTAB/NOTE) — fora ficam .rela*/.gnu.hash/.dynsym, cujos
// "bytes imprimíveis" são tabelas de relocação, não dados do programa. `.comment` entra
// por exceção declarada: é a versão do compilador, informação de triagem.
const dataRanges = sections
  .filter((s) => !s.exec && (s.alloc || s.name === ".comment"))
  .map((s) => ({ from: s.raw, to: s.raw + s.rawSize, name: s.name }));
const inData = (off) => dataRanges.find((r) => off >= r.from && off < r.to);

const strings = [];
if (!NO_STRINGS) {
  const seen = new Set();
  const push = (text, off, wide) => {
    const key = `${wide ? "w" : "a"}:${off}`;
    if (seen.has(key) || text.length < MIN) return;
    seen.add(key);
    strings.push({ rva: off2rva(off), off, sec: inData(off)?.name ?? null, wide, text });
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
    if (!s.exec) continue;
    const from = s.raw;
    const to = Math.min(s.raw + s.rawSize, buf.length);
    for (let o = from; o < to; ) {
      if (o + 8 <= to) {
        const abs = Number(u64(o));
        if (abs >= imgLo && abs < imgHi) add(abs - imageBase, { rva: off2rva(o), how: "ponteiro absoluto (8 bytes)", section: s.name });
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
  const dataSectionAt = (rva) => sections.find((s) => !s.exec && s.va >= 0 && rva >= s.va && rva < s.va + Math.max(s.virtualSize, s.rawSize));
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
    const soPonteiro = q0 >= imgLo && q0 < imgHi;
    const vals = new Set(Array.from(peek));
    const soZero = peek.length > 0 && vals.size === 1 && vals.has(0x00);   // global não inicializada
    // Máscara de verdade tem os DOIS bytes (ff e 00) e nada mais: só 00 é global zerada —
    // a primeira versão classificava .data zerada como "máscara" e enchia a lista de ruído
    // (medido: 11 dos 12 primeiros alvos eram globais zeradas do CRT).
    const soMascara = peek.length > 0 && vals.has(0xff) && [...vals].every((b) => b === 0x00 || b === 0xff);
    const tipo = soMascara ? "máscara"
      : soPonteiro ? "ponteiro/tabela"
      : soZero ? "zero (não inicializado)"
      : o < 0 ? "sem bytes no arquivo (.bss)"
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
  const ordem = { "máscara": 0, "inteiro pequeno": 1, dados: 2, "ponteiro/tabela": 3, "zero (não inicializado)": 4, "sem bytes no arquivo (.bss)": 5 };
  dataRefs.sort((a, b) => (ordem[a.tipo] - ordem[b.tipo]) || (b.refs - a.refs) || (a.rva - b.rva));
}

const report = {
  file: file.split(/[\\/]/).pop(),
  size: buf.length,
  format: FMT,
  machine: MACHINE_STR,
  imageBase: `0x${imageBase.toString(16)}`,
  entryPoint: `0x${entry.toString(16)}`,
  sizeOfImage: `0x${sizeOfImage.toString(16)}`,
  dllCharacteristics: HEAD.dllCharacteristics ?? null,
  header: HEAD,
  sections: sections.map((s) => ({
    name: s.name,
    // PE: RVA (relativo à ImageBase) · ELF: vaddr de link (absoluto, como no readelf)
    rva: s.va < 0 ? null : `0x${s.va.toString(16)}`,
    virtualSize: s.virtualSize,
    rawSize: s.rawSize,
    perms: `${s.read ? "R" : "-"}${s.write ? "W" : "-"}${s.exec ? "X" : "-"}`,
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
  if (isELF) {
    console.log(`  ${report.size} bytes · ${report.format} · ${report.machine} · ${HEAD.elfType}${HEAD.dynamic?.pie ? " · PIE (DF_1_PIE)" : ""}`);
    console.log(`  ${HEAD.interpreter ? `dinâmico (interpreter ${HEAD.interpreter})` : "sem interpreter — estático"} · entry=0x${entry.toString(16)} · faixa de endereços ${report.imageBase}..0x${imgHi.toString(16)}`);
    console.log(`  segmentos (program headers): ${HEAD.segments.length}`);
    for (const s of HEAD.segments) {
      if (!["LOAD", "INTERP", "DYNAMIC", "TLS", "GNU_STACK", "GNU_RELRO"].includes(s.type)) continue;
      console.log(`    ${s.type.padEnd(10)} vaddr=${s.vaddr.padEnd(12)} off=${s.offset.padEnd(9)} filesz=${String(s.filesz).padEnd(8)} memsz=${String(s.memsz).padEnd(8)} ${s.perms}`);
    }
  } else {
    console.log(`  ${report.size} bytes · ${report.format} · ${report.machine} · ImageBase=${report.imageBase} · EP=0x${entry.toString(16)} · SizeOfImage=${report.sizeOfImage}`);
    console.log(`  DllCharacteristics=${report.dllCharacteristics}`);
  }
  console.log("  seções:");
  for (const s of report.sections) {
    const onde = s.rva ? `addr=${s.rva.padEnd(10)}` : `off=0x${(sections.find((x) => x.name === s.name)?.raw ?? 0).toString(16).padEnd(7)}`;
    console.log(`    ${s.name.padEnd(15)} ${onde} virt=${String(s.virtualSize).padEnd(8)} raw=${String(s.rawSize).padEnd(8)} ${s.perms} entropia=${s.entropy}`);
  }
  if (!isELF) {
    console.log(`  diretórios: ${report.directories.map((d) => d.name).join(" ") || "(nenhum)"}`);
    if (tls) {
      console.log(`  TLS: callbacks=${tls.callbacks.length} (${tls.callbacks.map((c) => `rva 0x${c.rva.toString(16)}`).join(", ") || "nenhum"}) — o loader roda isto ANTES do entrypoint`);
    }
  } else {
    const din = HEAD.dynamic;
    if (din) {
      console.log(`  dinâmico: DT_NEEDED=${din.needed.length ? din.needed.join(", ") : "(nenhum)"}${din.soname ? ` · SONAME=${din.soname}` : ""}${din.rpath ? ` · RPATH=${din.rpath}` : ""}${din.runpath ? ` · RUNPATH=${din.runpath}` : ""}`);
      console.log(`    DT_INIT=${din.init ?? "(nenhum)"} · DT_INIT_ARRAY=${din.initArray ?? "(nenhum)"} — o loader chama isto ANTES do main (análogo ELF do TLS callback do PE)`);
      if (din.bindNow || din.textrel) {
        console.log(`    flags: ${[din.bindNow ? "BIND_NOW" : null, din.textrel ? "TEXTREL (relocação em região executável)" : null].filter(Boolean).join(" · ")}`);
      }
    } else {
      console.log("  dinâmico: sem .dynamic — binário estático");
    }
    for (const s of HEAD.signals) console.log(`  sinal: ${s}`);
  }
  console.log("");
  if (isELF) {
    console.log(`  bibliotecas (DT_NEEDED): ${imports.length ? imports.map((i) => i.dll).join(", ") : "(nenhuma)"}`);
    const und = HEAD.undefinedSymbols;
    console.log(`  símbolos indefinidos (o que ele chama de fora): ${und.length}`);
    if (und.length) {
      const txt = und.join(", ");
      console.log(`    ${txt.length > 900 ? txt.slice(0, 900) + ` … (+${und.length} no total; use --json)` : txt}`);
    }
  } else {
    console.log(`  imports (${imports.length} DLL):`);
    for (const i of imports) console.log(`    ${i.dll} (${i.count}): ${i.functions.join(", ")}`);
  }
  if (!NO_STRINGS) {
    console.log("");
    console.log(`  strings em seções de dados (>=${MIN} chars): ${strings.length}`);
    for (const s of withRefs) {
      const refs = s.refs?.length ? `   <- usada em ${s.refs.map((r) => `0x${r.rva.toString(16)} (${r.how})`).join(", ")}` : WANT_REFS ? "   <- (nenhuma referência encontrada no código)" : "";
      const loc = s.rva >= 0 ? `addr 0x${s.rva.toString(16).padStart(6, "0")}` : `off  0x${s.off.toString(16).padStart(6, "0")}`;
      console.log(`    ${loc} ${(s.sec ?? "?").padEnd(9)} ${s.wide ? "[utf16]" : "[ascii]"} ${JSON.stringify(s.text)}${refs}`);
    }
  }
  if (WANT_DATA_REFS) {
    console.log("");
    console.log(`  referências a DADOS que não são strings (constantes): ${dataRefs.length} alvo(s)`);
    for (const d of dataRefs.slice(0, 20)) {
      console.log(`    addr 0x${d.rva.toString(16).padStart(6, "0")} ${d.section} [${d.tipo}] <- ${d.refs} ref(s), 1a em 0x${(d.firstRef ?? 0).toString(16)} (${d.how})`);
      console.log(`        bytes: ${d.bytes}   ${d.ascii}`);
    }
    if (dataRefs.length > 20) console.log(`    … (+${dataRefs.length - 20} alvo(s); use --json para a lista completa)`);
  }
  console.log("");
}

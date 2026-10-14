#!/usr/bin/env node
/**
 * verify-dump.mjs — o dump reconstruído bate com o arquivo original? o que não bate é do
 * loader ou é defeito?
 *
 * Por que existe
 * --------------
 * O "Fix Dump" (Scylla) e o `rebuild-iat.mjs` produzem um arquivo que *parece* certo e abre
 * no Ghidra — mas quem decide é o loader, e um dump de MEMÓRIA carrega estado que o loader
 * não recria. Quando o analista tem o original em claro (a mesma build obtida por outro
 * caminho: uma cópia do programa, o arquivo antes do packer, a referência da mesma versão),
 * existe um teste muito mais forte que "abriu e não deu erro": **comparar byte a byte com o
 * original**, aplicando as relocações do próprio original (o dump rodou em outra base) e
 * separando o que é direito do loader do que é defeito.
 *
 * O que ele responde, e por que assim
 * -----------------------------------
 *   1. `expected` = o original com as relocações do original aplicadas para o delta de base
 *      (`dump.ImageBase - original.ImageBase`). Sem isso toda imagem com DYNAMIC_BASE
 *      apareceria diferente.
 *   2. Cada byte diferente vira uma classe:
 *        • `iat` / `iat-delay` — faixas de FirstThunk declaradas pelos descritores do dump
 *          (o loader preenche na carga; o `__delayLoadHelper2` preenche a IAT de delay no
 *          primeiro uso) → o conteúdo do arquivo é o antigo, e isso é esperado;
 *        • `loadconfig` / `tls` — o loader escreve os ponteiros de função do guard e indexa
 *          o TLS;
 *        • `estado-de-carga` — o `__security_cookie` e o complemento (o CRT recalcula; o
 *          loader exige o sentinela — `reset-load-state.mjs`);
 *        • `CODIGO` — diferença em seção EXECUTÁVEL. É o achado grave: instrução que não é a
 *          do original. Sai com exit 1.
 *        • `dados` — diferença em seção de dados: são as globais que o próprio programa
 *          escreveu ao rodar. Não é erro do dump (é a razão de um dump só rodar quando o
 *          programa reinicializa esse estado), mas fica listado — nada passa em silêncio.
 *
 * O caso que originou o script (iat-hardcase): o analista pôs um **breakpoint de software**
 * em `.text` ANTES de o stub do packer decriptar a seção; ao parar, o debugger restaurou o
 * byte *pré-decriptação* (o do arquivo empacotado) em vez do certo e o dump saiu com UMA
 * instrução trocada (`0x48` → `0x51`). O loader aceitava o arquivo e o programa morria com
 * AV dentro do CRT. `--dump dump-fixed.exe --original clean.exe` acusa esse byte como
 * `CODIGO` com o endereço exato; era o teste que faltava.
 *
 * Limites (medidos, não supostos)
 * -------------------------------
 *   * o original precisa ser a MESMA build e estar EM CLARO. Se as seções dele estiverem
 *     cifradas (é o arquivo empacotado), a comparação vira ruído: o script avisa quando uma
 *     seção difere em massa (>25%);
 *   * compara as seções presentes nos dois; seções só do dump (`.idata2`) e só do original
 *     são listadas, não comparadas;
 *   * `dados` inclui estado legítimo do programa — o relatório é uma lista para julgar.
 *
 * Uso:
 *   node scripts/verify-dump.mjs --dump <reconstruido.exe> --original <que-roda.exe>
 *        [--max <n>] [--strict] [--json]
 *
 * Exit: 0 nenhuma diferença em seção executável · 1 há (ou qualquer não explicada, com
 *       --strict) · 2 erro de uso ou arquivo ilegível. Nunca usa sudo.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);

if (has("--help") || has("-h") || !has("--dump") || !has("--original")) {
  console.log("uso: node scripts/verify-dump.mjs --dump <reconstruido.exe> --original <que-roda.exe> [--max n] [--strict] [--json]");
  console.log("  --dump       arquivo saído do rebuild-iat/reset-load-state (o que você vai rodar)");
  console.log("  --original   a mesma build em claro — base e mapa de relocação saem dele");
  console.log("  --max n      quantas faixas mostrar por classe (default 10; 0 = só a contagem)");
  console.log("  --strict     falha também se houver diferença em DADOS (verifica um dump tirado em tempo de carga)");
  process.exit(has("--dump") ? 2 : 0);
}
const dumpPath = val("--dump");
const origPath = val("--original");
const MAX = Number(val("--max", "10"));
const STRICT = has("--strict");
const JSON_OUT = has("--json");

const MSVC_COOKIE_SENTINEL = 0x2b992ddfa232n;
const COMPLEMENT = (~MSVC_COOKIE_SENTINEL) & 0xffffffffffffffffn;
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

function parsePE(buf, label) {
  const u16 = (o) => buf.readUInt16LE(o);
  const u32 = (o) => buf.readUInt32LE(o);
  if (buf.length < 0x40 || u16(0) !== 0x5a4d) throw new Error(`${label}: sem assinatura MZ`);
  const pe = u32(0x3c);
  if (u32(pe) !== 0x00004550) throw new Error(`${label}: assinatura PE ausente em 0x${pe.toString(16)}`);
  const is64 = u16(pe + 24) === 0x20b;
  const opt = pe + 24;
  const dirsOff = opt + (is64 ? 112 : 96);
  const secOff = opt + u16(pe + 20);
  const nSec = u16(pe + 6);
  const sections = [];
  for (let i = 0; i < nSec; i++) {
    const o = secOff + i * 40;
    if (o + 40 > buf.length) break;
    sections.push({
      name: buf.toString("latin1", o, o + 8).replace(/\0+$/, "") || "<sem nome>",
      va: u32(o + 12), vsz: u32(o + 8), raw: u32(o + 20), rawsz: u32(o + 16),
      chars: u32(o + 36),
    });
  }
  const secOf = (rva) => sections.find((s) => rva >= s.va && rva < s.va + Math.max(s.vsz, s.rawsz));
  return {
    buf, is64, sections,
    base: is64 ? buf.readBigUInt64LE(opt + 24) : BigInt(u32(opt + 28)),
    sizeOfImage: u32(opt + 56),
    dir: (i) => [u32(dirsOff + i * 8), u32(dirsOff + i * 8 + 4)],
    rva2off(rva) {
      const s = secOf(rva);
      if (!s) return -1;
      const off = s.raw + (rva - s.va);
      return off >= 0 && off < buf.length ? off : -1;
    },
    secOf,
  };
}

let dumpBuf, origBuf;
try {
  dumpBuf = readFileSync(dumpPath);
  origBuf = readFileSync(origPath);
} catch (e) {
  console.error(`não consegui ler: ${e.message}`);
  process.exit(2);
}
let d, o;
try {
  d = parsePE(dumpBuf, basename(dumpPath));
  o = parsePE(origBuf, basename(origPath));
} catch (e) {
  console.error(e.message);
  process.exit(2);
}

const delta = d.base - o.base;

// ── 1. expected = original com as relocações do original aplicadas ───────────
const expected = Buffer.from(origBuf);
let relocApplied = 0;
let relocUnsupported = 0;
const [relocRva, relocSize] = o.dir(5);
if (delta !== 0n && relocRva && relocSize) {
  let p = o.rva2off(relocRva);
  const end = p < 0 ? -1 : p + relocSize;
  while (p >= 0 && p + 8 <= end && p + 8 <= expected.length) {
    const pageRva = expected.readUInt32LE(p);
    const blockSize = expected.readUInt32LE(p + 4);
    if (blockSize < 8 || p + blockSize > end) break;
    for (let i = 0; i + 1 < (blockSize - 8) / 2; i++) {
      const e = expected.readUInt16LE(p + 8 + i * 2);
      const type = e >> 12;
      if (!type) continue; // ABSOLUTE: preenchimento
      const off = o.rva2off(pageRva + (e & 0xfff));
      if (off < 0) continue;
      if (type === 10) { expected.writeBigUInt64LE(expected.readBigUInt64LE(off) + delta, off); relocApplied++; }
      else if (type === 3) { expected.writeUInt32LE((expected.readUInt32LE(off) + Number(delta & 0xffffffffn)) >>> 0, off); relocApplied++; }
      else relocUnsupported++;
    }
    p += blockSize;
  }
}

// ── 2. faixas de propriedade do loader, lidas do próprio dump ────────────────
const loaderOwned = [];
const addRange = (rva, size, kind, what) => {
  if (rva && size) loaderOwned.push({ lo: rva, hi: rva + size, kind, what });
};
addRange(d.dir(10)[0], d.dir(10)[1], "loadconfig", "diretório LOAD_CONFIG");
addRange(d.dir(9)[0], d.dir(9)[1], "tls", "diretório TLS");

const iatRanges = [];
const importRva = d.dir(1)[0];
const importSize = d.dir(1)[1];
if (importRva && importSize) {
  for (let i = 0; i * 20 < importSize; i++) {
    const off = d.rva2off(importRva + i * 20);
    if (off < 0) break;
    const oft = d.buf.readUInt32LE(off);
    const name = d.buf.readUInt32LE(off + 12);
    const ft = d.buf.readUInt32LE(off + 16);
    if (!oft && !name && !ft) break;
    const nameOff = d.rva2off(name);
    const dll = nameOff >= 0 ? d.buf.toString("latin1", nameOff, d.buf.indexOf(0, nameOff)) : "?";
    let n = 0;
    const iltOff = d.rva2off(oft);
    if (iltOff >= 0) for (let k = 0; ; k++) { if (iltOff + k * 8 + 8 > d.buf.length) break; if (d.buf.readBigUInt64LE(iltOff + k * 8) === 0n) break; n++; }
    if (n && ft) {
      iatRanges.push({ dll, lo: ft, hi: ft + n * 8, slots: n });
      addRange(ft, n * 8, "iat", `${dll} (${n})`);
    }
  }
}
const delayRva = d.dir(13)[0];
const delaySize = d.dir(13)[1];
if (delayRva && delaySize) {
  for (let i = 0; i * 32 < delaySize; i++) {
    const off = d.rva2off(delayRva + i * 32);
    if (off < 0) break;
    const name = d.buf.readUInt32LE(off + 4);
    const intRva = d.buf.readUInt32LE(off + 12);
    const iatRva = d.buf.readUInt32LE(off + 16);
    if (!name && !iatRva) break;
    const nameOff = d.rva2off(name);
    const dll = nameOff >= 0 ? d.buf.toString("latin1", nameOff, d.buf.indexOf(0, nameOff)) : "?";
    let n = 0;
    const intOff = d.rva2off(intRva);
    if (intOff >= 0) for (let k = 0; ; k++) { if (intOff + k * 8 + 8 > d.buf.length) break; if (d.buf.readBigUInt64LE(intOff + k * 8) === 0n) break; n++; }
    if (n && iatRva) addRange(iatRva, n * 8, "iat-delay", `${dll} (${n})`);
  }
}
const ownerOf = (rva) => loaderOwned.find((r) => rva >= r.lo && rva < r.hi);
const lcRva = d.dir(10)[0];
let cookieRva = -1;
if (lcRva) {
  const lcOff = d.rva2off(lcRva);
  if (lcOff >= 0) {
    const cookieVa = d.buf.readBigUInt64LE(lcOff + 0x58);
    if (cookieVa >= d.base && cookieVa < d.base + BigInt(d.sizeOfImage)) cookieRva = Number(cookieVa - d.base);
  }
}

// ── 3. comparar seção por seção, agregando por classe e por faixa contígua ───
const runs = new Map(); // classe -> [{lo, hi, onde}]
const addByte = (kind, rva, where) => {
  const list = runs.get(kind) || [];
  const last = list[list.length - 1];
  if (last && last.hi === rva && last.where === where) last.hi = rva + 1;
  else list.push({ lo: rva, hi: rva + 1, where });
  runs.set(kind, list);
};
const sectionsReport = [];
const dumpOnly = [];
const origOnly = [];
for (const s of d.sections) {
  const os = o.sections.find((x) => x.name === s.name);
  if (!os) { dumpOnly.push(s.name); continue; }
  const len = Math.min(s.vsz, os.vsz);
  const executable = (s.chars & IMAGE_SCN_MEM_EXECUTE) !== 0;
  let diff = 0;
  for (let rva = s.va; rva < s.va + len; rva++) {
    const dOff = d.rva2off(rva);
    const oOff = o.rva2off(rva);
    if (dOff < 0 || oOff < 0) continue;
    if (d.buf[dOff] === expected[oOff]) continue;
    diff++;
    const owned = ownerOf(rva);
    if (owned) { addByte(owned.kind, rva, owned.what); continue; }
    const aligned = rva - (rva % 8);
    const aOff = o.rva2off(aligned);
    if (aOff >= 0 && aOff + 8 <= expected.length) {
      const v = expected.readBigUInt64LE(aOff);
      if (v === MSVC_COOKIE_SENTINEL || v === COMPLEMENT) { addByte("estado-de-carga", rva, "cookie/complemento do MSVC"); continue; }
    }
    if (cookieRva >= 0 && rva >= cookieRva && rva < cookieRva + 8) { addByte("estado-de-carga", rva, "SecurityCookie (LOAD_CONFIG)"); continue; }
    addByte(executable ? "CODIGO" : "dados", rva, s.name);
  }
  sectionsReport.push({ secao: s.name, executavel: executable, bytesDiferentes: diff, bytesComparados: len });
}
for (const s of o.sections) if (!d.sections.find((x) => x.name === s.name)) origOnly.push(s.name);

const byClass = Object.fromEntries([...runs].map(([k, v]) => [k, { bytes: v.reduce((a, r) => a + (r.hi - r.lo), 0), faixas: v.length }]));
const codeBytes = byClass.CODIGO?.bytes ?? 0;
const dataBytes = byClass.dados?.bytes ?? 0;
const massDiff = sectionsReport.filter((s) => s.bytesComparados >= 64 && s.bytesDiferentes > s.bytesComparados * 0.25);
const hexOf = (rva, which) => {
  const p = which === "dump" ? d : o;
  const off = p.rva2off(rva);
  if (off < 0) return null;
  const end = Math.min(off + 16, p.buf.length);
  return p.buf.subarray(off, end).toString("hex").replace(/(..)/g, "$1 ").trim();
};

const report = {
  dump: basename(dumpPath),
  original: basename(origPath),
  baseDump: `0x${d.base.toString(16)}`,
  baseOriginal: `0x${o.base.toString(16)}`,
  deltaAplicado: `0x${delta.toString(16)}`,
  relocacoesAplicadas: relocApplied,
  relocacoesTipoNaoSuportado: relocUnsupported,
  secoes: sectionsReport,
  secoesSoNoDump: dumpOnly,
  secoesSoNoOriginal: origOnly,
  iatDeclaradaPeloDump: { faixas: iatRanges.length, slots: iatRanges.reduce((a, r) => a + r.slots, 0), dlls: [...new Set(iatRanges.map((r) => r.dll))] },
  diferencas: Object.fromEntries([...runs].map(([k, v]) => [k, {
    bytes: v.reduce((a, r) => a + (r.hi - r.lo), 0),
    faixas: v.length,
    amostra: (MAX ? v.slice(0, MAX) : []).map((r) => ({
      rva: `0x${r.lo.toString(16)}`, tamanho: r.hi - r.lo, onde: r.where,
      esperado: hexOf(r.lo, "orig"), noDump: hexOf(r.lo, "dump"),
    })),
  }])),
  bytesEmCodigo: codeBytes,
  bytesEmDados: dataBytes,
  avisos: massDiff.map((s) => `${s.secao}: ${s.bytesDiferentes}/${s.bytesComparados} bytes diferentes (>25%) — o original pode não ser a versão em claro desta seção (empacotado? build diferente?)`),
};

if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
} else {
  const label = {
    iat: "iat            (faixa de FirstThunk: o loader preenche na carga)",
    "iat-delay": "iat-delay      (o __delayLoadHelper2 preenche no 1º uso)",
    loadconfig: "loadconfig     (o loader escreve os ponteiros de função)",
    tls: "tls            (o loader indexa/preenche)",
    "estado-de-carga": "estado-de-carga (cookie/complemento: o CRT recalcula)",
    dados: "dados          (globais que o programa escreveu ao rodar)",
    CODIGO: "CODIGO         (diferença em seção executável — é defeito)",
  };
  console.log("");
  console.log(`UnboxRE — verificação de dump contra o original: ${report.dump} vs ${report.original}`);
  console.log("─".repeat(78));
  console.log(`  base do dump = ${report.baseDump}  ·  base do original = ${report.baseOriginal}  ·  delta = ${report.deltaAplicado}`);
  console.log(`  relocações do original aplicadas: ${relocApplied}${relocUnsupported ? `  (${relocUnsupported} de tipo não suportado)` : ""}`);
  console.log(`  IAT declarada pelos descritores do dump: ${report.iatDeclaradaPeloDump.faixas} faixa(s) / ${report.iatDeclaradaPeloDump.slots} slot(s) de ${report.iatDeclaradaPeloDump.dlls.length} DLL(s)`);
  console.log("");
  for (const s of sectionsReport) console.log(`  ${(s.executavel ? "X " : "  ") + s.secao.padEnd(9)} ${String(s.bytesDiferentes).padStart(7)} byte(s) diferente(s) de ${s.bytesComparados}`);
  if (dumpOnly.length) console.log(`  só no dump: ${dumpOnly.join(", ")}`);
  if (origOnly.length) console.log(`  só no original: ${origOnly.join(", ")}`);
  console.log("");
  const order = ["CODIGO", "iat", "iat-delay", "loadconfig", "tls", "estado-de-carga", "dados"];
  for (const k of [...order, ...[...runs.keys()].filter((x) => !order.includes(x))]) {
    const v = runs.get(k);
    if (!v) continue;
    console.log(`  ${label[k] ?? k}: ${byClass[k].bytes} byte(s) em ${byClass[k].faixas} faixa(s)`);
    for (const r of v.slice(0, MAX)) {
      console.log(`      rva 0x${r.lo.toString(16)}  ${String(r.hi - r.lo).padStart(3)}B  [${r.where}]`);
      if (r.hi - r.lo <= 16) {
        console.log(`          esperado (original): ${hexOf(r.lo, "orig")}`);
        console.log(`          no dump            : ${hexOf(r.lo, "dump")}`);
      }
    }
  }
  if (!runs.size) console.log("  nenhuma diferença: o dump é o original, byte a byte (para a base/estado do loader)");
  for (const a of report.avisos) console.log(`  [aviso] ${a}`);
  console.log("");
  if (codeBytes) {
    console.log(`  Veredito: ${codeBytes} byte(s) em seção EXECUTÁVEL não são os do original. Duas leituras —`);
    console.log("            dá para separar sem adivinhar:");
    console.log("              (a) byte escrito por engano no dump: breakpoint de SOFTWARE em .text antes de o");
    console.log("                  stub decriptar (o debugger restaura o byte pr\u00e9-decripta\u00e7\u00e3o), se\u00e7\u00e3o remontada errada,");
    console.log("                  original de outra build. O original NUNCA escreve ali → defeito.");
    console.log("              (b) auto-patch do pr\u00f3prio programa (thunks/hooks em runtime): rode o ORIGINAL com");
    console.log("                  `ba w4 <endere\u00e7o>` e veja se ele escreve ali — se escreve, \u00e9 estado de execu\u00e7\u00e3o.");
  } else if (STRICT && (dataBytes || Object.keys(byClass).length)) {
    console.log("  Veredito: nenhuma diferença em código, mas há diferenças em dados/loader (--strict).");
  } else {
    console.log("  Veredito: o código é o do original, byte a byte. As demais diferenças são do loader");
    console.log("            (IAT/LOAD_CONFIG/TLS) e do estado que o CRT recalcula (cookie).");
  }
  console.log("");
}

// --strict: além do código, exige que não exista diferença em DADOS — é o teste de um dump
// tirado em tempo de carga (o programa ainda não escreveu nada nas próprias globais).
const fail = codeBytes > 0 || relocUnsupported > 0 || (STRICT && dataBytes > 0);
process.exit(fail ? 1 : 0);

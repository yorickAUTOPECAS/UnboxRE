#!/usr/bin/env node
/**
 * triage-java.mjs — triagem de alvo JVM: JAR (ou .class solto) e o que ele esconde.
 *
 * Por que existe
 * --------------
 * O alvo `nivel 6.5` é um **JAR** (cliente Minecraft/Forge) com uma trava anti-leak
 * feita de bytecode + uma DLL nativa de 31 MB — e nenhum dos leitores do toolkit
 * respondeu: os cinco do Cenário 0 são sobre **imagem** (PE/ELF) e o `triage-archive`
 * identifica o ZIP e os membros, mas não lê **bytecode**. O que decidia a rodada
 * (quem tem método `native`, quem extrai recurso e chama `System.load`, quais entradas
 * colidem por maiúscula) só saiu com `javap` em laço e script escrito no diretório do
 * caso. Recusar não é triagem (mesma lição dos rounds 8.3–8.5): aqui a JVM é lida.
 *
 * O que ele responde, e por que cada item importou de verdade
 * ----------------------------------------------------------
 *   1. **inventário com o que é binário nativo** — um `.jar` que carrega `x64-windows.dll`
 *      não é "só Java": a lógica pode estar no nativo. (Medido: 1 entrada `.dll` de
 *      31.453.712 B dentro do JAR.)
 *   2. **classes com método `native`** — os métodos que o JVM vai procurar em biblioteca
 *      carregada. Vem com nome e assinatura, e sinaliza o padrão de **nome de 40 hex**
 *      (`[0-9a-f]{40}`) que o antiLeak usa como marcador: um `native` desses é chamado
 *      pelo `<clinit>` de cada classe protegida. (Medido: 32 classes, 100 nativos, um
 *      marcador de 40 hex por classe.)
 *   3. **quem extrai e carrega** — classe que referencia `System.load`/`loadLibrary` e
 *      `getResourceAsStream`/`FileOutputStream` é o loader que escreve a DLL em disco
 *      (`native/<6 chars>.lib`) e a carrega. É o alvo da análise, e é onde a trava
 *      travou uma JVM inteira em 4 execuções (JRE 8 e JDK 21).
 *   4. **entradas que só diferem por maiúscula** — armadilha medida DUAS vezes neste
 *      alvo: um JAR com `myau/H.class` e `myau/h.class` **não se extrai** em NTFS sem
 *      pasta case-sensitive; um dos dois é sobrescrito em silêncio (o `binaries/myau/
 *      H.class` do alvo acabou contendo a classe `h`). O script conta e avisa ANTES de
 *      a extração destruir o material. (Medido: 88 pares.)
 *   5. **versão do class file** — diz contra qual JVM compilar/rodar de verdade
 *      (52 = Java 8; carregar em JVM mais nova funciona, carregar bytecode novo em JVM
 *      antiga dá UnsupportedClassVersionError — medido com um probe compilado em Java 21).
 *
 * Uso: node scripts/triage-java.mjs <arquivo.jar|.class|.zip> [--max-classes N] [--json]
 * Exit: 0 analisado · 2 arquivo ilegível ou formato não reconhecido. Nunca usa sudo.
 *
 * Sem dependência: Node puro (mesmo leitor de ZIP do triage-archive), nada a instalar.
 */

import { readFileSync, statSync } from "node:fs";
import { basename } from "node:path";
import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);
if (argv.length === 0 || has("--help") || has("-h")) {
  console.log("uso: node scripts/triage-java.mjs <arquivo.jar|.class|.zip> [--max-classes N] [--json]");
  console.log("  lê: JAR/ZIP de bytecode (JVM) ou um .class solto");
  console.log("  diz: versão de class file, classes com método native, loader JNI");
  console.log("       (System.load + extração de recurso), binários embutidos e");
  console.log("       entradas que só diferem por maiúscula (armadilha do NTFS)");
  console.log("  --max-classes N  limita quantas classes são abertas (default 2000)");
  console.log("  --json           saída JSON");
  process.exit(0);
}
const file = argv.find((a) => !a.startsWith("--"));
if (!file) {
  console.error("uso: node scripts/triage-java.mjs <arquivo.jar|.class|.zip> [--max-classes N] [--json]");
  process.exit(2);
}
const JSON_OUT = has("--json");
const MAX_CLASSES = Number(val("--max-classes", "2000")) || 2000;

let buf;
try {
  buf = readFileSync(file);
} catch (e) {
  console.error(`[!!] não consegui ler ${file}: ${e.message}`);
  process.exit(2);
}
const size = statSync(file).size;
const sha256 = createHash("sha256").update(buf).digest("hex").toUpperCase();

// ── ZIP (mesmo caminho do triage-archive: EOCD + diretório central) ──────────

function findEOCD(b) {
  const max = Math.min(b.length, 0x10000 + 22);
  for (let i = b.length - 22; i >= b.length - max; i--) {
    if (i < 0) break;
    if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 0x05 && b[i + 3] === 0x06) {
      return { count: b.readUInt16LE(i + 10), cdOff: b.readUInt32LE(i + 16) };
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
    if (b.readUInt32LE(p) !== 0x02014b50) break;              // PK\x01\x02
    const nameLen = b.readUInt16LE(p + 28);
    const extraLen = b.readUInt16LE(p + 30);
    const cmtLen = b.readUInt16LE(p + 32);
    const name = b.subarray(p + 46, p + 46 + nameLen).toString("latin1");
    members.push({
      name,
      method: b.readUInt16LE(p + 10),
      compSize: b.readUInt32LE(p + 20),
      size: b.readUInt32LE(p + 24),
      localOff: b.readUInt32LE(p + 42),
      isDir: name.endsWith("/"),
    });
    p += 46 + nameLen + extraLen + cmtLen;
  }
  return members;
}

/** Bytes de um membro (método 0 = guardado, 8 = deflate). */
function memberData(b, m) {
  const o = m.localOff;
  if (o + 30 > b.length || b.readUInt32LE(o) !== 0x04034b50) return null;
  const start = o + 30 + b.readUInt16LE(o + 26) + b.readUInt16LE(o + 28);
  const raw = b.subarray(start, start + m.compSize);
  if (m.method === 0) return raw;
  if (m.method === 8) {
    try { return inflateRawSync(raw); } catch { return null; }
  }
  return null;
}

// ── class file: constant pool, flags, métodos ────────────────────────────────

/**
 * Lê o essencial de um .class numa passada só: versão, nome, métodos (ACC_NATIVE) e os
 * Methodrefs resolvidos para "owner.metodo" (é assim que se vê java/lang/System.load).
 * Devolve null se o pool tiver tag desconhecida — melhor dizer "não li" que ler errado.
 */
function parseClass(b) {
  if (b.length < 10 || b.readUInt32BE(0) !== 0xcafebabe) return null;
  const major = b.readUInt16BE(6);
  const cpCount = b.readUInt16BE(8);
  const utf8 = new Map();
  const classNameIdx = new Map();
  const natIdx = new Map();
  const refs = [];                                  // {owner, nat} de Field/Method/Interface
  let p = 10;
  for (let i = 1; i < cpCount; i++) {
    const tag = b[p]; p++;
    if (tag === 1) { const len = b.readUInt16BE(p); utf8.set(i, b.subarray(p + 2, p + 2 + len).toString("utf8")); p += 2 + len; }
    else if (tag === 3 || tag === 4) p += 4;
    else if (tag === 5 || tag === 6) { p += 8; i++; }
    else if (tag === 7) { classNameIdx.set(i, b.readUInt16BE(p)); p += 2; }
    else if (tag === 8 || tag === 16 || tag === 19 || tag === 20) p += 2;
    else if (tag === 9 || tag === 10 || tag === 11) { refs.push({ owner: b.readUInt16BE(p), nat: b.readUInt16BE(p + 2) }); p += 4; }
    else if (tag === 12) { natIdx.set(i, [b.readUInt16BE(p), b.readUInt16BE(p + 2)]); p += 4; }
    else if (tag === 15) p += 3;
    else if (tag === 17 || tag === 18) p += 4;
    else return null;
    if (p > b.length) return null;
  }
  const nameOf = (idx) => utf8.get(classNameIdx.get(idx)) ?? `#${idx}`;
  if (p + 8 > b.length) return null;
  const thisClass = nameOf(b.readUInt16BE(p + 2));
  p += 6;
  p += 2 + b.readUInt16BE(p) * 2;                    // interfaces
  const readMembers = () => {
    const count = b.readUInt16BE(p); p += 2;
    const out = [];
    for (let i = 0; i < count; i++) {
      if (p + 8 > b.length) return out;
      const acc = b.readUInt16BE(p);
      const name = utf8.get(b.readUInt16BE(p + 2)) ?? "?";
      const desc = utf8.get(b.readUInt16BE(p + 4)) ?? "?";
      p += 6;
      const attrCount = b.readUInt16BE(p); p += 2;
      for (let a = 0; a < attrCount; a++) {
        if (p + 6 > b.length) return out;
        p += 6 + b.readUInt32BE(p + 2);
      }
      out.push({ acc, name, desc });
    }
    return out;
  };
  readMembers();                                     // fields
  const methods = readMembers();
  const calls = new Set();
  for (const ref of refs) {
    const pair = natIdx.get(ref.nat);
    if (!pair) continue;
    calls.add(`${nameOf(ref.owner)}.${utf8.get(pair[0]) ?? "?"}`);
  }
  return { major, thisClass, methods, calls };
}

// ── análise ──────────────────────────────────────────────────────────────────

const NATIVE = 0x0100;
const BINARY_EXT = /\.(dll|lib|so|dylib|exe|bin|node)$/i;
const MARKER = /^[0-9a-f]{40}$/;
const LOAD_CALL = /^(java\/lang\/(System|Runtime)\.(load|loadLibrary)|java\/lang\/ClassLoader\.loadLibrary)$/;
const EXTRACT_CALL = /^(java\/lang\/Class\.getResourceAsStream|java\/io\/FileOutputStream\.<init>|java\/io\/File\.(createTempFile|mkdirs?))$/;

const members = findEOCD(buf) ? zipMembers(buf) : null;
const singleClass = !members && buf.length >= 4 && buf.readUInt32BE(0) === 0xcafebabe;
if (!members && !singleClass) {
  console.error(`${file}: não é JAR/ZIP (sem EOCD) nem class file (sem CAFEBABE) — triagem de Java não se aplica`);
  process.exit(2);
}

const report = {
  file: basename(file),
  size,
  sha256,
  kind: members ? "JAR/ZIP" : "class",
  entries: members ? members.length : 1,
  binaries: [],
  classMajor: {},
  classes: { total: 0, opened: 0, withNative: [], nativeTotal: 0, markers: 0, loaders: [] },
  caseCollisions: [],
};

let classEntries;
if (members) {
  classEntries = members.filter((m) => !m.isDir && /\.class$/i.test(m.name));
  for (const m of members) {
    if (m.isDir) continue;
    if (!/\.class$/i.test(m.name) && BINARY_EXT.test(m.name)) report.binaries.push({ name: m.name, size: m.size });
  }
  const byLower = new Map();
  for (const m of members) {
    if (m.isDir) continue;
    const key = m.name.toLowerCase();
    byLower.set(key, [...(byLower.get(key) ?? []), m.name]);
  }
  for (const names of byLower.values()) if (names.length > 1) report.caseCollisions.push([...names].sort());
} else {
  classEntries = [{ name: basename(file), single: true }];
}
report.classes.total = classEntries.length;

for (const m of classEntries.slice(0, MAX_CLASSES)) {
  const bytes = m.single ? buf : memberData(buf, m);
  if (!bytes) continue;
  const cp = parseClass(bytes);
  if (!cp) continue;
  report.classes.opened++;
  report.classMajor[cp.major] = (report.classMajor[cp.major] ?? 0) + 1;

  const natives = cp.methods.filter((x) => (x.acc & NATIVE) !== 0);
  if (natives.length) {
    const markers = natives.filter((x) => MARKER.test(x.name)).length;
    report.classes.markers += markers;
    report.classes.nativeTotal += natives.length;
    report.classes.withNative.push({
      class: cp.thisClass,
      entry: m.name,
      natives: natives.map((x) => `${x.name}${x.desc}`),
      markers,
    });
  }
  const loads = [...cp.calls].filter((c) => LOAD_CALL.test(c));
  if (loads.length) {
    report.classes.loaders.push({
      class: cp.thisClass,
      entry: m.name,
      loads,
      extracts: [...cp.calls].filter((c) => EXTRACT_CALL.test(c)),
    });
  }
}

const JAVA_VERSION = (major) =>
  major <= 48 ? `Java 1.x (${major})` : major === 52 ? "Java 8" : major === 55 ? "Java 11" :
    major === 61 ? "Java 17" : major === 65 ? "Java 21" : `class file ${major}`;

if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}

const MB = (n) => `${(n / 1048576).toFixed(2)} MB`;
console.log("");
console.log(`UnboxRE — triagem de Java: ${report.file}`);
console.log("─".repeat(70));
console.log(`  ${size} bytes (${MB(size)}) · ${report.kind} · sha256 ${sha256.slice(0, 16)}…`);
console.log(`  entradas: ${report.entries} · classes: ${report.classes.total} (abertas: ${report.classes.opened})`);

console.log("  versões de class file:");
for (const [maj, n] of Object.entries(report.classMajor).sort((a, b) => b[1] - a[1])) {
  console.log(`    major ${maj} (${JAVA_VERSION(Number(maj))}): ${n} classe(s)`);
}

if (report.binaries.length) {
  console.log("  binários nativos embutidos (a lógica pode estar aqui, não no bytecode):");
  for (const b of report.binaries) console.log(`    ${b.name}  ${b.size} bytes (${MB(b.size)})`);
} else {
  console.log("  binários nativos embutidos: nenhum");
}

console.log("");
console.log(`  [!!] classes com método native: ${report.classes.withNative.length}  (métodos nativos: ${report.classes.nativeTotal}; marcadores de 40 hex: ${report.classes.markers})`);
for (const c of report.classes.withNative.slice(0, 40)) {
  const tag = c.markers ? ` · ${c.markers} marcador(es) 40-hex` : "";
  console.log(`    ${c.class}  (${c.natives.length} nativo(s)${tag})`);
  console.log(`      ${c.natives.slice(0, 6).join(", ")}${c.natives.length > 6 ? ", …" : ""}`);
}
if (report.classes.withNative.length > 40) console.log(`    … +${report.classes.withNative.length - 40} classe(s)`);

if (report.classes.loaders.length) {
  console.log("");
  console.log("  [!!] classe(s) que CARREGAM biblioteca nativa (o loader da trava):");
  for (const l of report.classes.loaders) {
    console.log(`    ${l.class}  (${l.entry})`);
    console.log(`      chama: ${[...new Set(l.loads)].join(", ")}`);
    if (l.extracts.length) console.log(`      e extrai: ${[...new Set(l.extracts)].join(", ")}`);
  }
} else {
  console.log("  classe que carrega biblioteca nativa: nenhuma encontrada");
}

if (report.caseCollisions.length) {
  console.log("");
  console.log(`  [!!] ${report.caseCollisions.length} par(es) de entradas que só diferem por MAIÚSCULA:`);
  for (const pair of report.caseCollisions.slice(0, 8)) console.log(`    ${pair.join("  |  ")}`);
  if (report.caseCollisions.length > 8) console.log(`    … +${report.caseCollisions.length - 8} par(es)`);
  console.log("    extrair isto em NTFS sem pasta case-sensitive SOBRESCREVE um dos dois em silêncio");
  console.log("    (medido: `binaries/myau/H.class` do alvo acabou com o conteúdo da classe `h`).");
} else {
  console.log("  colisões de maiúscula nas entradas: nenhuma");
}
console.log("");
process.exit(0);

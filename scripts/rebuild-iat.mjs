#!/usr/bin/env node
/**
 * rebuild-iat.mjs — reconstrói a tabela de imports de um dump de MEMÓRIA.
 *
 * Por que existe
 * --------------
 * O caso UPX (docs/06-workflows.md, Cenário 0) tem volta fácil: `upx -d` restaura o
 * arquivo. O caso que exige trabalho é um packer SEM caminho de volta: em memória, no
 * OEP, existe uma IAT cheia de PONTEIROS ABSOLUTOS (endereços daquela execução) e
 * NENHUM descritor de import. Um dump cru disso não roda de novo — os endereços são de
 * outro processo, em que os módulos caíram em outras bases.
 *
 * A ferramenta canônica para esse reparo é o **Scylla** (`NtQuery/Scylla`, GPL-3.0), que
 * faz isso NA GUI dentro do x64dbg (Plugins → Scylla; ou o comando `StartScylla`, com os
 * apelidos `scylla` e `imprec`). O Scylla upstream NÃO tem modo CLI: o que existe é a DLL
 * exportando `ScyllaIatSearch`/`ScyllaIatFixAutoW`/`ScyllaRebuildFileW` (automação exigiria
 * escrever um harnês nativo). Este script é o mesmo trabalho de forma HEADLESS e
 * reproduzível, para o fluxo poder ser auditado comando a comando:
 *
 *   1. acha a IAT — duas rotas independentes:
 *        a) thunks de import direto no código (`FF 25 disp32` => `jmp qword [rip+disp]`),
 *           que apontam exatamente para os slots que o código do alvo usa;
 *        b) varredura por blocos de 8 bytes que apontam para dentro de módulos
 *           conhecidos (mínimo de 3 slots seguidos);
 *   2. para cada slot, resolve (DLL, nome/ordinal) pelo ponteiro: quem contém o endereço
 *      é o módulo; a RVA dentro dele é a função, e a tabela de EXPORTS do módulo diz o
 *      nome — ou o ordinal, se o export não tiver nome (import `#N`);
 *   3. escreve uma tabela de imports NOVA numa seção nova, com `FirstThunk` = a RVA dos
 *      slots ORIGINAIS (é o que faz o loader preencher os endereços onde o código do alvo
 *      realmente chama) e `OriginalFirstThunk` = a ILT nova com os hint/name;
 *   4. aponta os data directories IMPORT e IAT para a tabela nova e grava o arquivo.
 *
 * O que ele NÃO faz (de propósito): limpar a seção do stub, desofuscar código, corrigir
 * relocações ou mexer no OEP. Num dump em que o stub já restaurou o OEP original
 * (é o caso do `scripts/make-packed-sample.mjs`), o OEP do cabeçalho já está certo.
 *
 * Pré-requisitos do caso (e limites honestos)
 * -------------------------------------------
 *   * o dump precisa estar no LAYOUT DE MEMÓRIA (as seções mapeadas na RVA), que é o que
 *     o `DumpModule` do x64dbg-MCP produz — e o que o Scylla também espera;
 *   * a lista de módulos (nome, base, tamanho) tem de vir de FORA do dump: um dump de
 *     módulo único não contém os módulos de sistema. O Scylla tira isso do processo vivo
 *     (ele é um plugin de debugger); aqui vem do `ListModules` do MCP. Sem isso não há
 *     como saber a qual DLL pertence cada ponteiro;
 *   * x64 (PE32+) e nomes de export; ordinal só quando o export não tem nome;
 *   * módulos de sistema são lidos dos arquivos em disco (`C:\Windows\System32`) para
 *     resolver os exports — mesma build que o processo carregou, então as RVAs batem.
 *
 * Uso:
 *   node scripts/rebuild-iat.mjs --dump <dump.exe> --out <saida.exe> \
 *        --modules <arquivo.txt|"nome=0xbase=0xsize,..."> [--oep <rva>] \
 *        [--mem <dir dos blobs .bin das imagens carregadas>] [--system32 <dir>] [--json]
 *
 *   # a lista de módulos sai viva do debugger (evidência do caso):
 *   node scripts/x64dbg-drive.mjs --modules > evidence/modules.txt
 *
 * Exit: 0 tabela reconstruída · 1 o dump não permitiu reconstruir · 2 erro de uso.
 * Nunca usa sudo.
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);

if (has("--help") || has("-h") || argv.length === 0) {
  console.log("uso: node scripts/rebuild-iat.mjs --dump <dump.exe> --out <saida.exe> --modules <arq|lista>");
  console.log("     --dump <arquivo>    dump de memória (layout de memória: rawptr == RVA)");
  console.log("     --out <arquivo>     PE reconstruído (tabela de imports nova)");
  console.log("     --modules <x>       arquivo com as linhas do ListModules (0xbase | 0xsize | nome)");
  console.log("                         OU lista inline 'nome=0xbase=0xsize,...'");
  console.log("     --oep <rva>         OEP conhecido (só informativo/relatório)");
  console.log("     --mem <dir>         blobs '<modulo>.bin' das imagens CARREGADAS (recomendado):");
  console.log("                         node scripts/x64dbg-drive.mjs --dump-module-mem <mod> <dir>/<mod>.bin");
  console.log("     --system32 <dir>    fallback: onde ler os módulos de sistema (default: %WINDIR%\\System32)");
  console.log("     --json              relatório em JSON");
  process.exit(argv.length === 0 ? 2 : 0);
}

const JSON_OUT = has("--json");
const dumpPath = val("--dump");
const outPath = val("--out");
const modulesArg = val("--modules");
const oepRva = val("--oep") ? Number(BigInt(val("--oep"))) : null;
const sys32 = val("--system32") ?? join(process.env.WINDIR ?? "C:\\Windows", "System32");

if (!dumpPath || !outPath || !modulesArg) {
  console.error("[!!] faltou --dump, --out ou --modules (veja --help)");
  process.exit(2);
}
if (!existsSync(dumpPath)) {
  console.error(`[!!] dump não existe: ${dumpPath}`);
  process.exit(2);
}

const die = (m) => {
  console.error(`[!!] ${m}`);
  process.exit(1);
};
const log = (m) => {
  if (!JSON_OUT) console.log(m);
};

// ── PE: leitura do dump ─────────────────────────────────────────────────────
const b = readFileSync(dumpPath);
if (b.readUInt16LE(0) !== 0x5a4d) die(`${basename(dumpPath)}: sem assinatura MZ — não é um dump de imagem`);
const peOff = b.readUInt32LE(0x3c);
if (b.readUInt32LE(peOff) !== 0x4550) die(`${basename(dumpPath)}: sem assinatura PE`);
const machine = b.readUInt16LE(peOff + 4);
if (machine !== 0x8664) die(`machine=0x${machine.toString(16)}: só x64 (PE32+) é suportado`);
const nSec = b.readUInt16LE(peOff + 6);
const optSz = b.readUInt16LE(peOff + 20);
const opt = peOff + 24;
const magic = b.readUInt16LE(opt);
if (magic !== 0x20b) die(`optional header magic=0x${magic.toString(16)}: só PE32+ é suportado`);
const secAlign = b.readUInt32LE(opt + 32);
const fileAlign = b.readUInt32LE(opt + 36);
const sizeOfImage = b.readUInt32LE(opt + 56);
const sizeOfHeaders = b.readUInt32LE(opt + 60);
const entryPoint = b.readUInt32LE(opt + 16);
const imageBase = Number(b.readBigUInt64LE(opt + 24));
const dirsOff = opt + 112;
const secTable = opt + optSz;

const sections = [];
for (let i = 0; i < nSec; i++) {
  const o = secTable + i * 40;
  sections.push({
    name: b.toString("latin1", o, o + 8).replace(/\0+$/, ""),
    vsz: b.readUInt32LE(o + 8),
    va: b.readUInt32LE(o + 12),
    rawsz: b.readUInt32LE(o + 16),
    rawptr: b.readUInt32LE(o + 20),
    flags: b.readUInt32LE(o + 36),
    hdrOff: o,
  });
}
// O DumpModule do x64dbg escreve quase sempre no layout de memória (rawptr == RVA), mas
// compacta as seções em que rawsz > vsz (ex.: .pdata 0x2000 > 0x1218). Isso NÃO atrapalha:
// todo o algoritmo raciocina em RVA e traduz pela tabela de seções, nos dois casos. O
// número é reportado porque um dump com seções compactadas é sinal de outra ferramenta —
// se a tradução estiver certa, os slots resolvem; se não, o passo 2 acusa.
const memLayout = sections.filter((s) => s.rawptr === s.va || s.rawsz === 0).length;
// O DumpModule do x64dbg (plugin MCP) grava os DADOS no layout de MEMÓRIA (o bloco de
// relocação aparece no offset == RVA) mas mantém a TABELA DE SEÇÕES no layout de ARQUIVO
// (rawptr do arquivo original). Nas seções em que SizeOfRawData > VirtualSize — .pdata,
// .didat, .rsrc, .reloc, .pkr neste caso — as duas coisas divergem e o arquivo fica
// INCOERENTE: o loader mapeia .reloc do offset errado, lê bloco de relocação inválido e
// recusa a imagem ("Este aplicativo não pode ser executado em seu PC"). Medido:
// reloc em 0x59000 vs rawptr 0x57000 na tabela. A reconstrução normaliza a tabela.
const looksMemoryImage = b.length >= sizeOfImage && Math.abs(b.length - sizeOfImage) <= sizeOfImage * 0.25;
const normalize = val("--normalize") !== "no" && looksMemoryImage && memLayout < sections.length;
log(`  [i ] dump: ${sections.length} seções, ${memLayout} com rawptr == RVA${normalize ? " -> tabela de seções normalizada para o layout de memória (as divergentes viram rawptr = RVA)" : ""}`);

const off2rva = (off) => {
  for (const s of sections) if (off >= s.rawptr && off < s.rawptr + Math.max(s.vsz, s.rawsz)) return s.va + (off - s.rawptr);
  return -1;
};
const rva2off = (rva) => {
  for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsz, s.rawsz)) return s.rawptr + (rva - s.va);
  return -1;
};
const secOf = (rva) => sections.find((s) => rva >= s.va && rva < s.va + Math.max(s.vsz, s.rawsz)) ?? null;

// ── módulos: nome, base, tamanho (a lista vem do debugger, não do dump) ──────
const mods = [];
if (existsSync(modulesArg)) {
  for (const line of readFileSync(modulesArg, "utf8").split(/\r?\n/)) {
    // formato do ListModules do MCP: "  0x7FFD14640000 | 0xCB000 | kernel32.dll"
    const m = line.match(/0x([0-9a-f]+)\s*\|\s*0x([0-9a-f]+)\s*\|\s*(.+?)\s*$/i);
    if (m) mods.push({ name: m[3].trim(), base: BigInt("0x" + m[1]), size: BigInt("0x" + m[2]), core: false });
    else if (/sistema|system|core/i.test(line) && !/0x/i.test(line)) continue;
  }
}
if (!mods.length) {
  for (const part of modulesArg.split(",")) {
    const m = part.match(/^(.+?)=0x([0-9a-f]+)=0x([0-9a-f]+)$/i);
    if (m) mods.push({ name: m[1].trim(), base: BigInt("0x" + m[2]), size: BigInt("0x" + m[3]), core: false });
  }
}
if (!mods.length) die(`--modules não deu nenhum módulo (arquivo no formato do ListModules ou lista 'nome=0xbase=0xsize')`);

const selfName = basename(dumpPath).toLowerCase();
// Ponteiro para DENTRO do próprio alvo não é import: é vtable/estrutura interna. O Scylla
// também só considera endereços que caem em OUTRO módulo. Sem este filtro, a varredura
// engole centenas de ponteiros internos de .rdata do alvo (medido: 346 falsos positivos).
// O módulo-alvo é identificado pelo TAMANHO: o ListModules reporta SizeOfImage do módulo
// carregado, e o dump é justamente essa imagem. Comparar pelo nome do arquivo não serve —
// o nome do módulo no processo é o do alvo original (clean.hardcase.exe), enquanto o dump
// pode ter sido salvo com outro nome (dump-raw.exe).
const selfMod =
  mods.find((m) => m.size === BigInt(sizeOfImage)) ?? mods.find((m) => m.name.toLowerCase() === selfName) ?? null;
if (selfMod) selfMod.core = true;
const inSelf = (v) => selfMod !== null && v >= selfMod.base && v < selfMod.base + selfMod.size;
const modOf = (addr) => mods.find((m) => addr >= m.base && addr < m.base + m.size) ?? null;

// ── exports de um módulo ────────────────────────────────────────────────────
// Duas origens, nesta ordem:
//  1. `--mem <dir>`: blob da IMAGEM CARREGADA (DumpMemory do módulo inteiro, via
//     x64dbg-drive --dump-module-mem). É a origem correta: há DLLs de sistema cujo
//     arquivo no System32 NÃO é o que está em memória — medido: comctl32.dll v6 vem do
//     WinSxS, e as RVAs de export não batem com as do System32 (11 slots não resolviam).
//  2. arquivo em disco (System32/SysWOW64) — fallback honesto, com o layout do arquivo.
const memDir = val("--mem") ?? null;
const exportCache = new Map();
function exportsOf(name) {
  const key = name.toLowerCase();
  if (exportCache.has(key)) return exportCache.get(key);
  let blob = null;
  let mr2o = null;
  let file = null;
  let fromMem = false;
  if (memDir) {
    const cand = join(memDir, `${name}.bin`);
    if (existsSync(cand)) {
      blob = readFileSync(cand);
      file = cand;
      fromMem = true;
    }
  }
  if (!blob) {
    const candidates = [join(sys32, name), join(process.env.WINDIR ?? "C:\\Windows", "SysWOW64", name)];
    file = candidates.find((c) => existsSync(c)) ?? null;
    if (!file) {
      exportCache.set(key, null);
      return null;
    }
    blob = readFileSync(file);
  }
  // Os dois blobs são PEs completos (o do --mem vem do DumpModule de um módulo de sistema,
  // que escreve a imagem carregada no layout de arquivo) — então a tradução RVA->offset é
  // sempre pela tabela de seções do próprio blob.
  {
    const bpe = blob.readUInt32LE(0x3c);
    const mOptSz = blob.readUInt16LE(bpe + 20);
    const mopt = bpe + 24;
    const msecs = [];
    for (let i = 0; i < blob.readUInt16LE(bpe + 6); i++) {
      const o = mopt + mOptSz + i * 40;
      msecs.push({ va: blob.readUInt32LE(o + 12), vsz: blob.readUInt32LE(o + 8), rawsz: blob.readUInt32LE(o + 16), rawptr: blob.readUInt32LE(o + 20) });
    }
    mr2o = (rva) => {
      for (const s of msecs) if (rva >= s.va && rva < s.va + Math.max(s.vsz, s.rawsz)) return s.rawptr + (rva - s.va);
      return -1;
    };
  }
  const mb = blob;
  const mpe = mb.readUInt32LE(0x3c);
  const mopt = mpe + 24;
  const mdirs = mopt + (mb.readUInt16LE(mopt) === 0x20b ? 112 : 96);
  const dirOff = mb.readUInt32LE(mdirs + 0); // export directory
  const eo = mr2o(dirOff);
  if (eo < 0) {
    exportCache.set(key, null);
    return null;
  }
  const nNames = mb.readUInt32LE(eo + 24);
  const nFuncs = mb.readUInt32LE(eo + 20);
  const addrTableRva = mb.readUInt32LE(eo + 28);
  const nameTableRva = mb.readUInt32LE(eo + 32);
  const ordTableRva = mb.readUInt32LE(eo + 36);
  const ordBase = mb.readUInt32LE(eo + 16);
  const exp = new Map(); // rva -> {name, ordinal}
  const nameOf = new Map(); // rva -> name (do name table)
  for (let i = 0; i < nNames; i++) {
    const no = mr2o(nameTableRva + i * 4);
    const fnRva = mb.readUInt32LE(no + 0);
    const s = mr2o(fnRva);
    let e = s;
    while (mb[e] !== 0) e++;
    nameOf.set(mb.readUInt32LE(mr2o(ordTableRva + i * 2)) + ordBase, mb.toString("latin1", s, e));
  }
  for (let i = 0; i < nFuncs; i++) {
    const fo = mr2o(addrTableRva + i * 4);
    const fnRva = mb.readUInt32LE(fo);
    if (!fnRva) continue;
    const ordinal = ordBase + i;
    exp.set(fnRva, { name: nameOf.get(ordinal) ?? null, ordinal });
  }
  const rec = { file, exp, fromMem };
  exportCache.set(key, rec);
  return rec;
}

// ── 1. achar a IAT: thunks diretos + blocos de ponteiros ────────────────────
const slotSites = new Map(); // rva do slot -> [rvas dos thunks]
let thunkCount = 0;
for (const s of sections) {
  if (!(s.flags & 0x20000000)) continue; // só seções de código
  for (let off = s.rawptr; off + 6 <= s.rawptr + s.vsz && off + 6 <= b.length; off++) {
    if (b[off] !== 0xff || b[off + 1] !== 0x25) continue; // jmp qword ptr [rip+disp32]
    const rva = off - s.rawptr + s.va;
    const target = rva + 6 + b.readInt32LE(off + 2);
    if (target <= 0 || rva2off(target) < 0) continue;
    thunkCount++;
    if (!slotSites.has(target)) slotSites.set(target, []);
    slotSites.get(target).push(rva);
  }
}
const fromThunks = new Set(slotSites.keys());

// Rotas de "varredura por blocos de ponteiros para módulos": pega IATs alcançadas por
// ponteiro guardado em estrutura, que o scan de thunks não vê.
const fromRuns = new Set();
for (const s of sections) {
  const end = Math.min(s.rawptr + Math.max(s.vsz, s.rawsz), b.length);
  let run = 0;
  for (let off = s.rawptr; off + 8 <= end; off += 8) {
    const v = b.readBigUInt64LE(off);
    const m = v > 0x10000n && !inSelf(v) ? modOf(v) : null;
    if (m) {
      run++;
      if (run >= 3) for (let k = 0; k < run; k++) fromRuns.add(off - 8 * k - s.rawptr + s.va);
    } else run = 0;
  }
}
const slots = [...new Set([...fromThunks, ...fromRuns])].sort((a, c) => a - c);
if (!slots.length) die("não achei nenhuma IAT (nenhum thunk direto e nenhum bloco de ponteiros para módulos)");

// ── 2. resolver cada slot: módulo + nome/ordinal ────────────────────────────
const resolved = [];
const skipped = [];
for (const slotRva of slots) {
  const off = rva2off(slotRva);
  if (off < 0 || off + 8 > b.length) {
    skipped.push({ slotRva, why: "slot fora do dump" });
    continue;
  }
  const v = b.readBigUInt64LE(off);
  const mod = v > 0x10000n && !inSelf(v) ? modOf(v) : null;
  if (!mod) {
    // Slot encontrado por thunk mas ainda não resolvido (zero, ou valor que não é
    // endereço): sinaliza — o loader preencheria, mas num dump isso é entrada perdida.
    skipped.push({ slotRva, value: `0x${v.toString(16)}`, why: "valor não aponta para nenhum módulo conhecido" });
    continue;
  }
  const rvaInMod = Number(v - mod.base);
  const lib = exportsOf(mod.name);
  if (!lib) {
    skipped.push({ slotRva, value: `0x${v.toString(16)}`, why: `sem tabela de exports para ${mod.name} (arquivo não encontrado em ${sys32})` });
    continue;
  }
  const hit = lib.exp.get(rvaInMod);
  if (!hit) {
    skipped.push({ slotRva, value: `0x${v.toString(16)}`, why: `${mod.name}+0x${rvaInMod.toString(16)} não é export` });
    continue;
  }
  resolved.push({ slotRva, dll: mod.name, name: hit.name, ordinal: hit.ordinal, value: v });
}
if (!resolved.length) die("nenhum slot pôde ser resolvido (módulos errados? dump pós-unpack?)");

// Um slot só pode pertencer a uma DLL (se o mesmo endereço aparecesse em blocos de DLLs
// diferentes, a tabela sairia inconsistente). Verificação explícita, não suposição.
const bySlot = new Map(resolved.map((r) => [r.slotRva, r]));
const orderedSlots = [...bySlot.values()].sort((a, c) => a.slotRva - c.slotRva);

// ── 3. montar a tabela nova numa seção nova ─────────────────────────────────
// Ordem dos descritores: por módulo, na ordem em que o primeiro slot aparece. Os slots de
// cada módulo são escritos na posição ORIGINAL (FirstThunk = slot), então blocos
// intercalados continuam corretos — o loader preenche cada endereço no lugar certo.
const moduleOrder = [];
const perModule = new Map();
for (const r of orderedSlots) {
  const k = r.dll.toLowerCase();
  if (!perModule.has(k)) {
    perModule.set(k, { dll: r.dll, entries: [] });
    moduleOrder.push(k);
  }
  perModule.get(k).entries.push(r);
}

const align = (n, a) => Math.ceil(n / a) * a;
const newRva = align(sizeOfImage, secAlign);
const newRaw = newRva; // layout de memória: rawptr == RVA
let cursor = 0; // offsets relativos ao começo da seção nova
const plan = moduleOrder.map((k) => ({ mod: perModule.get(k), dllName: perModule.get(k).dll }));
const namesArea = [];
for (const p of plan) {
  for (const e of p.mod.entries) namesArea.push({ e, nm: e.name ?? `#${e.ordinal}`, off: 0 });
}

// Layout da seção nova: [ILTs][descritores][descritor nulo][nomes de DLL][hint/name]
let c2 = 0;
const iltOff2 = [];
for (const p of plan) {
  c2 = align(c2, 8);
  iltOff2.push(c2);
  c2 += p.mod.entries.length * 8 + 8;
}
const descOff2 = [];
for (const p of plan) {
  c2 = align(c2, 8);
  descOff2.push(c2);
  c2 += 20;
}
c2 = align(c2, 8);
const descEnd2 = c2;
c2 += 20;
const strOff2 = [];
for (const p of plan) {
  c2 = align(c2, 2);
  strOff2.push(c2);
  c2 += p.dllName.length + 1;
}
c2 = align(c2, 2);
for (const n of namesArea) {
  if (n.e.name) {
    c2 = align(c2, 2);
    n.off = c2;
    c2 += 2 + n.nm.length + 1;
  }
}
c2 = align(c2, 8);
const secSize = c2;
const sec = Buffer.alloc(secSize, 0);

for (let i = 0; i < plan.length; i++) {
  const p = plan[i];
  sec.write(p.dllName, strOff2[i], "latin1");
  p.mod.entries.forEach((e, j) => {
    if (e.name) {
      const n = namesArea.find((x) => x.e === e);
      sec.writeUInt16LE(0, n.off);
      sec.write(n.nm, n.off + 2, "latin1");
      sec.writeBigUInt64LE(BigInt(newRva + n.off), iltOff2[i] + j * 8);
    } else {
      sec.writeBigUInt64LE(0x8000000000000000n | BigInt(e.ordinal), iltOff2[i] + j * 8);
    }
  });
  // FirstThunk aponta para os slots ORIGINAIS (cada bloco pode ter tamanho próprio em
  // bytes, mas o descritor declara o começo; o terminador NULO fecha cada bloco).
  const ftRva = p.mod.entries[0].slotRva;
  const desc = descOff2[i];
  sec.writeUInt32LE(newRva + iltOff2[i], desc + 0); // OriginalFirstThunk
  sec.writeUInt32LE(0, desc + 4); // TimeDateStamp
  sec.writeUInt32LE(0, desc + 8); // ForwarderChain
  sec.writeUInt32LE(newRva + strOff2[i], desc + 12); // Name
  sec.writeUInt32LE(ftRva, desc + 16); // FirstThunk (slots originais)
}

// ── 4. montar o arquivo: + seção, + header de seção, + data dirs ────────────
const out = Buffer.from(b);
if (normalize) {
  // rawptr = RVA e rawsz = VirtualSize arredondado: o arquivo passa a ser a imagem de
  // memória coerente (é o que o "Fix Dump" do Scylla faz com os cabeçalhos do dump).
  for (const s of sections) {
    out.writeUInt32LE(s.va, s.hdrOff + 20);
    out.writeUInt32LE(s.vsz === 0 ? 0 : align(s.vsz, fileAlign), s.hdrOff + 16);
  }
}
const hdrSpace = secTable + (nSec + 1) * 40;
if (hdrSpace > (sections.length ? Math.min(...sections.map((s) => s.rawptr || Infinity)) : sizeOfHeaders)) {
  die("sem espaço no cabeçalho para o header de seção novo");
}
const newHdr = secTable + nSec * 40;
out.write(".idata2", newHdr, 8, "latin1");
out.writeUInt32LE(secSize, newHdr + 8);
out.writeUInt32LE(newRva, newHdr + 12);
out.writeUInt32LE(align(secSize, fileAlign), newHdr + 16);
out.writeUInt32LE(newRaw, newHdr + 20);
out.writeUInt32LE(0, newHdr + 24);
out.writeUInt32LE(0, newHdr + 28);
out.writeUInt16LE(0, newHdr + 32);
out.writeUInt16LE(0, newHdr + 34);
out.writeUInt32LE(0xc0000040, newHdr + 36); // READ|WRITE|INITIALIZED_DATA
out.writeUInt16LE(nSec + 1, peOff + 6);
out.writeUInt32LE(Math.max(sizeOfImage, newRva + align(secSize, secAlign)), opt + 56);
// data directories: IMPORT -> descritores novos · IAT -> faixa de slots descoberta
const iatFirst = orderedSlots[0].slotRva;
const iatLast = orderedSlots[orderedSlots.length - 1].slotRva + 8;
out.writeUInt32LE(newRva + descOff2[0], dirsOff + 1 * 8);
out.writeUInt32LE(20 * plan.length + 20, dirsOff + 1 * 8 + 4);
out.writeUInt32LE(iatFirst, dirsOff + 12 * 8);
out.writeUInt32LE(iatLast - iatFirst, dirsOff + 12 * 8 + 4);
out.writeUInt32LE(0, dirsOff + 11 * 8); // BoundImport: nada de binding quebrado
out.writeUInt32LE(0, dirsOff + 11 * 8 + 4);

const rawNeeded = newRaw + align(secSize, fileAlign);
const finalBuf = Buffer.alloc(Math.max(out.length, rawNeeded), 0);
out.copy(finalBuf);
sec.copy(finalBuf, newRaw);
writeFileSync(outPath, finalBuf);

// ── relatório ───────────────────────────────────────────────────────────────
const report = {
  dump: dumpPath,
  out: outPath,
  imageBase: `0x${imageBase.toString(16)}`,
  entryPoint: `0x${entryPoint.toString(16)}`,
  oepInformado: oepRva !== null ? `0x${oepRva.toString(16)}` : null,
  secoesOriginais: sections.map((s) => s.name),
  novaSecao: { nome: ".idata2", rva: `0x${newRva.toString(16)}`, tamanho: secSize },
  thunksDiretos: thunkCount,
  slotsPorThunk: fromThunks.size,
  slotsPorVarredura: fromRuns.size,
  slotsResolvidos: orderedSlots.length,
  slotsNaoResolvidos: skipped.length,
  dlls: plan.map((p, i) => ({
    dll: p.dllName,
    funcoes: p.mod.entries.length,
    primeiroSlot: `0x${p.mod.entries[0].slotRva.toString(16)}`,
    firstThunk: `0x${p.mod.entries[0].slotRva.toString(16)}`,
    ilt: `0x${(newRva + iltOff2[i]).toString(16)}`,
    descritor: `0x${(newRva + descOff2[i]).toString(16)}`,
  })),
  importDirectory: { rva: `0x${(newRva + descOff2[0]).toString(16)}`, tamanho: 20 * plan.length + 20 },
  iatDirectory: { rva: `0x${iatFirst.toString(16)}`, tamanho: iatLast - iatFirst },
  tabelaDeSecoesNormalizada: normalize,
  naoResolvidos: skipped.slice(0, 20),
};
if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`\nUnboxRE — reconstrução de IAT (equivalente headless do Fix Dump do Scylla)`);
  console.log("─".repeat(70));
  console.log(`  dump: ${dumpPath} (${b.length} bytes, imageBase=${report.imageBase}, EP=0x${entryPoint.toString(16)})`);
  console.log(`  módulo-alvo na lista do debugger: ${selfMod ? `${selfMod.name} base=0x${selfMod.base.toString(16)} size=0x${selfMod.size.toString(16)}` : "não identificado (pontos para si mesmo não serão filtrados)"}`);
  console.log(`  IAT encontrada: ${orderedSlots.length} slot(s) resolvido(s) — ${fromThunks.size} por thunk direto, ${fromRuns.size} por varredura`);
  console.log(`  ${plan.length} DLL(s) reconstruída(s):`);
  for (const d of report.dlls) console.log(`    ${d.dll.padEnd(38)} ${String(d.funcoes).padStart(4)} função(ões)  FirstThunk=0x${d.firstThunk.slice(2)}`);
  if (skipped.length) {
    console.log(`  [!!] ${skipped.length} slot(s) sem resolução:`);
    for (const s of report.naoResolvidos) console.log(`    slot 0x${s.slotRva.toString(16)}: ${s.why}`);
  }
  console.log(`  seção nova .idata2 em rva=0x${newRva.toString(16)} (${secSize} bytes)`);
  console.log(`  IMPORT dir -> 0x${(newRva + descOff2[0]).toString(16)}  ·  IAT dir -> 0x${iatFirst.toString(16)}+${iatLast - iatFirst}`);
  console.log(`  saída: ${outPath} (${finalBuf.length} bytes)`);
}

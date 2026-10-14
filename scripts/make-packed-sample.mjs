#!/usr/bin/env node
/**
 * make-packed-sample.mjs — gera um "caso controlado" de packer SEM caminho de restore.
 *
 * Por que existe
 * --------------
 * O caso UPX (reports/unpack-iat-upx-case.md) tem volta fácil: `upx -d` restaura o
 * arquivo original. Isso não exercita a parte difícil do fluxo de unpack — achar o OEP,
 * dumpar a memória e RECONSTRUIR A IAT. Para exercitar isso não havia alvo: os protótipos
 * VMProtect/Themida DEMO não carregam nesta máquina
 * (reports/root-cause-0xc000007b.md) e um protetor comercial não é reproduzível em CI.
 *
 * Este script FABRICA o alvo que faltava, a partir de um binário que roda, com as
 * propriedades que tornam o caminho "duro" inevitável:
 *
 *   1. a seção de código vai XOR'd no arquivo (análise estática vê lixo);
 *   2. a tabela de imports ORIGINAL é apagada do arquivo (descritores zerados) e o data
 *      directory IMPORT passa a apontar só para a tabela mínima do stub (kernel32);
 *   3. o entrypoint aponta para o stub, que em runtime: descriptografa o código,
 *      restaura a IAT ORIGINAL chamando LoadLibraryA/GetProcAddress e salta para o OEP.
 *
 * O que NÃO é restaurado (de propósito): os DESCRITORES de import do alvo. Em memória, no
 * OEP, existe uma IAT cheia de ponteiros resolvidos e nenhum descritor — exatamente a
 * situação em que um dump "cru" é inútil e é preciso reconstruir a tabela (Scylla, ou o
 * `scripts/rebuild-iat.mjs` desta mesma rodada).
 *
 * O stub não é escrito em hex na mão: ele é assembly x64 em `scripts/lib/pkr-stub.rs`,
 * montado pelo rustc (`--emit=obj`, sem link) e copiado byte a byte por este script. O
 * blob é posição-independente e SEM relocações (todas as referências são intra-seção),
 * então a cópia é literal — o `--dump-stub` prova isso imprimindo a seção do objeto.
 *
 * Uso:
 *   node scripts/make-packed-sample.mjs <alvo.exe> -o <saida.exe> [--run] [--json]
 *        [--key1 N] [--key2 N] [--stub <pkr-stub.obj>] [--dump-stub] [--force]
 *
 * Exit: 0 empacotado (e, com --run, o alvo empacotado rodou com exit 0) · 1 o alvo
 *       empacotado NÃO rodou · 2 pré-condição recusada / erro de uso. Nunca usa sudo.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);

if (has("--help") || has("-h") || argv.length === 0) {
  console.log("uso: node scripts/make-packed-sample.mjs <alvo.exe> -o <saida.exe> [--run] [--json]");
  console.log("  --key1 N     chave do XOR da seção de código (default: derivada do hash do alvo)");
  console.log("  --key2 N     chave do XOR do plano de imports (idem)");
  console.log("  --stub PATH  objeto do stub (default: <tmp>/pkr-stub.obj, construído com rustc)");
  console.log("  --build-only força reconstruir o stub, mesmo se o objeto já existir");
  console.log("  --dump-stub  imprime o layout do objeto COFF do stub (símbolos/relocações)");
  console.log("  --run        executa o alvo empacotado e exige exit 0");
  console.log("  --no-encrypt  variante de diagnóstico: NÃO cifra a seção de código");
  console.log("  --no-imports  variante de diagnóstico: NÃO mexe na tabela de imports do alvo");
  console.log("  --no-ep-jump  variante de diagnóstico: NÃO patcheia o EP (o stub fica inalcançável)");
  console.log("  --force      empacota mesmo se o alvo já parecer empacotado");
  process.exit(argv.length === 0 ? 2 : 0);
}

const JSON_OUT = has("--json");
const RUN = has("--run");
const FORCE = has("--force");
// Variantes de diagnóstico: servem para separar "o stub quebrou" de "a cirurgia no PE
// quebrou". Com --no-encrypt o stub não descriptografa nada; com --no-imports ele não
// toca na IAT (o loader resolve tudo como num binário normal).
const NO_ENCRYPT = has("--no-encrypt");
const NO_IMPORTS = has("--no-imports");
const NO_EP_JUMP = has("--no-ep-jump");
const NO_RESTORE_EP = has("--no-restore-ep"); // diagnóstico: não devolve os bytes do EP
const DUMP_STUB = has("--dump-stub");
const target = argv.find((a) => !a.startsWith("--") && a !== val("--stub") && a !== val("-o") && a !== val("--key1") && a !== val("--key2"));
const out = val("-o");
if (!target || !out) {
  console.error("faltou o alvo ou o -o <saida.exe>");
  process.exit(2);
}

const notes = [];
const step = (m) => notes.push(m);
const die = (m) => {
  console.error(`[!!] ${m}`);
  process.exit(2);
};

// ────────────────────────────────────────────────────────────────────────────
//  PE: leitura do alvo (mesmo estilo de scripts/diagnose-load.mjs — sem dependência)
// ────────────────────────────────────────────────────────────────────────────
const buf = readFileSync(target);
if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) die(`${target}: sem assinatura MZ`);
const u16 = (b, o) => b.readUInt16LE(o);
const u32 = (b, o) => b.readUInt32LE(o);
const peOff = u32(buf, 0x3c);
if (u32(buf, peOff) !== 0x00004550) die(`${target}: assinatura PE ausente`);
const machine = u16(buf, peOff + 4);
if (machine !== 0x8664) die(`${target}: machine=0x${machine.toString(16)} — este packer só faz x64 (0x8664)`);
const is64 = u16(buf, peOff + 24) === 0x20b;
const opt = peOff + 24;
const nSec = u16(buf, peOff + 6);
const sizeOfHeaders = u32(buf, opt + 60);
const optSize = u16(buf, peOff + 20);
const dirsOff = opt + (is64 ? 112 : 96);
const secOff = opt + optSize;
const fileAlign = u32(buf, opt + 36);
const sectAlign = u32(buf, opt + 32);
const sizeOfImage = u32(buf, opt + 56);
const sizeOfCode = u32(buf, opt + 4);
const sizeOfInitData = u32(buf, opt + 8);
const epRva = u32(buf, opt + 16);
const dllChar = u16(buf, opt + 70);

if (u32(buf, dirsOff + 14 * 8)) die(`${target}: tem cabeçalho CLR (.NET) — fora do escopo deste packer`);
if (sizeOfHeaders - secOff < 40) die(`${target}: não há espaço para um novo cabeçalho de seção (SizeOfHeaders=${sizeOfHeaders})`);
if (fileAlign < 0x200 || (fileAlign & (fileAlign - 1)) !== 0) die(`${target}: FileAlignment inválido (0x${fileAlign.toString(16)})`);

const DIRNAME = ["export", "import", "resource", "exception", "security", "basereloc", "debug", "arch", "globalptr", "tls", "loadconfig", "boundimport", "iat", "delayimport", "clr"];
const sections = [];
for (let i = 0; i < nSec; i++) {
  const o = secOff + i * 40;
  sections.push({
    index: i,
    name: buf.toString("latin1", o, o + 8).replace(/\0+$/, ""),
    headerOff: o,
    virtualSize: u32(buf, o + 8),
    virtualAddress: u32(buf, o + 12),
    sizeRaw: u32(buf, o + 16),
    ptrRaw: u32(buf, o + 20),
    characteristics: u32(buf, o + 36),
  });
}
const span = (s) => Math.max(s.virtualSize, s.sizeRaw);
const secOf = (rva) => sections.find((s) => rva >= s.virtualAddress && rva < s.virtualAddress + span(s));
const rva2off = (rva) => {
  const s = secOf(rva);
  if (!s) return -1;
  const off = s.ptrRaw + (rva - s.virtualAddress);
  return off >= 0 && off < buf.length ? off : -1;
};
const align = (n, a) => (n + a - 1) & ~(a - 1);

// ── pré-condições: o que este packer exige do alvo ──────────────────────────
const codeSec = secOf(epRva);
if (!codeSec) die(`${target}: o entrypoint (rva=0x${epRva.toString(16)}) não cai em nenhuma seção`);
if (codeSec.sizeRaw === 0) die(`${target}: a seção do entrypoint (${codeSec.name}) não tem dados no arquivo`);

// TLS callbacks rodam no loader ANTES do entrypoint — sobre código ainda cifrado. Recusa.
const tlsRva = u32(buf, dirsOff + 9 * 8);
if (tlsRva) {
  const tlsOff = rva2off(tlsRva);
  let callbacks = 0;
  if (tlsOff >= 0) {
    const cbRva = u32(buf, tlsOff + 24); // IMAGE_TLS_DIRECTORY64.AddressOfCallBacks
    let p = cbRva ? rva2off(cbRva) : -1;
    while (p >= 0 && p + 8 <= buf.length && u32(buf, p) !== 0) { callbacks++; p += 8; }
  }
  if (callbacks > 0) die(`${target}: tem ${callbacks} TLS callback(s) — o loader os executaria sobre o código cifrado`);
  step("TLS: diretório presente mas sem callbacks — ok");
}

// Ordinais: o plano do stub é por NOME. Ordinal exigiria outro caminho no asm.
const impRva = u32(buf, dirsOff + 1 * 8);
const impSize = u32(buf, dirsOff + 1 * 8 + 4);
if (!impRva || !impSize) die(`${target}: sem tabela de imports — não há o que destruir nem o que restaurar`);

const imports = []; // [{dll, funcs:[...]}]
let iatFirst = 0; // faixa contínua mínima que cobre a IAT original (para liberar escrita)
let iatLast = 0;
{
  let off = rva2off(impRva);
  if (off < 0) die(`${target}: o data directory IMPORT não é legível no arquivo`);
  let ordinals = 0;
  for (;;) {
    // A ILT (OriginalFirstThunk) é a tabela de nomes; a IAT (FirstThunk) pode estar
    // pré-preenchida com endereços por causa de binding, então ela não serve para ler nomes.
    const iltRva = u32(buf, off + 0);
    const firstThunk = u32(buf, off + 16);
    const nameRva = u32(buf, off + 12);
    if (!iltRva && !firstThunk && !nameRva) break;
    const nameOff = rva2off(nameRva);
    if (nameOff < 0) die(`${target}: nome de DLL inválido no descritor de import`);
    let end = nameOff;
    while (buf[end] !== 0 && end < buf.length) end++;
    const dll = buf.toString("latin1", nameOff, end);
    const funcs = [];
    let t = rva2off(iltRva || firstThunk);
    if (t < 0) die(`${target}: ILT de ${dll} não é legível`);
    for (;;) {
      // PE32+ tem thunks de 8 BYTES: ler 4 pegaria a metade errada e o bit de ordinal
      // (bit 63) passaria batido — foi exatamente o bug que fez o parse morrer numa DLL.
      const thunk = buf.readBigUInt64LE(t);
      if (thunk === 0n) break;
      if (thunk & 0x8000000000000000n) {
        ordinals++;
        funcs.push(`#${(thunk & 0xffffn).toString()}`);
      } else {
        const no = rva2off(Number(thunk & 0xffffffffn));
        if (no < 0) die(`${target}: entrada de ${dll} com RVA inválido`);
        const fend = no + 2;
        let q = fend;
        while (buf[q] !== 0 && q < buf.length) q++;
        funcs.push(buf.toString("latin1", fend, q));
      }
      t += 8;
    }
    imports.push({ dll, funcs, descOff: off, iltRva, firstThunk });
    off += 20;
    if (imports.length > 200) die(`${target}: tabela de imports suspeita (>200 DLLs)`);
  }
  const total = imports.reduce((a, i) => a + i.funcs.length, 0);
  const ordCount = imports.reduce((a, i) => a + i.funcs.filter((f) => f.startsWith("#")).length, 0);
  step(`pré-condições: x64, ${sections.length} seções, ${imports.length} DLLs / ${total} funções (${ordCount} por ordinal), sem TLS callbacks`);

  // A IAT NÃO é contígua nesta imagem (o linker alinha cada bloco) — por isso o plano
  // carrega a RVA da IAT de cada DLL e o stub reposiciona o cursor antes de cada bloco.
  // Medir isso aqui é o que evita "andar de 8 em 8" e corromper a tabela.
  let expect = Number(imports[0].firstThunk);
  let gaps = 0;
  for (const imp of imports) {
    const ft = Number(imp.firstThunk);
    if (ft !== expect) gaps++;
    expect = ft + imp.funcs.length * 8;
  }
  if (imports.length > 128) die(`${target}: ${imports.length} DLLs > 128 (a tabela de IAT do stub tem 512 bytes)`);
  // A faixa que precisa de permissão de escrita em runtime: da IAT mais baixa até o fim
  // da mais alta. Sem isso o stub escreve em .rdata (somente leitura) e o alvo morre
  // com 0xC0000005 — foi medido antes desta correção.
  iatFirst = Math.min(...imports.map((i) => Number(i.firstThunk)));
  iatLast = Math.max(...imports.map((i) => Number(i.firstThunk) + i.funcs.length * 8));
  step(`IAT por DLL (${gaps ? `${gaps} bloco(s) com alinhamento — o plano carrega a RVA de cada IAT` : "blocos contíguos"})`);
}

// Relocações: a seção cifrada NÃO pode ser alvo delas (o loader relocaria bytes cifrados).
{
  const relRva = u32(buf, dirsOff + 5 * 8), relSize = u32(buf, dirsOff + 5 * 8 + 4);
  if (relRva && relSize) {
    const base = rva2off(relRva);
    let p = base, end = base + relSize, bad = 0;
    while (p >= 0 && p + 8 <= end && p + 8 <= buf.length) {
      const pageRva = u32(buf, p), blockSize = u32(buf, p + 4);
      if (blockSize < 8) break;
      for (let i = 0; i + 1 < (blockSize - 8) / 2; i++) {
        const e = u16(buf, p + 8 + i * 2);
        if (!(e >> 12)) continue;
        if (secOf(pageRva + (e & 0xfff)) === codeSec) bad++;
      }
      p += blockSize;
    }
    if (bad) die(`${target}: ${bad} relocação(ões) apontam para "${codeSec.name}" — cifrar essa seção corromperia o delta do loader`);
    step(`relocações: nenhuma em "${codeSec.name}" — cifrar a seção é seguro`);
  } else {
    step("relocações: nenhuma (imagem sem ASLR)");
  }
}

// ────────────────────────────────────────────────────────────────────────────
//  Stub: objeto COFF -> blob posição-independente
// ────────────────────────────────────────────────────────────────────────────
const stubDir = join(tmpdir(), "unboxre-pkr");
const stubObj = val("--stub", join(stubDir, "pkr-stub.obj"));
function buildStub() {
  mkdirSync(stubDir, { recursive: true });
  const src = join(ROOT, "scripts", "lib", "pkr-stub.rs");
  if (!existsSync(src)) die(`não achei ${src}`);
  const r = spawnSync("rustc", ["--crate-type=lib", "--emit=obj", "-C", "panic=abort", "--target", "x86_64-pc-windows-msvc", "-o", stubObj, src], { encoding: "utf8" });
  if (r.error) die(`rustc não disponível: ${r.error.code} (instale o Rust: winget install Rustlang.Rustup)`);
  if (r.status !== 0) die(`rustc falhou:\n${r.stdout}${r.stderr}`);
  const warn = (r.stderr || "").split(/\r?\n/).filter((l) => l.includes("warning") || l.includes("error")).length;
  step(`stub: montado com rustc (${basename(src)} -> ${stubObj}${warn ? `, ${warn} aviso(s)` : ""})`);
}
// Reconstrói se o objeto não existe, se pedido, ou se o FONTE é mais novo: um objeto
// velho aqui faz o packer montar um stub sem as últimas correções — silenciosamente.
const stubSrc = join(ROOT, "scripts", "lib", "pkr-stub.rs");
const stale = existsSync(stubSrc) && existsSync(stubObj) && statSync(stubSrc).mtimeMs > statSync(stubObj).mtimeMs;
if (!existsSync(stubObj) || has("--build-only") || stale) buildStub();

/** Lê só o necessário de um objeto COFF: seções, símbolos e relocações. */
function readCoff(b) {
  const nsec = u16(b, 2);
  const symPtr = u32(b, 8);
  const nsym = u32(b, 12);
  const secs = [];
  for (let i = 0; i < nsec; i++) {
    const o = 20 + i * 40;
    secs.push({
      i: i + 1,
      name: b.toString("latin1", o, o + 8).replace(/\0+$/, ""),
      size: u32(b, o + 16),
      ptrRaw: u32(b, o + 20),
      ptrReloc: u32(b, o + 24),
      nReloc: u16(b, o + 32),
      characteristics: u32(b, o + 36),
    });
  }
  const syms = [];
  for (let i = 0; i < nsym; i++) {
    const o = symPtr + i * 18;
    if (o + 18 > b.length) break;
    const raw = b.toString("latin1", o, o + 8).replace(/\0+$/, "");
    const strOff = u32(b, o + 4);
    const name = !raw && strOff ? b.toString("latin1", u32(b, 0) + strOff).replace(/\0.*$/, "") : raw;
    syms.push({ name, value: u32(b, o + 8), section: u16(b, o + 12), aux: b[o + 17] });
    i += b[o + 17]; // registros auxiliares não têm nome: pular evita nomes-lixo no dump
  }
  for (const s of secs) {
    s.relocs = [];
    for (let i = 0; i < s.nReloc; i++) {
      const o = s.ptrReloc + i * 10;
      s.relocs.push({ va: u32(b, o), sym: u32(b, o + 4), type: u16(b, o + 8) });
    }
  }
  return { secs, syms };
}

const coff = readCoff(readFileSync(stubObj));
// A seção do stub é achada pelo SÍMBOLO `pkr_stub` (não por nome nem por "a primeira"):
// o rustc emite .text/.data/.bss vazios e um `.pkrstub` — escolher pelo nome errado
// foi o que fez o packer ler uma seção de tamanho 0.
const stubSym = coff.syms.find((s) => s.name === "pkr_stub" && s.section > 0);
const codeObjSec =
  (stubSym && coff.secs.find((s) => s.i === stubSym.section)) ??
  coff.secs.find((s) => s.name === ".pkrstub") ??
  coff.secs.reduce((a, s) => (s.size > (a?.size ?? 0) ? s : a), null);
if (!codeObjSec || !codeObjSec.size) die(`${stubObj}: não achei uma seção com o stub (o objeto foi montado a partir de scripts/lib/pkr-stub.rs?)`);
const blob = Buffer.from(readFileSync(stubObj).subarray(codeObjSec.ptrRaw, codeObjSec.ptrRaw + codeObjSec.size));

if (DUMP_STUB) {
  console.log(`objeto: ${stubObj}`);
  for (const s of coff.secs) console.log(`  seção ${s.name.padEnd(10)} size=0x${s.size.toString(16)} relocs=${s.nReloc} chars=0x${s.characteristics.toString(16)}`);
  for (const s of coff.syms.filter((x) => x.section === codeObjSec.i)) console.log(`  símbolo ${s.name.padEnd(14)} +0x${s.value.toString(16)}`);
  for (const r of codeObjSec.relocs) console.log(`  reloc @0x${r.va.toString(16)} tipo=0x${r.type.toString(16)} sym=${coff.syms[r.sym]?.name ?? r.sym}`);
  if (!codeObjSec.relocs.length) console.log("  relocações: nenhuma — o blob é copiado byte a byte (posição-independente)");
}

// A config e a IAT do stub são encontradas por MARCADOR, não por offset fixo: se o
// assembly mudar de tamanho, o packer continua correto.
const MAGIC = Buffer.from("PKRCFG01", "latin1");
const cfgOff = blob.indexOf(MAGIC);
if (cfgOff < 0) die("o blob do stub não contém a magic PKRCFG01 — objeto errado?");
const symOff = (name, fallback) => {
  const s = coff.syms.find((x) => x.name === name && x.section === codeObjSec.i);
  return s ? s.value : fallback;
};
const iatOff = symOff("pkr_iat", cfgOff - 48);
const stubOff = symOff("pkr_stub", 0);
step(`stub: blob de ${blob.length} bytes, iat@+0x${iatOff.toString(16)}, cfg@+0x${cfgOff.toString(16)}`);

// ────────────────────────────────────────────────────────────────────────────
//  Cirurgia no PE
// ────────────────────────────────────────────────────────────────────────────
const key1 = (Number(val("--key1", 0)) || (u32(buf, peOff + 8) >>> 24) || 0x9e) & 0xff;
const key2 = (Number(val("--key2", 0)) || (u32(buf, peOff + 8) >>> 16) || 0x5a) & 0xff;

/** XOR com fluxo de chave incremental — o mesmo que o stub faz em asm. */
function xorStream(dst, start, size, key, inc) {
  let k = key & 0xff;
  for (let i = 0; i < size; i++) {
    dst[start + i] ^= k;
    k = (k + inc) & 0xff;
  }
}

const pkrRva = align(sizeOfImage, sectAlign);
const fileEnd = sections.reduce((a, s) => Math.max(a, s.ptrRaw + s.sizeRaw), 0);
const pkrRawPtr = align(Math.max(fileEnd, sizeOfHeaders), fileAlign);

// 1. monta o conteúdo de .pkr: [blob do stub][descritor+nomos do stub][plano de imports]
const pkr = Buffer.alloc(align(blob.length, 8));
blob.copy(pkr, 0);

const stubIatRva = pkrRva + iatOff;
const names = ["LoadLibraryA", "GetProcAddress", "VirtualProtect"];
const extra = []; // pedaços depois do blob, com o RVA calculado no fim
let cursor = pkr.length;

// nome da DLL do stub + entradas hint/name (o packer aponta a IAT para elas)
const dllName = "kernel32.dll";
const dllNameOff = cursor;
cursor += align(dllName.length + 1, 2);
const nameEntryOffs = [];
for (const n of names) {
  nameEntryOffs.push(cursor);
  cursor += align(2 + n.length + 1, 2);
}
const descOff = align(cursor, 8);
cursor = descOff + 40; // descritor + terminador nulo
const planOff = align(cursor, 8);

// Formato do plano (contrato do stub, ver o cabeçalho de pkr-stub.rs): cada DLL é
// `NOME\0` + `fn\0` por função + um `\0` EXTRA que fecha o bloco, e o plano termina com
// um nome de DLL vazio. Sem o `\0` extra o stub lê o nome da DLL SEGUINTE como se fosse
// função da DLL atual: GetProcAddress devolve NULL (gravado na IAT) e todas as DLLs
// seguintes deslocam uma entrada — medido: o alvo morria com 0xC0000005 no OEP.
const planStr = imports.map((i) => `${i.dll}\0${i.funcs.map((f) => `${f}\0`).join("")}\0`).join("") + "\0";
const iatTabOff = symOff("pkr_iattab", cfgOff + 64);
const planBuf = Buffer.from(planStr, "latin1");
cursor = planOff + planBuf.length;

const pkrFull = Buffer.alloc(align(cursor, 16));
pkr.copy(pkrFull, 0);

// strings do stub
pkrFull.write(dllName, dllNameOff, "latin1");
nameEntryOffs.forEach((off, i) => {
  pkrFull.writeUInt16LE(0, off);
  pkrFull.write(names[i], off + 2, "latin1");
});
// descritor do stub (20 bytes) + terminador (20 bytes zerados)
const impDesc = { rva: pkrRva + descOff };
pkrFull.writeUInt32LE(stubIatRva, descOff + 0); // OriginalFirstThunk == FirstThunk: uma única
// array (o formato que o loader aceita sem ILT separada)
pkrFull.writeUInt32LE(0, descOff + 4);
pkrFull.writeUInt32LE(0, descOff + 8);
pkrFull.writeUInt32LE(pkrRva + dllNameOff, descOff + 12);
pkrFull.writeUInt32LE(stubIatRva, descOff + 16);
// IAT do stub pré-preenchida com as RVAs das entradas hint/name (a ordem casa com o asm)
nameEntryOffs.forEach((off, i) => pkrFull.writeUInt32LE(pkrRva + off, iatOff + i * 8));
pkrFull.writeUInt32LE(0, iatOff + 3 * 8);
// plano de imports (cifrado com key2 — o stub descriptografa no lugar)
planBuf.copy(pkrFull, planOff);
xorStream(pkrFull, planOff, planBuf.length, key2, 0x3d);

if (DUMP_STUB) {
  console.log(`  .pkr: blob=${blob.length} iat@0x${iatOff.toString(16)} cfg@0x${cfgOff.toString(16)} iattab@0x${iatTabOff.toString(16)}`);
  console.log(`        dllName@0x${dllNameOff.toString(16)} desc@0x${descOff.toString(16)} plan@0x${planOff.toString(16)} total=${pkrFull.length}`);
  console.log(`  pkrFull[0x370..0x3a0]: ${pkrFull.subarray(0x370, 0x3a0).toString("hex")}`);
  console.log(`  pkrFull[0x140..0x160]: ${pkrFull.subarray(0x140, 0x160).toString("hex")}`);
}

// config do stub (key1 é escrita no fim, quando o layout do arquivo já está fechado)

// 2. cifra a seção de código NO ARQUIVO (cópia do alvo). Os 8 bytes ORIGINAIS do EP
//    saem da imagem LIMPA, antes de qualquer cifragem — é o que o stub devolve no fim.
const outBuf = Buffer.from(buf);
const epOff = rva2off(epRva);
if (epOff < 0) die(`${target}: EP não é gravável no arquivo`);
const oepOrig8 = Buffer.from(buf.subarray(epOff, epOff + 8));
if (oepOrig8.length < 8) die(`${target}: EP a menos de 8 bytes do fim do arquivo`);
if (!NO_ENCRYPT) xorStream(outBuf, codeSec.ptrRaw, codeSec.sizeRaw, key1, 0x5b);

// 2b. o EP CONTINUA sendo a RVA original — só que apontando para um `jmp` de 5 bytes ao
//     stub. Isso não é cosmético: com GUARD_CF ligado o loader valida o EP contra a
//     GuardCFFunctionTable, e um EP numa seção nova morre com 0xC0000409 (medido nas
//     quatro variantes antes desta mudança). O EP original JÁ é um alvo válido da tabela.
if (!NO_EP_JUMP) {
  const rel = (pkrRva + stubOff) - (epRva + 5);
  outBuf.writeUInt8(0xe9, epOff); // jmp rel32
  outBuf.writeInt32LE(rel, epOff + 1);
  outBuf.writeUInt8(0x90, epOff + 5);
  outBuf.writeUInt8(0x90, epOff + 6);
  outBuf.writeUInt8(0x90, epOff + 7);
}

if (!NO_IMPORTS) {
  // 3. apaga os DESCRITORES de import originais: em memória não vai existir tabela
  for (const imp of imports) outBuf.fill(0, imp.descOff, imp.descOff + 20);

  // 4. data directories: IMPORT/IAT apontam só para o stub
  outBuf.writeUInt32LE(impDesc.rva, dirsOff + 1 * 8);
  outBuf.writeUInt32LE(40, dirsOff + 1 * 8 + 4);
  outBuf.writeUInt32LE(stubIatRva, dirsOff + 12 * 8);
  outBuf.writeUInt32LE(32, dirsOff + 12 * 8 + 4);
  outBuf.writeUInt32LE(0, dirsOff + 11 * 8); // BOUND_IMPORT
  outBuf.writeUInt32LE(0, dirsOff + 11 * 8 + 4);
} else {
  step("variante --no-imports: a tabela de imports fica intacta e o stub não toca na IAT");
}

// 5. novo cabeçalho de seção + headers
const newHdr = secOff + nSec * 40;
const pkrCh = (0x60000020 | 0x80000000) >>> 0; // CODE|EXECUTE|READ|WRITE (o | em JS é signed 32-bit)
outBuf.write(".pkr", newHdr, 8, "latin1");
outBuf.writeUInt32LE(pkrFull.length, newHdr + 8);
outBuf.writeUInt32LE(pkrRva, newHdr + 12);
outBuf.writeUInt32LE(align(pkrFull.length, fileAlign), newHdr + 16);
outBuf.writeUInt32LE(pkrRawPtr, newHdr + 20);
outBuf.writeUInt32LE(0, newHdr + 24);
outBuf.writeUInt32LE(0, newHdr + 32);
outBuf.writeUInt32LE(pkrCh, newHdr + 36);

outBuf.writeUInt16LE(nSec + 1, peOff + 6);
outBuf.writeUInt32LE(pkrRva + align(pkrFull.length, sectAlign), opt + 56); // SizeOfImage
outBuf.writeUInt32LE(sizeOfCode, opt + 4);
outBuf.writeUInt32LE(sizeOfInitData + align(pkrFull.length, sectAlign), opt + 8);

// 6. escreve .pkr no fim do arquivo (com o padding de FileAlignment)
const finalBuf = Buffer.concat([outBuf.subarray(0, Math.max(pkrRawPtr, outBuf.length)), Buffer.alloc(Math.max(0, pkrRawPtr - outBuf.length)), pkrFull, Buffer.alloc(align(pkrFull.length, fileAlign) - pkrFull.length)]);
// O EP do cabeçalho permanece o ORIGINAL (alvo válido de CFG); o `jmp` gravado lá é
// que leva ao stub. Reescrever aqui seria justamente o erro que gerava 0xC0000409.
if (u32(finalBuf, opt + 16) !== epRva) die("EP do cabeçalho mudou — o patch do EP não deveria alterar a RVA");

// 7. o arquivo de saída É cifrado (a chave mora no blob: isto é um caso de estudo — o
//    objetivo é o caminho de unpack, não a resistência a análise).
const pkrCfgInFile = pkrRawPtr + cfgOff;
finalBuf.writeUInt32LE(key1, pkrCfgInFile + 8);
finalBuf.writeUInt32LE(key2, pkrCfgInFile + 12);
finalBuf.writeUInt32LE(codeSec.virtualAddress, pkrCfgInFile + 16);
finalBuf.writeUInt32LE(codeSec.sizeRaw, pkrCfgInFile + 20); // faixa a PROTEGER (VirtualProtect)
finalBuf.writeUInt32LE(NO_ENCRYPT ? 0 : codeSec.sizeRaw, pkrCfgInFile + 56); // encSize: 0 = não descriptografar
finalBuf.writeUInt32LE(epRva, pkrCfgInFile + 24);
finalBuf.writeUInt32LE(pkrRva + planOff, pkrCfgInFile + 28);
finalBuf.writeUInt32LE(planBuf.length, pkrCfgInFile + 32);
finalBuf.writeUInt32LE(NO_IMPORTS ? 0 : imports.length, pkrCfgInFile + 36); // 0 = não mexer na IAT
finalBuf.writeUInt32LE(NO_IMPORTS ? 0 : iatFirst, pkrCfgInFile + 40); // faixa de IAT a liberar
finalBuf.writeUInt32LE(NO_IMPORTS ? 0 : iatLast - iatFirst, pkrCfgInFile + 44);
// Campo zerado = o stub NÃO devolve os bytes (só na variante de diagnóstico).
if (!NO_RESTORE_EP) oepOrig8.copy(finalBuf, pkrCfgInFile + 48);
// A tabela mora no INÍCIO da seção (offset iatTabOff a partir de .pkr), não depois da
// config: somar cfgOff aqui escrevia 0x148 bytes adiante e sobrescrevia o nome da DLL —
// o loader então lia um nome inválido e o processo morria com 0xC0000135.
imports.forEach((imp, i) => finalBuf.writeUInt32LE(Number(imp.firstThunk), pkrRawPtr + iatTabOff + i * 4));

writeFileSync(out, finalBuf);

const report = {
  target: basename(target),
  out: basename(out),
  key1, key2,
  codeSection: { name: codeSec.name, rva: `0x${codeSec.virtualAddress.toString(16)}`, size: codeSec.sizeRaw },
  oepRva: `0x${epRva.toString(16)}`,
  pkrRva: `0x${pkrRva.toString(16)}`,
  stubIatRva: `0x${stubIatRva.toString(16)}`,
  importDescriptorRva: `0x${impDesc.rva.toString(16)}`,
  planRva: `0x${(pkrRva + planOff).toString(16)}`,
  planSize: planBuf.length,
  importsDestroyed: NO_IMPORTS ? null : { dlls: imports.length, funcs: imports.reduce((a, i) => a + i.funcs.length, 0) },
  variants: { noEncrypt: NO_ENCRYPT, noImports: NO_IMPORTS, noEpJump: NO_EP_JUMP, noRestoreEp: NO_RESTORE_EP },
  size: finalBuf.length,
  steps: notes,
};

if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else {
  console.log("");
  console.log("UnboxRE — packer controlado (sem caminho de restore)");
  console.log("─".repeat(70));
  for (const n of notes) console.log(`  [i ] ${n}`);
  console.log(`  [i ] alvo: ${basename(target)} -> ${basename(out)} (${finalBuf.length} bytes)`);
  console.log(`  [i ] seção de código cifrada: ${codeSec.name} rva=0x${codeSec.virtualAddress.toString(16)} size=${codeSec.sizeRaw} (key1=0x${key1.toString(16)})`);
  console.log(`  [i ] .pkr em rva=0x${pkrRva.toString(16)} · EP do stub=0x${(pkrRva + stubOff).toString(16)} · OEP real=0x${epRva.toString(16)}`);
  console.log(`  [i ] imports APAGADOS do arquivo: ${imports.length} DLLs / ${imports.reduce((a, i) => a + i.funcs.length, 0)} funções`);
  console.log(`  [i ] a IAT original (rva=0x${imports[0].firstThunk.toString(16)}) será preenchida EM MEMÓRIA pelo stub – sem descritores`);
  console.log("");
}

// ── execução: se o stub estiver errado, o processo morre aqui ───────────────
if (RUN) {
  const r = spawnSync(out, [], { timeout: 8000 });
  const status = r.status === null ? null : r.status >>> 0;
  if (!JSON_OUT) console.log(`  [${status === 0 ? "ok" : "!!"}] run — exit=${status === null ? "null" : `0x${status.toString(16)}`}`);
  if (status !== 0) {
    console.error(`\n[!!] o alvo empacotado NÃO rodou (exit=${status === null ? "null" : `0x${status.toString(16)}`}) — stub/config errados`);
    process.exit(1);
  }
  if (!JSON_OUT) console.log("  [ok] o stub descriptografou, restaurou a IAT e chegou ao OEP (exit 0)\n");
}
process.exit(0);

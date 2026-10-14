#!/usr/bin/env node
/**
 * reset-load-state.mjs — devolve um dump de MEMÓRIA ao "estado de carga limpo" que o
 * loader do Windows exige para aceitar a imagem como executável.
 *
 * Por que existe
 * --------------
 * O `rebuild-iat.mjs` conserta a tabela de imports de um dump. Só isso **não** basta: o
 * dump carrega o estado de EXECUÇÃO, e o loader reprova a imagem antes de qualquer código
 * do alvo rodar, com `0xC000007B` (STATUS_INVALID_IMAGE_FORMAT) — a caixa
 * "Este aplicativo não pode ser executado em seu PC".
 *
 * A checagem que reprova foi medida nesta ordem (ntdll do Windows 11 26200, x64):
 *
 *   ntdll!LdrpInitializeProcess
 *     └─ ntdll!LdrpProcessMappedModule
 *          ├─ ntdll!LdrpValidateEntrySection ... AddressOfEntryPoint deve ser >= SizeOfHeaders
 *          └─ ntdll!LdrInitSecurityCookie  (chamada ANTES de as relocações serem aplicadas)
 *                 rdi = LoadConfig->SecurityCookie          (VA, offset 0x58)
 *                 exige [rdi] == 0x00002B992DDFA232         (sentinela do MSVC x64)
 *                 senão: xor eax,eax -> devolve 0
 *
 *   e, de volta ao LdrpProcessMappedModule:
 *          test eax,eax / jne … ; com eax == 0 -> mov edi,0C000007Bh -> retorna 0xC000007B
 *
 * Um processo JÁ EM EXECUÇÃO tem esse cookie randomizado (`__security_init_cookie`), então
 * todo dump de memória cai nesse caso. Este script escreve o sentinela de volta no lugar
 * do cookie — o mesmo estado de uma imagem recém-compilada — e o loader passa a aceitá-la.
 *
 * O que ele NÃO faz (de propósito)
 * --------------------------------
 *   * não reconstrói a IAT (para isso, `rebuild-iat.mjs` antes deste);
 *   * não mexe em relocações, seções, EP nem nas seções esvaziadas pelo packer;
 *   * com o cookie no sentinela, o CRT de runtime volta a randomizá-lo (e o
 *     `__security_cookie_complement`) no início do processo — é exatamente o estado que o
 *     CRT espera, então nada é mascarado em tempo de execução.
 * Aceitar a imagem NÃO significa que o alvo volta a rodar: o EP de um dump costuma ser o
 * do STUB do packer (que reexecuta sobre memória já desempacotada). O status seguinte
 * medido no caso é `0xC0000005` no EP — problema diferente, e um passo posterior do fluxo.
 *
 * Uso:
 *   node scripts/reset-load-state.mjs --dump <dump.exe> [--out <saida.exe>] [--json]
 *
 *   # sem --out é dry-run: só relata o que faria (o mapa do scripts/README.md)
 *
 * Exit: 0 estado já limpo ou arquivo escrito · 1 o dump não permitiu agir · 2 erro de uso.
 * Nunca usa sudo, nunca eleva, nunca escreve sem --out.
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, basename } from "node:path";

const MSVC_COOKIE_SENTINEL = 0x00002b992ddfa232n; // __security_cookie "cru" no x64 do MSVC
const SECURITY_COOKIE_FIELD = 0x58; // IMAGE_LOAD_CONFIG_DIRECTORY64.SecurityCookie
const LOAD_CONFIG_DIR = 10; // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);

if (has("--help") || has("-h") || argv.length === 0) {
  console.log("uso: node scripts/reset-load-state.mjs --dump <dump.exe> [--out <saida.exe>] [--json]");
  console.log("     --dump <arquivo>   dump de memória (layout de memória: rawptr == RVA)");
  console.log("     --out  <arquivo>   grava a imagem corrigida (sem isso, só relata)");
  console.log("     --json             saída em JSON");
  process.exit(2);
}
const dumpPath = val("--dump");
const outPath = val("--out");
const JSON_OUT = has("--json");
if (!dumpPath) {
  console.error("erro: --dump <arquivo> é obrigatório");
  process.exit(2);
}

const buf = Buffer.from(readFileSync(dumpPath));
const u16 = (o) => buf.readUInt16LE(o);
const u32 = (o) => buf.readUInt32LE(o);
const peOff = u32(0x3c);
const opt = peOff + 24;
const is64 = u16(opt) === 0x20b;
const nSec = u16(peOff + 6);
const secOff = opt + u16(peOff + 20);
const dirsOff = opt + (is64 ? 112 : 96);
const imageBase = is64 ? buf.readBigUInt64LE(opt + 24) : BigInt(u32(opt + 28));
const sizeOfImage = u32(opt + 56);
const sizeOfHeaders = u32(opt + 60);

const secs = [];
for (let i = 0; i < nSec; i++) {
  const o = secOff + i * 40;
  secs.push({
    name: buf.toString("latin1", o, o + 8).replace(/\0+$/, ""),
    va: u32(o + 12),
    vsz: u32(o + 8),
    rawsz: u32(o + 16),
    raw: u32(o + 20),
  });
}
/** RVA -> offset de arquivo. Fora das seções, o cabeçalho tem offset == RVA. */
const rva2off = (rva) => {
  for (const s of secs) {
    if (rva >= s.va && rva < s.va + Math.max(s.vsz, s.rawsz)) return s.raw + (rva - s.va);
  }
  return rva < sizeOfHeaders ? rva : -1;
};

const loadConfigRva = u32(dirsOff + LOAD_CONFIG_DIR * 8);
const loadConfigSize = u32(dirsOff + LOAD_CONFIG_DIR * 8 + 4);

const report = {
  ferramenta: "reset-load-state",
  dump: dumpPath,
  arquiteto: is64 ? "PE32+ (x64)" : "PE32 (x86)",
  imageBase: `0x${imageBase.toString(16)}`,
  sizeOfImage: `0x${sizeOfImage.toString(16)}`,
  sizeOfHeaders: `0x${sizeOfHeaders.toString(16)}`,
  loadConfig: loadConfigRva ? `rva=0x${loadConfigRva.toString(16)} size=0x${loadConfigSize.toString(16)}` : null,
  securityCookie: null,
  sentinela: `0x${MSVC_COOKIE_SENTINEL.toString(16)}`,
  acao: "nada",
  avisos: [],
};
let changed = false;
let failed = false;

if (!loadConfigRva) {
  report.avisos.push(
    "imagem não declara diretório LOAD_CONFIG; sem ele o próprio loader já reprova " +
      "(LdrInitSecurityCookie devolve 0) — não há cookie para resetar",
  );
  failed = true;
} else {
  const lcOff = rva2off(loadConfigRva);
  if (lcOff < 0) {
    report.avisos.push("LOAD_CONFIG fora das seções do dump");
    failed = true;
  } else {
    const declaredSize = u32(lcOff); // ULONG Size (o primeiro campo é Size, mesmo em 64 bits)
    const cookieVa = buf.readBigUInt64LE(lcOff + SECURITY_COOKIE_FIELD);
    report.loadConfigSizeDeclarado = `0x${declaredSize.toString(16)}`;
    report.securityCookie = { va: `0x${cookieVa.toString(16)}` };
    if (declaredSize < 0x70) {
      report.avisos.push(
        `LoadConfig com Size=0x${declaredSize.toString(16)} < 0x70: o loader nem chega a ler o ` +
          "cookie (seção do LoadConfig esvaziada no dump?)",
      );
      failed = true;
    } else if (cookieVa === 0n) {
      report.avisos.push("LoadConfig não declara SecurityCookie");
      failed = true;
    } else if (cookieVa < imageBase || cookieVa >= imageBase + BigInt(sizeOfImage)) {
      report.avisos.push(
        `SecurityCookie=0x${cookieVa.toString(16)} está fora de [ImageBase, ImageBase+SizeOfImage): ` +
          "o dump não está no layout de memória baseado no ImageBase do cabeçalho (rode o DumpModule " +
          "do x64dbg-MCP, que produz esse layout), então a RVA do cookie não é dedutível",
      );
      failed = true;
    } else {
      const cookieRva = Number(cookieVa - imageBase);
      const cookieOff = rva2off(cookieRva);
      if (cookieOff < 0) {
        report.avisos.push("cookie fora das seções do dump");
        failed = true;
      } else {
        const before = buf.readBigUInt64LE(cookieOff);
        report.securityCookie.rva = `0x${cookieRva.toString(16)}`;
        report.securityCookie.antes = `0x${before.toString(16).padStart(16, "0")}`;
        if (before === MSVC_COOKIE_SENTINEL) {
          report.acao = "já_limpo";
          report.avisos.push("cookie já está no sentinela: imagem aceita pelo loader");
        } else {
          buf.writeBigUInt64LE(MSVC_COOKIE_SENTINEL, cookieOff);
          report.securityCookie.depois = `0x${MSVC_COOKIE_SENTINEL.toString(16).padStart(16, "0")}`;
          report.acao = outPath ? "escrito" : "dry-run";
          changed = true;
        }
      }
    }
  }
}

if (changed && outPath) {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, buf);
  report.saida = outPath;
  report.bytes = buf.length;
}

if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`\nUnboxRE — reset do estado de carga (dump de memória -> imagem aceita pelo loader)`);
  console.log("─".repeat(74));
  console.log(`  dump  : ${basename(dumpPath)}  ${report.arquiteto}`);
  console.log(`  base  : ImageBase=${report.imageBase}  SizeOfImage=${report.sizeOfImage}  SizeOfHeaders=${report.sizeOfHeaders}`);
  console.log(`  config: LoadConfig ${report.loadConfig ?? "(ausente)"}`);
  if (report.securityCookie) {
    console.log(`  cookie: VA=${report.securityCookie.va}  RVA=${report.securityCookie.rva ?? "(n/d)"}`);
    if (report.securityCookie.antes) {
      console.log(`          antes  = ${report.securityCookie.antes} (estado de EXECUÇÃO)`);
      console.log(`          depois = ${report.securityCookie.depois ?? report.securityCookie.antes} (sentinela MSVC)`);
    }
  }
  console.log(`  ação  : ${report.acao}`);
  for (const a of report.avisos) console.log(`  [!!] ${a}`);
  if (report.saida) console.log(`  saída : ${report.saida} (${report.bytes} bytes)`);
  if (changed && !outPath) console.log(`  (dry-run: rode de novo com --out <arquivo> para gravar)`);
}

process.exit(failed ? 1 : 0);

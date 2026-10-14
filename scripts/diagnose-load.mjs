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
 *   2. o mapa de relocações / o load config, que deixam de cobrir o que precisam;
 *   3. o **estado de carga** — `__security_cookie` já randomizado (dump de memória):
 *      `LdrInitSecurityCookie` reprova a imagem. Ver §8 de `reports/root-cause-0xc000007b.md`.
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
 * Alvo de CONSOLE que lê stdin (medido no round 8.1, com um crackme)
 * -------------------------------------------------------------------
 * Sem `--stdin`, o processo recebe EOF imediatamente: um programa que pergunta a senha lê
 * nada, escolhe o caminho de erro e sai com o código DELE (no caso, 1). O script então
 * imprimia `exit=0x1 (status não catalogado)`, que se lê como defeito do binário — não é:
 * é o programa funcionando. Duas correções: `--stdin <texto>` (ou `--stdin-file <arq>`)
 * alimenta a entrada, e um status abaixo de 0x80000000 passa a ser reportado como "saiu
 * normalmente com status N (código do próprio programa)", separado de um NTSTATUS de falha.
 *
 * E o status sozinho não basta: aquele crackme sai 0 tanto com a senha certa quanto com a
 * errada — quem distingue é o TEXTO que ele imprime. Por isso o script também captura a
 * saída do alvo (stdout+stderr, até 8 linhas) e a mostra; `--no-output` desliga. Com
 * `--stdin` + a saída capturada, ele passa a ser um harness black-box de linha de comando
 * (o que antes exigia `printf senha | alvo.exe` na mão).
 *
 * Alvo ELF (Linux) — adicionado no round 8.3
 * ------------------------------------------
 * Um ELF não é imagem que o loader do Windows aceite: `CreateProcess` falha com 193
 * (`ERROR_BAD_EXE_FORMAT`), que NÃO é `0xC000007B` — confundir os dois ("deve ser a
 * virtualização"/"deve ser relocação") manda a investigação para o lado errado. Para ELF o
 * script não procura vício de loader: ele diz o formato, dá o status real da execução e
 * aponta os caminhos (Linux nativo, WSL com distro, emulação) — as três ferramentas de
 * leitura do toolkit já leem ELF.
 *
 * Uso: node scripts/diagnose-load.mjs <arquivo> [--no-run] [--stdin <texto>]
 *         [--stdin-file <arquivo>] [--no-output] [--json]
 * Exit: 0 analisado e o alvo carregou (ou --no-run) · 1 o loader rejeitou (inclusive
 *       quando o `CreateProcess` falha, ex. `EFTYPE`/193 = ERROR_BAD_EXE_FORMAT, que é o
 *       mesmo erro visto como `0xC000007B` quando o processo chega a ser criado) ·
 *       2 não consegui ler/executar. Nunca usa sudo.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h") || args.length === 0) {
  console.log("uso: node scripts/diagnose-load.mjs <arquivo.exe> [--no-run] [--stdin <texto>] [--stdin-file <arquivo>] [--json]");
  console.log("  --no-run              só a análise estática (não executa o alvo)");
  console.log("  --stdin <texto>       alimenta a entrada do alvo (alvo de console; sem isso ele recebe EOF)");
  console.log("  --stdin-file <arq>    idem, lendo o texto de um arquivo");
  console.log("  --no-output           não mostra a saída capturada do alvo (stdout/stderr)");
  process.exit(args.length === 0 ? 2 : 0);
}
const JSON_OUT = args.includes("--json");
const NO_RUN = args.includes("--no-run");
const NO_OUTPUT = args.includes("--no-output");
const argVal = (flag) => (args.includes(flag) ? args[args.indexOf(flag) + 1] : null);
const file = args.find((a) => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--stdin" && args[args.indexOf(a) - 1] !== "--stdin-file");

// stdin do alvo: sem isto, um alvo de console recebe EOF e sai pelo caminho de erro (o
// código de saída dele seria lido como se fosse falha de loader).
let stdinData = null;
const stdinInline = argVal("--stdin");
const stdinFile = argVal("--stdin-file");
if (stdinInline !== null) stdinData = stdinInline.endsWith("\n") ? stdinInline : `${stdinInline}\n`;
else if (stdinFile !== null) {
  try {
    stdinData = readFileSync(stdinFile);
  } catch (e) {
    console.error(`[!!] --stdin-file ${stdinFile}: ${e.message}`);
    process.exit(2);
  }
}

let buf;
try {
  buf = readFileSync(file);
} catch (e) {
  console.error(`não consegui ler ${file}: ${e.message}`);
  process.exit(2);
}
// ── ELF (Linux) ──────────────────────────────────────────────────────────────
// Pergunta parecida, resposta CURTA e verificável: um ELF não é imagem que o loader do
// Windows aceite, então `0xC000007B` não é o erro dele — o `CreateProcess` falha antes, com
// 193 (`ERROR_BAD_EXE_FORMAT`). Confundir os dois manda a investigação para o lado errado
// (medido no round 8.3: o alvo era ELF e a leitura apressada seria "loader/relocação").
// Este branch dá o status REAL executando o alvo (a menos que --no-run) e diz o que fazer.
if (buf.length >= 0x40 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
  const u16e = (o) => buf.readUInt16LE(o);
  const u32e = (o) => buf.readUInt32LE(o);
  const u64e = (o) => Number(buf.readBigUInt64LE(o));
  const is64e = buf[4] === 2;
  const TYPE = { 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN (PIE/shared)", 4: "ET_CORE" }[u16e(16)] ?? `e_type=0x${u16e(16).toString(16)}`;
  const MACH = { 0x03: "x86", 0x3e: "x64", 0x28: "ARM", 0xb7: "ARM64", 0xf3: "RISC-V" }[u16e(18)] ?? `0x${u16e(18).toString(16)}`;
  const entry = is64e ? u64e(24) : u32e(24);
  const findings = [
    { level: "high", code: "formato-nao-carregavel-no-windows", detail: `é ELF (${is64e ? "ELF64" : "ELF32"}, ${TYPE}, ${MACH}, entry 0x${entry.toString(16)}) — o loader do Windows só carrega PE; o erro dele é 193 (ERROR_BAD_EXE_FORMAT), NÃO 0xC000007B` },
    { level: "info", code: "0xc000007b-nao-se-aplica", detail: "0xC000007B é o loader rejeitando uma imagem PE malformada; aqui não há PE nenhum para rejeitar, então investigar relocação/DYNAMIC_BASE/estado de carga deste arquivo não leva a nada" },
    { level: "info", code: "caminhos", detail: "para EXECUTAR: Linux nativo, WSL com distro instalada (`wsl --install -d Ubuntu` — exige elevação e rede) ou emulação (Unicorn/Qiling, Cenário 12 de docs/06-workflows.md). Sem isso o caminho é estático — e as três ferramentas de leitura do toolkit já leem ELF (triage-static.mjs, disasm-range.py, pe-read.mjs)" },
  ];
  const run = { skipped: NO_RUN, exit: null, hex: null, meaning: null, output: null, error: null, stdin: stdinData !== null ? { fed: true, bytes: Buffer.byteLength(stdinData) } : { fed: false } };
  if (!NO_RUN) {
    const r = spawnSync(file, [], { input: stdinData ?? undefined, encoding: "utf8", timeout: 10000, windowsHide: true });
    const clean = (s) => String(s ?? "").replace(/\r/g, "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "");
    const output = `${clean(r.stdout)}${clean(r.stderr)}`;
    const status = typeof r.status === "number" ? r.status : null;
    run.exit = status;
    run.hex = status === null ? null : `0x${status.toString(16)}`;
    run.error = r.error ? `${r.error.code ?? ""} ${r.error.message}`.trim() : null;
    // Duas recusas DIFERENTES, e confundi-las é fácil (medido no round 8.3): sem extensão
    // `.exe`, o Node/libuv procura `<nome>.exe` e devolve ENOENT — isso é a busca do nome, não
    // o loader lendo a imagem. Com `.exe`, o `CreateProcess` tenta carregar e devolve um erro
    // sem código específico (UNKNOWN) que é o ERROR_BAD_EXE_FORMAT dos bastidores.
    const semExe = !file.toLowerCase().endsWith(".exe");
    run.meaning = r.error
      ? r.error.code === "ENOENT" && semExe
        ? 'o arquivo não tem extensão .exe: o Node procura "<nome>.exe" e não acha (ENOENT) — é a busca do nome, NÃO a recusa do loader; copie para um nome com .exe para ver a recusa real'
        : `CreateProcess recusou a imagem (${r.error.code ?? "erro"}; no Windows isso é ERROR_BAD_EXE_FORMAT/193) — é isto que "não carrega" significa para um ELF`
      : status === 0 ? "saiu normalmente com status 0"
      : `saiu com status ${status}${status === 193 ? " (193 = ERROR_BAD_EXE_FORMAT: não é imagem Win32 válida)" : ""}`;
    if (status === 193 || (r.error && !(r.error.code === "ENOENT" && semExe))) {
      findings.push({ level: "medium", code: "execucao-recusada", detail: `executar no Windows falhou como esperado para um ELF — ${run.meaning}` });
    }
  }
  const verdict = "não é imagem do loader do Windows (ELF) — nada no arquivo para consertar visando o Windows; rodar exige Linux, WSL com distro ou emulação";
  const report = {
    file: basename(file), size: buf.length, format: is64e ? "ELF64" : "ELF32", type: TYPE, machine: MACH,
    entryPoint: `0x${entry.toString(16)}`, findings, run, verdict,
  };
  if (JSON_OUT) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("");
    console.log(`UnboxRE — diagnóstico de carga: ${report.file}`);
    console.log("─".repeat(70));
    console.log(`  ${report.size} bytes · ${report.format} · ${report.type} · ${report.machine} · entry=0x${entry.toString(16)}`);
    console.log("");
    const tag = { high: "!!", medium: "? ", info: "i " };
    for (const f of findings) console.log(`  [${tag[f.level]}] ${f.code} — ${f.detail}`);
    if (run.skipped) console.log("  [i ] run — pulado (--no-run)");
    else {
      const stdinInfo = run.stdin?.fed ? ` · stdin alimentado (${run.stdin.bytes} bytes)` : " · stdin: EOF (sem --stdin)";
      console.log(`  [i ] run — exit=${run.hex ?? "(nenhum)"} (${run.meaning})${stdinInfo}`);
      if (!NO_OUTPUT) {
        if (!run.output) console.log("  [i ] saída do alvo — (stdout+stderr vazios)");
        else {
          const lines = run.output.split(/\n/).filter((l) => l.trim() !== "");
          console.log(`  [i ] saída do alvo (${lines.length} linha(s)):`);
          for (const l of lines.slice(0, 8)) console.log(`        | ${l.slice(0, 200)}`);
        }
      }
    }
    console.log(`\n  Veredito: ${verdict}`);
    console.log("");
  }
  process.exit(NO_RUN ? 0 : run.error || (run.exit !== null && run.exit !== 0) ? 1 : 0);
}

if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) {
  console.error(`${file}: nem assinatura "MZ" (PE) nem "\\x7fELF" — formato não reconhecido`);
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
      // Um dump de memória pode trazer a tabela de seções no layout de arquivo e os dados
      // no de memória: aí o bloco lido aqui é lixo e `blockSize` pode ser enorme. Sem este
      // limite o script estourava (ERR_OUT_OF_RANGE) em vez de classificar o arquivo.
      if (blockSize < 8 || blockSize > end - p || p + blockSize > buf.length) {
        add("high", "reloc-bloco-invalido",
          `bloco de relocação inválido em rva 0x${reloc.rva.toString(16)}: pageRva=0x${pageRva.toString(16)} blockSize=0x${blockSize.toString(16)} (lido em offset 0x${p.toString(16)}) — cabeçalho inconsistente com os dados (dump em layout de memória com tabela de seções de arquivo?)`);
        break;
      }
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

// LoadConfig / __security_cookie — o estado de carga exigido pelo loader.
// Medido em ntdll (ver reports/root-cause-0xc000007b.md §8): LdrInitSecurityCookie exige
// que o cookie da imagem ainda esteja no sentinela do MSVC e devolve 0 caso contrário; com
// 0, LdrpProcessMappedModule devolve STATUS_INVALID_IMAGE_FORMAT antes do entrypoint.
const MSVC_COOKIE_SENTINEL = 0x2b992ddfa232n;
const imageBase = is64 ? buf.readBigUInt64LE(opt + 24) : BigInt(u32(opt + 28));
const lcRva = u32(dirsOff + 10 * 8);
const lcSize = u32(dirsOff + 10 * 8 + 4);
if (lcRva && lcSize) {
  const lcOff = rva2off(lcRva);
  if (lcOff < 0 || lcOff + 0x60 > buf.length) {
    add("high", "loadconfig-ilegivel",
      `LOAD_CONFIG rva=0x${lcRva.toString(16)} size=0x${lcSize.toString(16)} não é legível no arquivo: sem ele LdrInitSecurityCookie devolve 0 e o loader sai com 0xC000007B`);
  } else {
    const declared = u32(lcOff);
    const cookieVa = buf.readBigUInt64LE(lcOff + 0x58);
    if (declared < 0x70) {
      add("high", "loadconfig-curto",
        `LOAD_CONFIG com Size=0x${declared.toString(16)} (< 0x70): o cookie nem é lido — LdrInitSecurityCookie devolve 0 e o loader sai com 0xC000007B (típico de seção do LoadConfig esvaziada)`);
    } else if (cookieVa === 0n) {
      add("medium", "securitycookie-ausente", "LOAD_CONFIG não declara SecurityCookie (imagem sem CRT, ou load config remontado por packer)");
    } else if (cookieVa < imageBase || cookieVa >= imageBase + BigInt(sizeOfImage)) {
      add("medium", "securitycookie-fora-da-imagem",
        `SecurityCookie=0x${cookieVa.toString(16)} está fora de [ImageBase, ImageBase+SizeOfImage): o arquivo não está no layout de memória (tabela de seções de arquivo com dados de dump, ou base trocada)`);
    } else {
      const cookieRva = Number(cookieVa - imageBase);
      const cookieOff = rva2off(cookieRva);
      const current = cookieOff >= 0 && cookieOff + 8 <= buf.length ? buf.readBigUInt64LE(cookieOff) : null;
      if (current !== null && current !== MSVC_COOKIE_SENTINEL) {
        add("high", "cookie-em-estado-de-execucao",
          `__security_cookie em RVA 0x${cookieRva.toString(16)} = 0x${current.toString(16).padStart(16, "0")}, ` +
            `mas o loader exige o sentinela do MSVC 0x${MSVC_COOKIE_SENTINEL.toString(16)}: esta imagem está no estado de EXECUÇÃO ` +
            "(dump de memória) — LdrInitSecurityCookie devolve 0 e o loader sai com 0xC000007B antes do entrypoint. " +
            "Corrija com: node scripts/reset-load-state.mjs --dump <dump.exe> --out <saida.exe>");
      } else if (current !== null) {
        add("info", "cookie-no-sentinela", `__security_cookie em RVA 0x${cookieRva.toString(16)} está no sentinela do MSVC (estado de carga limpo)`);
      }
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
  // encoding: captura a saída do alvo (um alvo de console sem stdin morre no EOF e o que
  // ele imprimiu é a única prova do caminho que ele tomou).
  const r = spawnSync(file, [], { timeout: 8000, encoding: "utf8", ...(stdinData !== null ? { input: stdinData } : {}) });
  if (r.error) {
    // O processo nem chegou a existir: é o MESMO erro de imagem inválida, detectado um
    // estágio antes (o NTSTATUS 0xC000007B e o Win32 193/ERROR_BAD_EXE_FORMAT são o mesmo
    // STATUS_INVALID_IMAGE_FORMAT em camadas diferentes). `status` aqui é `null`, e tratar
    // `null >>> 0` como "0" faria o script dizer que o alvo carregou — não faz.
    run = { skipped: false, exit: null, hex: null, error: r.error.code, meaning: `CreateProcess falhou (${r.error.code}) — o loader recusou a imagem antes de criar o processo` };
    add("high", "loader-recusou-createprocess",
      `CreateProcess falhou com ${r.error.code} (ERROR_BAD_EXE_FORMAT = 193 é o mesmo STATUS_INVALID_IMAGE_FORMAT visto como 0xC000007B quando o processo chega a ser criado)`);
  } else {
    const status = r.status === null ? null : r.status >>> 0;
    // Status < 0x80000000 NÃO é NTSTATUS: é o código de saída do PRÓPRIO programa (um
    // crackme que termina pelo caminho de erro sai com 1). Dizer "não catalogado" nesse
    // caso faz o analista procurar defeito de loader onde não há (medido no round 8.1).
    const meaning =
      status === null ? "sem status (timeout/sinal)"
      : NTSTATUS[status] ? NTSTATUS[status]
      : status < 0x80000000
        ? `saiu normalmente com status ${status} — código do PRÓPRIO programa, não é falha de loader`
        : "status NTSTATUS não catalogado";
    const stdinNote = stdinData !== null ? { fed: true, bytes: Buffer.byteLength(stdinData) } : { fed: false };
    const clean = (s) => String(s ?? "").replace(/\r/g, "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "");
    const output = `${clean(r.stdout)}${clean(r.stderr)}`;
    run = {
      skipped: false,
      exit: status,
      hex: status === null ? null : `0x${status.toString(16)}`,
      stdin: stdinNote,
      output: output.trim() || null,
      outputTruncated: r.error?.code === "ETIMEDOUT",
      meaning,
    };
    if (run.exit === 0xc000007b) {
      add("high", "loader-rejeitou", "a execução terminou com 0xC000007B: o loader rejeitou a imagem ANTES do entrypoint (é isto que este script diagnostica)");
    }
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
  else if (run.error) console.log(`  [!!] run — ${run.error} (${run.meaning})`);
  else {
    const stdinInfo = run.stdin?.fed ? ` · stdin alimentado (${run.stdin.bytes} bytes)` : " · stdin: EOF (sem --stdin)";
    console.log(`  [${run.exit === 0xc000007b ? "!!" : "i "}] run — exit=${run.hex} (${run.meaning})${stdinInfo}`);
    if (!NO_OUTPUT) {
      if (!run.output) console.log("  [i ] saída do alvo — (stdout+stderr vazios)");
      else {
        const lines = run.output.split(/\n/).filter((l) => l.trim() !== "");
        const shown = lines.slice(0, 8);
        console.log(`  [i ] saída do alvo (${lines.length} linha(s)${lines.length > shown.length ? ", mostrando 8" : ""}):`);
        for (const l of shown) console.log(`        | ${l.slice(0, 200)}`);
      }
    }
  }
  console.log(`\n  Veredito: ${verdict}`);
  console.log("");
}

const rejected = run.exit === 0xc000007b || Boolean(run.error);
process.exit(run.skipped ? 0 : rejected ? 1 : 0);

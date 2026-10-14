#!/usr/bin/env python3
"""
disasm-range.py — lê o CÓDIGO de um PE ou ELF sem abrir Ghidra nem o debugger.

Formatos: **PE (Windows)** e **ELF (Linux)**. Um alvo ELF apareceu no round 8.3 e este
script (como as outras ferramentas de leitura) morria em "sem assinatura MZ". O motor de
desmontagem é o mesmo; o que mudou foi reconhecer o outro cabeçalho e normalizar as seções
(as duas formas viram {nome, va, vs, raw, rs}), então `--section .text` e `--strings`
funcionam igual nos dois. Em ELF o endereço é o vaddr de link (absoluto, como no objdump).

Por que existe
--------------
O toolkit tinha caminho para triagem estática (`identify-protections.mjs`, agora também
`triage-static.mjs`) e para tudo o mais pelo debugger vivo (MCP do x64dbg: `Disassemble`,
`GetReferences`). Faltava o meio: ler ~300 bytes de código de um alvo pequeno, offline,
num comando. O que existia na máquina era nada — nem `objdump`, nem `dumpbin`, nem `r2`
(medido no round 8.1; o Capstone, porém, é catalogado desde sempre e já estava no
ambiente Python). Este script é o caminho, com dependência declarada:

    pip install --user capstone        # o bootstrap (perfil static) instala

Entrada: intervalo de RVA. Sem `--fim`, desmonta a seção que contém o RVA inicial.
Saída: endereço (relativo à imagem), bytes, mnemônico/operandos e, com `--strings`, o
valor de strings apontadas por RIP-relativo (a anotação que responde "onde essa mensagem
é usada" sem passar pelo debugger).

Limites honestos: é linear (`--fim` errado no meio de uma instrução contamina o resto);
não segue fluxo, não resolve indireto, não é decompilador. Para fluxo/estrutura o caminho
continua sendo Ghidra (headless ou GUI) e o x64dbg pelo MCP.

Uso:
  python scripts/disasm-range.py <arquivo.exe> <rva-ini> [rva-fim|--fim 0x1234]
        [--section .text] [--strings] [--json] [--max N]
Exit: 0 desmontado · 2 arquivo ilegível, RVA inválido ou capstone ausente. Nunca usa sudo.
"""

import argparse
import json
import sys


def _setup_console() -> None:
    """Impede que o desenho do relatório derrube a análise no console do Windows.

    Medido no round 8.1: `python scripts/disasm-range.py <alvo> 0x1520 --fim ...` num
    console cp1252 morreu com `UnicodeEncodeError: 'charmap' codec can't encode
    characters in position 0-69` — no `'─'` (U+2500) da linha separadora, DEPOIS de já
    ter impresso metade do relatório. O destino decide a correção:

      · saída REDIRECIONADA (`> evidence/x.txt`, pipe — o caso canônico do toolkit):
        UTF-8, para o arquivo guardar o desenho correto;
      · saída no CONSOLE: a code page local com `errors='replace'` — o desenho vira '?'
        (legível) e nada mais lança exceção no meio da saída.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass  # stream não reconfigurável: segue sem isso (pior caso: o de antes)


try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP
    try:
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:                     # capstone antigo: só o caminho x86 fica disponível
        CS_ARCH_ARM64 = None
except ImportError:
    print("[!!] capstone não está instalado no Python desta máquina.", file=sys.stderr)
    print("     instale com:  python -m pip install --user capstone", file=sys.stderr)
    print("     (o bootstrap do toolkit, perfil 'static', faz isso: scripts\\bootstrap-windows.ps1 -Profile static -Apply)", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    _setup_console()
    ap = argparse.ArgumentParser(add_help=True, description="desmonta um intervalo de código de um PE ou ELF (RVA ou vaddr)")
    ap.add_argument("arquivo")
    # Obrigatório só quando não se usa --section: `--section .text` sozinho é o caso mais
    # comum e exigia um RVA de enfeite na linha de comando (fricção medida no round 8.3).
    ap.add_argument("rva_ini", nargs="?", default=None, help="RVA/vaddr inicial (aceita 0x...) — dispensável com --section")
    ap.add_argument("rva_fim", nargs="?", default=None, help="RVA final (opcional; default: fim da seção)")
    ap.add_argument("--fim", dest="fim_opt", default=None, help="RVA final (alternativa posicional)")
    ap.add_argument("--section", default=None, help="desmonta uma seção inteira pelo nome (ex.: .text)")
    ap.add_argument("--strings", action="store_true", help="anota strings apontadas por RIP-relativo")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max", type=int, default=4000, help="máximo de instruções (default 4000)")
    args = ap.parse_args()

    try:
        buf = open(args.arquivo, "rb").read()
    except OSError as e:
        print(f"[!!] não consegui ler {args.arquivo}: {e}", file=sys.stderr)
        return 2

    # ── formato: PE (Windows) ou ELF (Linux) ──────────────────────────────────
    is_elf = len(buf) >= 0x40 and buf[0:4] == b"\x7fELF"
    is_pe = len(buf) >= 0x40 and buf[0:2] == b"MZ"
    if not is_pe and not is_elf:
        print(f"[!!] {args.arquivo}: nem assinatura \"MZ\" (PE) nem \"\\x7fELF\" — formato não reconhecido", file=sys.stderr)
        return 2
    u16 = lambda o: int.from_bytes(buf[o:o + 2], "little")
    u32 = lambda o: int.from_bytes(buf[o:o + 4], "little")
    u64 = lambda o: int.from_bytes(buf[o:o + 8], "little")

    machine = None
    secs = []
    if is_pe:
        pe = u32(0x3C)
        if buf[pe:pe + 4] != b"PE\0\0":
            print(f"[!!] {args.arquivo}: assinatura PE ausente em 0x{pe:x}", file=sys.stderr)
            return 2
        opt = pe + 24
        is64 = u16(opt) == 0x20B
        machine = u16(pe + 4)
        nsec, osz = u16(pe + 6), u16(pe + 20)
        image_base = int.from_bytes(buf[opt + 24:opt + 32], "little") if is64 else u32(opt + 28)
        fmt = "PE"
        for i in range(nsec):
            s = pe + 24 + osz + i * 40
            secs.append({
                "name": buf[s:s + 8].rstrip(b"\0").decode("latin1"),
                "va": u32(s + 12), "vs": u32(s + 8), "raw": u32(s + 20), "rs": u32(s + 16),
            })
    else:
        # ELF: as seções viram o MESMO dicionário do PE ({name, va, vs, raw, rs}), então
        # todo o resto do script (rva2off, --section, --fim, anotação de string) segue sem
        # saber de qual formato veio. `va` aqui é o vaddr de link (absoluto) e a imagem é
        # referenciada com base 0 — é assim que objdump/readelf mostram.
        if buf[5] != 1:
            print(f"[!!] {args.arquivo}: ELF big-endian (EI_DATA={buf[5]}) — este script lê little-endian", file=sys.stderr)
            return 2
        if buf[4] not in (1, 2):
            print(f"[!!] {args.arquivo}: EI_CLASS={buf[4]} inválido", file=sys.stderr)
            return 2
        is64 = buf[4] == 2
        machine = u16(18)
        if is64:
            shoff, shentsize, shnum, shstrndx = u64(0x28), u16(0x3A), u16(0x3C), u16(0x3E)
        else:
            shoff, shentsize, shnum, shstrndx = u32(0x20), u16(0x2E), u16(0x30), u16(0x32)
        if shnum == 0 or shentsize == 0:
            print(f"[!!] {args.arquivo}: ELF sem tabela de seções (stripped até nisso) — não sei onde está o código", file=sys.stderr)
            return 2
        raw = []
        for i in range(shnum):
            o = shoff + i * shentsize
            if o + shentsize > len(buf):
                break
            raw.append({"name_off": u32(o), "type": u32(o + 4), "flags": u64(o + 8) if is64 else u32(o + 8),
                        "addr": u64(o + 16) if is64 else u32(o + 12),
                        "off": u64(o + 24) if is64 else u32(o + 16),
                        "size": u64(o + 32) if is64 else u32(o + 20)})
        shstr = raw[shstrndx] if shstrndx < len(raw) else None

        def cname(off):
            o = (shstr["off"] + off) if shstr else -1
            if o < 0 or o >= len(buf):
                return ""
            e = buf.find(b"\0", o)
            return buf[o:(e if e >= 0 else len(buf))].decode("latin1")

        image_base = 0
        fmt = "ELF"
        for s in raw:
            alloc = bool(s["flags"] & 0x2)          # SHF_ALLOC
            nobits = s["type"] == 8                 # SHT_NOBITS: memória, não arquivo
            secs.append({
                "name": cname(s["name_off"]) or "(sem nome)",
                "va": s["addr"] if alloc else -1,
                "vs": s["size"], "raw": s["off"], "rs": 0 if nobits else s["size"],
            })

    def rva2off(r):
        for s in secs:
            if s["va"] < 0 or s["rs"] == 0:        # sem vaddr ou sem bytes no arquivo
                continue
            if s["va"] <= r < s["va"] + max(s["vs"], s["rs"]):
                return s["raw"] + (r - s["va"])
        return -1

    def section_of(r):
        for s in secs:
            if s["va"] < 0 or s["rs"] == 0:
                continue
            if s["va"] <= r < s["va"] + max(s["vs"], s["rs"]):
                return s
        return None

    def cstr(r):
        o = rva2off(r)
        if o < 0:
            return None
        e = o
        while e < len(buf) and buf[e] not in (0,) and 0x20 <= buf[e] < 0x7F:
            e += 1
        txt = buf[o:e].decode("latin1")
        return txt if len(txt) >= 3 else None

    if args.section:
        sec = next((s for s in secs if s["name"] == args.section), None)
        if not sec:
            print(f"[!!] seção {args.section} não existe (tem: {', '.join(s['name'] for s in secs)})", file=sys.stderr)
            return 2
        if sec["va"] < 0 or sec["rs"] == 0:
            print(f"[!!] seção {args.section} não está carregada / não tem bytes no arquivo (nada para desmontar)", file=sys.stderr)
            return 2
        ini, fim = sec["va"], sec["va"] + min(sec["vs"], sec["rs"])
    else:
        if args.rva_ini is None:
            print("[!!] informe um endereço inicial ou use --section <nome>", file=sys.stderr)
            return 2
        try:
            ini = int(args.rva_ini, 0)
        except ValueError:
            print("[!!] rva-ini precisa ser numérico (ex.: 0x1520)", file=sys.stderr)
            return 2
        fim_txt = args.fim_opt if args.fim_opt is not None else args.rva_fim
        if fim_txt is None:
            sec = section_of(ini)
            if not sec:
                print(f"[!!] RVA 0x{ini:x} não está em seção nenhuma (e sem --fim não sei onde parar)", file=sys.stderr)
                return 2
            fim = sec["va"] + min(sec["vs"], sec["rs"])
        else:
            try:
                fim = int(fim_txt, 0)
            except ValueError:
                print("[!!] rva-fim precisa ser numérico (ex.: 0x15c0)", file=sys.stderr)
                return 2
        if fim <= ini:
            print(f"[!!] rva-fim (0x{fim:x}) tem de ser maior que o inicial (0x{ini:x})", file=sys.stderr)
            return 2

    off_ini = rva2off(ini)
    off_fim = rva2off(fim)
    if off_fim < 0:
        # O fim de seção é EXCLUSIVO e cai no byte seguinte (o mapa trabalha com [início, fim)):
        # `--section .text` monta exatamente esse valor, então tratá-lo como endereço fora do
        # arquivo recusava o caso mais comum. Medido no round 8.3 (o ELF morreu em "intervalo
        # não é legível" para `--section .text` inteira).
        for s in secs:
            if s["va"] >= 0 and s["rs"] > 0 and fim == s["va"] + max(s["vs"], s["rs"]):
                off_fim = s["raw"] + s["rs"]
                break
    if off_ini < 0 or off_fim < 0:
        print(f"[!!] intervalo 0x{ini:x}-0x{fim:x} não é legível no arquivo", file=sys.stderr)
        return 2

    # Arquitetura: x86 nos dois formatos; ARM64 se o capstone desta máquina tiver
    # (o catálogo do toolkit usa x86; ARM64 é o outro `e_machine` que aparece na prática).
    arm64_machines = {0xB7, 0xAA64}                 # EM_AARCH64 / IMAGE_FILE_MACHINE_ARM64
    if machine in arm64_machines and CS_ARCH_ARM64 is not None:
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    elif machine in (0x03, 0x14C):                  # EM_386 / IMAGE_FILE_MACHINE_I386
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif machine in (0x3E, 0x8664) or machine is None:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        print(f"[!!] {args.arquivo}: e_machine/machine 0x{machine:x} não suportado por este script (x86, x86-64, ARM64)", file=sys.stderr)
        return 2
    md.detail = True
    rows = []
    for ins in md.disasm(buf[off_ini:off_fim], image_base + ini):
        row = {
            "rva": ins.address - image_base,
            "bytes": " ".join(f"{b:02x}" for b in ins.bytes),
            "mnemonic": ins.mnemonic,
            "op_str": ins.op_str,
            "annotation": None,
        }
        if args.strings:
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    tgt = ins.address + ins.size + op.mem.disp
                    s = cstr(tgt - image_base)
                    row["annotation"] = f'"{s}"' if s else f"-> rva 0x{tgt - image_base:x}"
                elif op.type == X86_OP_REG and ins.mnemonic.startswith("call"):
                    row["annotation"] = "call indireto (por registrador)"
        rows.append(row)
        if len(rows) >= args.max:
            break

    if args.json:
        print(json.dumps({"file": args.arquivo, "imageBase": f"0x{image_base:x}", "from": f"0x{ini:x}", "to": f"0x{fim:x}", "count": len(rows), "instructions": rows}, indent=2))
    else:
        print("")
        print(f"UnboxRE — desmontagem estática: {args.arquivo}")
        rotulo = "RVA" if fmt == "PE" else "vaddr"
        print(f"  {fmt} · ImageBase=0x{image_base:x} · intervalo {rotulo} 0x{ini:x}..0x{fim:x} · {len(rows)} instrução(ões)")
        print("─" * 70)
        for r in rows:
            note = f"   ; {r['annotation']}" if r["annotation"] else ""
            # 24, não 22: uma instrução de 8 bytes ocupa 23 colunas de "xx " e estourava o
            # campo, colando os bytes no mnemônico. Medido no round 8.3: a linha do
            # `movzx eax, byte ptr [rsp + rcx + 0x260]` saiu sem o separador e uma extração
            # por coluna (a minha, lendo esta saída) PERDEU a instrução — justamente numa das
            # que decodificam o bytecode do alvo.
            print(f"  0x{r['rva']:05x}  {r['bytes']:<24} {r['mnemonic']:<8} {r['op_str']}{note}")
        print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())

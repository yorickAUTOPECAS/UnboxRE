#!/usr/bin/env python3
"""
disasm-range.py — lê o CÓDIGO de um PE sem abrir Ghidra nem o debugger.

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
except ImportError:
    print("[!!] capstone não está instalado no Python desta máquina.", file=sys.stderr)
    print("     instale com:  python -m pip install --user capstone", file=sys.stderr)
    print("     (o bootstrap do toolkit, perfil 'static', faz isso: scripts\\bootstrap-windows.ps1 -Profile static -Apply)", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    _setup_console()
    ap = argparse.ArgumentParser(add_help=True, description="desmonta um intervalo de RVA de um PE")
    ap.add_argument("arquivo")
    ap.add_argument("rva_ini", help="RVA inicial (aceita 0x...)")
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

    if len(buf) < 0x40 or buf[0:2] != b"MZ":
        print(f"[!!] {args.arquivo}: sem assinatura MZ — não é um PE", file=sys.stderr)
        return 2
    u16 = lambda o: int.from_bytes(buf[o:o + 2], "little")
    u32 = lambda o: int.from_bytes(buf[o:o + 4], "little")
    pe = u32(0x3C)
    if buf[pe:pe + 4] != b"PE\0\0":
        print(f"[!!] {args.arquivo}: assinatura PE ausente em 0x{pe:x}", file=sys.stderr)
        return 2
    opt = pe + 24
    is64 = u16(opt) == 0x20B
    nsec, osz = u16(pe + 6), u16(pe + 20)
    image_base = int.from_bytes(buf[opt + 24:opt + 32], "little") if is64 else u32(opt + 28)

    secs = []
    for i in range(nsec):
        s = pe + 24 + osz + i * 40
        secs.append({
            "name": buf[s:s + 8].rstrip(b"\0").decode("latin1"),
            "va": u32(s + 12), "vs": u32(s + 8), "raw": u32(s + 20), "rs": u32(s + 16),
        })

    def rva2off(r):
        for s in secs:
            if s["va"] <= r < s["va"] + max(s["vs"], s["rs"]):
                return s["raw"] + (r - s["va"])
        return -1

    def section_of(r):
        for s in secs:
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
        ini, fim = sec["va"], sec["va"] + min(sec["vs"], sec["rs"])
    else:
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

    off_ini, off_fim = rva2off(ini), rva2off(fim)
    if off_ini < 0 or off_fim < 0:
        print(f"[!!] intervalo 0x{ini:x}-0x{fim:x} não é legível no arquivo", file=sys.stderr)
        return 2

    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
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
        print(f"  ImageBase=0x{image_base:x} · intervalo rva 0x{ini:x}..0x{fim:x} · {len(rows)} instrução(ões)")
        print("─" * 70)
        for r in rows:
            note = f"   ; {r['annotation']}" if r["annotation"] else ""
            print(f"  0x{r['rva']:05x}  {r['bytes']:<22} {r['mnemonic']:<8} {r['op_str']}{note}")
        print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())

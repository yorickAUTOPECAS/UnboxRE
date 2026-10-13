# radare2 / rizin
**Licença:** LGPL-3.0 (radare2) · **Status:** a instalar · **Camada:** análise estática

Caminho após bootstrap: `tools/radare2/`

## O que faz

Suíte de linha de comando para RE: disassembly, análise de função, xrefs, strings,
busca de padrões, patching, emulação básica (ESIL), e — o diferencial — **diff de
binários** (`radiff2`). Totalmente scriptável e script-friendly (r2pipe).

## Quando usar

- **Pipelines.** É a ferramenta mais fácil de automatizar: `r2 -q -c '...' bin`.
- **Diff rápido** entre duas versões: `radiff2 -C a b`.
- **Recon em lote** de dezenas de binários (firmware extraído).
- Quando você quer resposta em 2 segundos sem abrir GUI.
- Busca de padrões de bytes (`/x`) e de gadgets (com ROPgadget).

## Quando NÃO usar

- **Como descompilador principal.** O decompilador do r2 (`pdc`) é fraco perto do
  Ghidra. Para pseudocódigo, Ghidra (ou IDA, se você tiver).
- **Como debugger principal no Windows.** O x64dbg é muito superior. r2 debug é ok em
  Linux.
- **Quando você quer GUI.** Use Cutter (GUI do r2) ou Ghidra.
- **Código dentro do seu repo.** LGPL-3.0: chame por **subprocesso** (`r2 -q -c`), não
  linke a lib, para manter seu MIT limpo ([03-licencas.md](../03-licencas.md)).

## Instalação

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile static
# ou manual:
PS> winget install radareorg.radare2      # ou baixe o zip e extraia em tools/radare2/
```

```bash
$ sudo apt install radare2 rizin           # no WSL
```

> **rizin** é o fork da comunidade do radare2 (mesma CLI, governança diferente). Se o
> pacote do seu distro traz rizin, ele serve — os comandos aqui funcionam nos dois.

## Uso — receitas curtas

```bash
# Recon rápido: funções, imports, strings
$ r2 -q -c 'aaa; afl~main; ii; izz~http' work/acme/src/target.exe

# Uma função: disassembly + decompile fraco
$ r2 -q -c 'aaa; s sym.check_license; pdf' work/acme/src/target.exe

# Diff de versões (o Cenário 11 em 10 segundos)
$ radiff2 -C work/acme/src/target-1.0.exe work/acme/src/target-2.1.exe

# Busca de padrão de bytes (ex.: prologue de uma função conhecida)
$ r2 -q -c '/x 4883EC28' work/acme/src/target.exe

# JSON para o pipeline (r2pipe ou -j)
$ r2 -q -j -c 'aaa; aflj' work/acme/src/target.exe > evidence/r2-functions.json
```

Interativo (`r2>`): `aaa` analisa, `afl` lista funções, `pdf` disassembly da função,
`axt` xrefs para, `V` modo visual, `VV` grafo.

## Integração com o resto do setup

- **Ghidra** para profundidade; **r2** para velocidade e lote. Não são exclusivos.
- **radiff2** cobre o Cenário 11 quando você não quer montar projeto Ghidra só para diff.
- **r2pipe** (Python/Node) é o caminho para o pipeline de automação (domínio f).
- Saída `-j` (JSON) alimenta `evidence/` diretamente.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| esquecer `aaa` | análise vazia, `afl` vazio | sempre rode `aaa` (ou `aa`) primeiro |
| confiar em `pdc` | pseudocódigo ruim → conclusão errada | use Ghidra para pseudocódigo |
| linkar a lib LGPL no seu MIT | conflito de licença | chame por subprocesso |
| `radiff2 -C` em binários muito diferentes | resultado ruidoso | compare versões próximas |
| analisar sem base de rebase | endereços não casam com o x64dbg | anote o ImageBase |

## Referências

- `r2 -h`, `r2 -q -c '?*'` (ajuda interna é a melhor doc)
- `docs/02-catalogo-ferramentas.md` §2 (a.1)

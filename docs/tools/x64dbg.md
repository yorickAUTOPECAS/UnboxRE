# x64dbg (snapshot 2026-05-27)
**Licença:** GPL-3.0 — **não redistribuir os binários** no repo MIT ·
**Status:** instalado · **Camada:** núcleo

Caminho: `x64dbg/release/`

## O que faz

Debugger usermode Windows para x32 e x64: stepping (into/over/out), breakpoints
(software INT3, hardware DRx, memória, condicional, exceção), patching em memória,
análise de módulos, script engine própria, e `headless.exe` para automação em CI.

## Quando usar

- Todo cenário **dinâmico** em Windows: achar o OEP, observar checks, inspecionar
  memória viva, capturar a IAT antes do unpack.
- Tracing de API (`TraceInto`/`TraceOver` + log de chamadas) para mapear comportamento.
- Patching rápido para **testar uma hipótese** (não para entregar patch).
- Automação com `headless.exe` em pipeline.

## Quando NÃO usar

- **Kernel.** O x64dbg é usermode. Kernel exige WinDbg + duas máquinas.
- **macOS/Linux/Android.** Use LLDB/GDB/Frida.
- **Como sandbox.** Ele roda na sua máquina real com seus privilégios. Amostra
  desconhecida vai em VM descartável ([08-higiene-e-seguranca.md](../08-higiene-e-seguranca.md)).
- **Contra proteção forte.** Com VMProtect/Themida/anti-debug agressivo, o x64dbg
  sozinho é detectado e o alvo muda de comportamento. Use ScyllaHide/TitanHide **e**
  espere ainda assim ser detectado — proteções comerciais modernas detectam
  hardware breakpoints e timing.

## Instalação / estado

Já presente em `x64dbg/release/`. Dois pontos de atenção da auditoria:

```bash
$ ls x64dbg/release/x96dbg.exe          # launcher (escolhe x32/x64)
$ ls x64dbg/release/x64/x64dbg.exe      # x64 direto
$ ls -d x64dbg/release/*/plugins        # ⚠️ precisa existir para o plugin MCP carregar
```

**G4 do diagnóstico:** se a pasta `plugins/` não existe, o plugin MCP não carrega e o
MCP não sobe. Crie com `mkdir x64dbg/release/x64/plugins` (ou deixe o
`setup-ghidra-extensions`/bootstrap cuidar disso).

## Uso — receitas curtas

**GUI:**

```powershell
PS> .\x64dbg\release\x96dbg.exe          # abre o seletor; escolha o alvo
```

**Headless (automação):**

```bash
$ x64dbg/release/x64/headless.exe -a work/acme/scripts/trace-api.txt
```

**Script engine (receita: log de chamadas a uma API)**

```text
// work/acme/scripts/trace-api.txt
bp CreateFileW
log "CreateFileW chamado"
SetBreakpointCondition CreateFileW, "[[esp+4]]!=0"
run
```

**Receita: dump limpo depois do unpack (via MCP, do agente)**

```text
LoadBinary      work/acme/src/target.exe
RunToAddress    <entrypoint>
StepOver                          // até o salto final do stub
DetectOEP                         // devolve o OEP real
SetBreakpoint   <oep>
run                               // pausa no código original
DumpModule      target_dump.exe   // dump completo com IAT
AnalyzeModule   target_dump.exe   // reconstrói imports no dump
```

> **Ordem obrigatória:** OEP → dump → reparo de IAT. Dump sem IAT abre no Ghidra com
> imports lixo e a análise estática vira ruído.

**Patching responsável:** patche a **cópia** em `unpacked/`, nunca `src/`. Antes de
patchar, anote os bytes originais e o endereço; depois, use `RestorePatches` para voltar
ao estado limpo.

## Integração com o resto do setup

- **Hospeda o x64dbg-MCP** (`plugins/x64dbg-MCP-Server.dp64`) → controle por IA.
- **Complementa o Ghidra:** x64dbg = runtime (endereços reais, valores), Ghidra =
  estrutura (tipos, fluxo). Case pelo `ImageBase` do `AnalyzeModule`.
- **ScyllaHide** entra em `plugins/` e resolve a maioria dos anti-debug triviais.
- **Scylla** (mesma família) entra em `plugins/` para reparo de IAT pós-dump.
- **PE-sieve** roda sobre o processo **em paralelo** ao x64dbg para detectar código
  injetado/hollowed.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| `plugins/` ausente | plugin MCP não carrega, `:9094` não existe | crie a pasta |
| ASLR | endereço do Ghidra ≠ endereço do x64dbg | rebase pela base do módulo |
| anti-debug | alvo morre ou se comporta diferente | ScyllaHide; documente o check |
| 32 vs 64 | não debuga o outro | `x96dbg.exe` escolhe; `headless.exe` tem versões x32/x64 |
| patchar `src/` | alvo corrompido, análise irreproduzível | patche só em `unpacked/` |
| depurar sem snapshot | VM infectada | reverta sempre |

## Referências

- `x64dbg-mcp-server-main/README.md` (catálogo das 72+ tools MCP)
- `docs/05-mcp.md` (como subir e conectar o MCP)
- `docs/06-workflows.md` Cenários 1, 2 e 12 (uso real do debugger)

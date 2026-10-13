# ScyllaHide (+ TitanHide) + Scylla
**Licença:** GPL-3.0 (ScyllaHide, Scylla) / GPL-3.0 (TitanHide) ·
**Status:** a instalar · **Camada:** desobfuscação

Destino: `x64dbg/release/x64/plugins/` (e `x32/plugins/`)

## O que faz

- **ScyllaHide:** plugin de x64dbg que esconde o debugger — limpa o PEB
  (`BeingDebugged`, `NtGlobalFlag`), corrige heap flags, hooka APIs de detecção
  (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`,
  `OutputDebugString`, timing), esconde breakpoints de hardware.
- **TitanHide:** esconde o debugger **no kernel** (driver). Necessário quando a
  proteção consulta o kernel diretamente. Requer instalar um driver → **só em VM**.
- **Scylla:** reparador de IAT pós-dump. Recebe um processo rodando e reconstrói a
  tabela de imports no dump.

## Quando usar

- **Sempre que o alvo detecta o debugger.** Sintoma: o processo morre, entra em loop, ou
  se comporta diferente sob debug.
- **Scylla depois de todo unpack** (Cenário 1) — é o passo que faz o dump virar um
  binário analisável no Ghidra.
- **TitanHide** quando ScyllaHide não basta e a proteção é kernel-aware.

## Quando NÃO usar

- **Esperando invisibilidade total.** Proteções comerciais modernas (VMProtect, Themida)
  detectam hardware breakpoints, timing anômalo, integridade do próprio código e
  anomalias de ambiente. O ScyllaHide resolve o **trivial**, não o sofisticado.
- **TitanHide na máquina de trabalho.** Ele instala um driver de kernel.
- **Como justificativa para não documentar.** Cada check contornado é um **achado**:
  registre em `notes/anti-analysis.md` com o nível de confiança.
- **Em produção.** Estas ferramentas são para laboratório.

## Instalação

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile dynamic
# copia os .dp64/.dp32 para x64dbg/release/{x64,x32}/plugins/
# e o perfil de configuração para x64dbg/release/x64/plugins/ScyllaHide/
```

No x64dbg: **Plugins → ScyllaHide → Options**, escolha o perfil. Perfis prontos:
`VMProtect`, `Themida`, `SafeEngine`, `Obsidium`, `Default`.

## Uso — receitas curtas

**Contornar detecção (fluxo):**

```text
1. Abra o x64dbg com o ScyllaHide ativo (perfil Default)
2. SetExceptionBreakpoint / observe o GetEventLog
3. Se o alvo ainda detectar, mude para o perfil do protetor específico
4. Se detectar no kernel, ative o TitanHide (VM descartável)
5. DOCUMENTE: qual check disparou, onde, e como foi contornado
```

**Reparar a IAT (Scylla, depois do dump):**

```text
1. Processo pausado no OEP (pós-unpack)
2. Abra Scylla (Plugins → Scylla)
3. IAT Autosearch → Get Imports
4. Corrija entradas inválidas manualmente
5. Fix Dump → selecione o dump feito antes
```

## Integração com o resto do setup

- **x64dbg** é o hospedeiro ([x64dbg.md](x64dbg.md)).
- **Cenário 1** (unpack): Scylla é o passo final que torna o dump analisável.
- **Cenário 2** (virtualização): ScyllaHide é o que permite *observar* o alvo protegido.
- **PE-sieve** complementa: detecta código injetado/hollowed que o dump não revela.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| TitanHide na máquina real | driver no sistema | só em VM |
| perfil errado | alvo continua detectando | teste perfis; combine hooks |
| IAT reparada parcialmente | imports lixo no Ghidra | valide abrindo o dump no x64dbg |
| não documentar os checks | perde metade do valor da análise | `notes/anti-analysis.md` |
| GPL-3.0 no repo MIT | conflito | referencie, não redistribua |

## Referências

- `docs/06-workflows.md` Cenários 1 e 2
- `docs/02-catalogo-ferramentas.md` §4 (c.1, c.2)

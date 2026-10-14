# gflags (Global Flags Editor) — Debugging Tools for Windows
**Licença:** `[COMERCIAL]` (grátis) — EULA Microsoft, **não redistribuído** ·
**Status:** a instalar (manual) · **Camada:** diagnóstico do loader

Destino padrão: `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe`

## O que faz

`gflags.exe` é o editor de *Global Flags* do Windows. A flag que interessa aqui é
**`+sls` — “Show loader snaps”** (`FLG_SHOW_LDR_SNAPS = 0x02`): liga a impressão, pelo
próprio loader do `ntdll`, de **cada passo da montagem da imagem** — arquivo mapeado,
seções, imports, relocations, dependências, decisão final.

O que o `gflags /i alvo.exe +sls` faz por baixo é uma escrita de registro:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<imagem>
    GlobalFlag (DWORD)  →  bit 0x2 ligado
```

É a única forma documentada de **ver a decisão do loader** quando um `.exe` morre antes
de chegar ao entrypoint (`0xC000007B`, `0xC0000135`, `0xC0000142`, `0xC0000142`…). Sem
isso só existe o sintoma: o processo não sobe e **nada** dentro dele roda — logo, não há
backtrace, não há log da aplicação, não há artefato. Ver
[../../reports/root-cause-0xc000007b.md](../../reports/root-cause-0xc000007b.md).

## Quando usar

- **Um `.exe` é recusado pelo Windows** (“Este aplicativo não pode ser executado em seu
  PC”) e `scripts/diagnose-load.mjs` já disse *o que* está torto, mas não *qual checagem*
  do `ntdll` disparou.
- Suspeita de **dependência impossível**: arquitetura errada, DLL que não carrega,
  import por ordinal que não existe, delay-import quebrado, `.reloc` inconsistente.
- Um alvo que **só funciona sob debugger** e falha no duplo-clique (ou o inverso, como
  aconteceu neste projeto — ver “armadilhas”).

## Quando NÃO usar

- **Como depurador.** O gflags não depura nada; ele liga a impressão. Quem lê a saída é
  o debugger anexado ao processo novo (`x64dbg`, `WinDbg`) ou um listener do canal
  global `DBWIN_BUFFER` (`scripts/capture-debugprint.ps1`, DebugView).
- **Num processo que já está rodando.** O flag vale para instâncias **novas**.
- **Esperando saída em produção / sem anexar nada.** Sem debugger e sem listener, a
  impressão simplesmente vai para o vazio.
- **Como atalho para entender o alvo.** Loader snaps responde uma pergunta só (“por que
  o loader recusou?”). Lógica de programa, proteção e algoritmo continuam sendo
  análise estática/dinâmica normal.
- **Ligado “para sempre”.** É um valor em `HKLM` que afeta **toda** instância nova do
  processo. Ligue, colete, desligue (`-Disable`).

## Instalação

O gflags **não vem sozinho e não está no winget**. Medido nesta máquina (2026-10-14):

```console
$ winget search "debugging tools"
No package found matching input criteria.          # não existe pacote do componente

$ winget list --id Microsoft.WinDbg --exact --disable-interactivity
Name    Id               Version        Source
WinDbg  Microsoft.WinDbg 1.2610.1001.0  winget    # o WinDbg moderno está instalado…

$ (Get-ChildItem <InstallLocation do pacote WinDbg> -Filter '*.exe').Name -join ', '
createdump.exe, DbgX.Mcp.Proxy.exe, DbgX.Shell.exe, DebuggerCredentialManager.exe
$ Get-ChildItem <InstallLocation> -Filter 'gflags*' -Recurse       # → nada
```

…e **não traz o gflags.exe**. A ferramenta vem com o componente *Debugging Tools for
Windows* do **Windows SDK / WDK** (ou numa instalação avulsa do mesmo componente), e a
documentação da Microsoft diz exatamente isso: “The Debugging Tools for Windows 10
(WinDbg) includes the gflags.exe file”, em
`C:\Program Files (x86)\Windows Kits\10\Debuggers\{x64,x86}`.

Registro para quando for instalar: [Debugging Tools for Windows — download e instalação](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools).

**O caminho que não exige instalar nada** (e o que este projeto usa):

```powershell
PS> .\scripts\load-snaps.ps1 -Image alvo.exe            # dry-run: mostra o plano
PS> .\scripts\load-snaps.ps1 -Image alvo.exe -Status    # só lê o GlobalFlag atual
PS> # em uma janela PowerShell ELEVADA:
PS> .\scripts\load-snaps.ps1 -Image alvo.exe -Apply     # liga o bit 0x2
PS> .\scripts\capture-debugprint.ps1 -Seconds 20 -OutFile work\alvo\evidence\loadsnaps.txt
PS> # … e, nos 20 s seguintes, iniciar o alvo em outra janela
PS> .\scripts\load-snaps.ps1 -Image alvo.exe -Disable -Apply   # desligue depois de coletar
```

`load-snaps.ps1` escreve o **mesmo bit** que o `gflags /i` escreveria. Ele:
exige elevação (escrita em `HKLM`), **nunca se eleva sozinho** (sem `-Apply` é dry-run;
com `-Apply` fora de shell elevado, para com instrução clara) e apaga o valor quando o
flag fica em `0`, em vez de deixar lixo de registro.

## Uso — receitas curtas

**1. Ver a decisão do loader num alvo que não sobe** (fluxo canônico):

```text
1. diagnose-load.mjs alvo.exe            → quais vícios de PE existem (evidência)
2. load-snaps.ps1 -Image alvo.exe -Apply → em shell elevado
3. abrir o alvo no x64dbg (ou WinDbg)    → o debugger é quem RECEBE a saída
4. ler a janela Log do debugger          → as linhas do loader estão lá
5. load-snaps.ps1 -Image alvo.exe -Disable -Apply
6. gravar a saída em evidence/ e interpretar DEPOIS (regra do projeto)
```

O `capture-debugprint.ps1` (listener do canal global) continua útil para
`OutputDebugString` de alvos que não estão sob debugger — e é assim que ele foi validado —
mas, medido nesta máquina, ele **não** é o caminho para ler loader snaps.

**2. O caminho que funciona quando o canal global não vê nada: um debugger.** Medido nesta
máquina (2026-10-14): com o flag ligado e **sem** debugger, os snaps **não aparecem** no
canal global — nem para uma imagem válida (`clean.exe`, control com 0 byte capturado),
enquanto um `OutputDebugString` direto de outro processo **é** capturado pelo mesmo
listener. Com o x64dbg rodando o alvo, os eventos aparecem — mas o log de eventos do MCP
registra `OutputDebugString received` **sem** a string (e o plugin não tem tool que devolva
o log). Ou seja: leia o texto **dentro** do debugger, na janela *Log* do x64dbg ou no
WinDbg. Evidência: `work/iat-hardcase/evidence/20261014-1{1,2,3}-*`.

**3. Com o gflags instalado, linha de comando (equivalência exata):**

```console
> gflags /i alvo.exe +sls            # liga
> gflags /i alvo.exe                 # confere o valor atual
> gflags /i alvo.exe -sls            # desliga
```

## Integração com o resto do setup

- **`scripts/diagnose-load.mjs`** é o passo 1: ele mede os vícios de PE (seções
  esvaziadas, diretório de dados apontando para seção sem bytes, ASLR sem relocations) e
  o status real da execução. O gflags/loader snaps é o passo 2, para quando o diagnóstico
  estático não fecha a conta.
- **`scripts/load-snaps.ps1`** é a versão auditável do `gflags /i`; para a saída, o leitor
  confiável é o **debugger** (janela *Log* do x64dbg / WinDbg). O
  `scripts/capture-debugprint.ps1` lê o canal global e funciona para `OutputDebugString`
  comum, mas nesta máquina **não** recebeu loader snaps (medido — ver receita 2).
- **x64dbg** ([x64dbg.md](x64dbg.md)) e **WinDbg/TTD** ([windbg-ttd.md](windbg-ttd.md))
  são os leitores “de verdade” da saída.
- **`docs/06-workflows.md`** (cenário de unpack/dump) usa isso quando um dump
  reconstruído é recusado — foi exatamente o caso de `reports/unpack-iat-hardcase.md`.

## Limites e armadilhas conhecidas

| Armadilha | Efeito | Correção |
|---|---|---|
| tentar achar `gflags.exe` no pacote do WinDbg | não existe (medido) | instale o componente *Debugging Tools for Windows* do Windows SDK/WDK, ou use `load-snaps.ps1` |
| ligar o flag sem anexar debugger | **nada** aparece no canal global (medido nesta máquina) | abra o alvo no x64dbg/WinDbg e leia a janela *Log* |
| esperar saída de um processo já em execução | nada aparece | o flag vale só para instâncias novas |
| esquecer o flag ligado | toda instância nova do processo imprime lixo no console de depuração | `-Disable -Apply` ao terminar |
| achar que o gflags “conserta” algo | ele não altera a imagem, só a impressão | trate a saída como **evidência**, não como correção |
| não elevar | `load-snaps.ps1 -Apply` recusa com exit 1 | rode num PowerShell elevado (o script nunca se eleva sozinho) |

## Referências

- GFlags (visão geral, Microsoft): <https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags>
- Debugging Tools for Windows — SDK/WDK/avulso: <https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools>
- “O gflags só é instalado quando você seleciona o componente Debugging Tools for Windows”: <https://learn.microsoft.com/en-us/answers/questions/5625362/where-is-gflags-installed>
- Licença (registro do projeto): `config/licenses.json` → `gflags (Debugging Tools for Windows)` (`LicenseRef-Microsoft-SDK-WDK-EULA`, EULA Microsoft — não redistribuído)
- `docs/02-catalogo-ferramentas.md` §3 (b.9)
- `reports/root-cause-0xc000007b.md` · `reports/unpack-iat-hardcase.md` §6

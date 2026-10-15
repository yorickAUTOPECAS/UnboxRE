# Verificação da rodada de fechamento — 2026-10-15

Auditoria **de usuário-zero** (quem nunca viu o repositório e segue só o que está escrito),
README em inglês, página de resultado da sequência — e as correções que a auditoria exigiu,
feitas **antes** de reportar como concluído. Como sempre: cada afirmação abaixo tem comando e
saída reais; o que não funcionou está na §7, sem maquiagem.

| Frente | Estado | Evidência |
|---|---|---|
| Ambiente do zero (`health-check`) | **41 ok · 0 warn · 0 fail** | §1.1 |
| Bootstrap e fetch como a doc manda | dry-run **exit 0**, plano explícito, nada instalado | §1.2 |
| Ponte MCP do REA, manual | `initialize` + `tools/list` → **170 tools** | §1.3 |
| `--help` de cada script do toolkit | **16 `.mjs` + 1 `.py` = exit 0**; `.ps1` documentado (limitação do host) | §2 |
| Links internos dos 49 `.md` | **0 quebrados · 0 âncoras inexistentes** (eram 4 + 2) | §3 |
| `check-consistency.mjs` | **exit 0** — 198 verificações, nenhuma divergência | §6 |
| `verify-licenses.mjs` | **exit 0** — 79 licenças batem com a fonte primária | §6 |
| CI | **4/4 jobs verdes** no commit do fechamento | §6 |

---

## 1. Auditoria de usuário-zero — o caminho que os docs descrevem

### 1.1 O ambiente, do jeito que um usuário novo olha

```console
$ powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\health-check.ps1 -Json
{
    "generatedAt":  "2026-10-15T12:29:50.0124697-03:00",
    "root":  "C:\Users\Admin\Desktop\UnboxRE",
    "summary":  {
                    "ok":  41,
                    "warn":  0,
                    "fail":  0
                },
```

Nada de aviso “só para quem já sabe”: 41 checagens, todas OK, com `-Json` consumível por IA.

### 1.2 Bootstrap e fetch — dry-run primeiro, como o README manda

```console
$ powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\fetch-tools.ps1 -DryRun
  modo:  dry-run (nada será baixado)
  alvos: ghidra, x64dbg, rea, x64dbg-mcp
  [OK  ] Ghidra já instalado (ghidra/*/support/analyzeHeadless.bat)
  [OK  ] x64dbg já instalado (x64dbg/release/x64/x64dbg.exe)
  [OK  ] REA (rea-agents) já instalado (rea-main/scripts/rea.mjs)
  [OK  ] x64dbg-MCP Server já instalado (x64dbg/release/x64/plugins/x64dbg-MCP-Server.dp64)
  instalados/ok: 4   falhas: 0
  Isto foi um DRY-RUN. Rode de novo com -Apply para baixar e instalar.

$ powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1 -Profile core -DryRun
  modo:   dry-run (nada será instalado)
  (… fetch acima …)
  [OK  ] Zig — já instalado (zig)
  [OK  ] CMake — já instalado (cmake)
  [OK  ] Ninja — já instalado (ninja)
  [OK  ] Rust — já instalado (cargo)
  [OK  ] Python 3.12 — já instalado (python)
  [OK  ] Node.js LTS — já instalado (node)
  instalados: 0   já presentes: 6   pendentes/manual: 0
```

O `README.md` antigo mandava rodar o passo 2 **sem `-Apply`** — o que, na leitura de um usuário
novo, parecia instalar e não instalava. O par documentado agora é explícito: `-DryRun` mostra o
plano, `-Apply` age (o script declara os dois, e `-DryRun` ganha se os dois vierem).

### 1.3 A Ponte MCP do REA, subida à mão (o CI faz isso automatizado)

```console
$ node .\scripts\smoke-mcp.mjs

UnboxRE — smoke test do MCP (stdio)
  entrada: C:\Users\Admin\Desktop\UnboxRE\rea-main\scripts\rea.mjs
  initialize → serverInfo: {"name":"rea","version":"6.4.0"}
  tools/list  → 170 ferramentas (ex.: annotate_native_function, inspect_native_load_image, inspect_native_data_type)

  [OK] a ponte MCP sobe e responde a uma chamada real.
```

Um humano reproduz sem ajuda: um comando, sem variável de ambiente a adivinhar e sem caminho
fixo de máquina no meio.

---

## 2. `--help` de cada script do toolkit (o que a doc promete × o que sai)

Depois da correção (§4), todos os leitores saem **0** pedindo ajuda:

```console
$ for f in scripts/*.mjs; do node "$f" --help >/dev/null 2>&1; echo "$f exit=$?"; done
scripts/check-consistency.mjs      --help exit=0
scripts/diagnose-load.mjs          --help exit=0
scripts/gen-mcp-config.mjs         --help exit=0
scripts/identify-protections.mjs   --help exit=0      ← saía 2 antes (§4.1)
scripts/make-packed-sample.mjs     --help exit=0
scripts/mcp-x64dbg-smoke.mjs       --help exit=0
scripts/pe-read.mjs                --help exit=0
scripts/rebuild-iat.mjs            --help exit=0
scripts/reset-load-state.mjs       --help exit=0
scripts/smoke-mcp.mjs              --help exit=0
scripts/triage-archive.mjs         --help exit=0
scripts/triage-java.mjs            --help exit=0
scripts/triage-static.mjs          --help exit=0
scripts/verify-dump.mjs            --help exit=0
scripts/verify-licenses.mjs        --help exit=0
scripts/x64dbg-drive.mjs           --help exit=0
scripts/disasm-range.py            --help exit=0
```

As flags que esses textos prometem batem com `scripts/README.md` e `docs/06-workflows.md`
(a checagem mecânica disso é a §6 — `check-consistency.mjs` percorre comando × script × perfil ×
cliente de MCP).

**Os `.ps1` são outra história, e é limitação do host — não dos nossos arquivos.** Medido:

| Caminho | Resultado medido |
|---|---|
| `Get-Help .\scripts\<script>.ps1` | `HelpNotFound` em **todos** os `.ps1` — e igual para um script **mínimo de controle** (`<# .SYNOPSIS #>` + `param()`), então nada que a gente escreva conserta |
| `.\scripts\<script>.ps1 -?` | sai **mudo** (exit 0, sem texto) |
| `.\scripts\<script>.ps1 -Help` | rejeitado como parâmetro inexistente |
| `Get-Content scripts\<script>.ps1 -TotalCount 60` | **funciona** — 7 linhas de ajuda em `new-case.ps1`, 5 em `health-check.ps1`, 6 em `fetch-tools.ps1` |
| `pwsh` (PowerShell 7) | **não instalado** neste host — não dá para afirmar que resolveria |

Por isso o caminho documentado passou a ser o bloco de cabeçalho, com a limitação escrita em
`scripts/README.md` e no `README.md` (para ninguém concluir “script sem documentação”).

**Achado colateral, que vale para agentes:** rodar um `.ps1` **sem os parâmetros obrigatórios**
num terminal interativo **não falha — ele pede o valor e fica esperando** (medido: um comando de
auditoria estourou 240 s de timeout por isso). Em CI/agente, sempre passe os parâmetros.

---

## 3. Links internos: 176 links, 49 arquivos — e o que estava quebrado

Auditoria mecânica própria (extrai `[texto](destino)`, resolve relativo ao arquivo, confere
existência **e** âncora). Antes das correções:

```console
$ python work/audit-final-20261015/link-audit.py
arquivos .md versionados: 49 · links internos verificados: 180

[1] LINKS QUEBRADOS (4):
docs/02-catalogo-ferramentas.md:83  ->  ../rea-main/docs/windows-ghidra-p0.md
docs/05-mcp.md:104                  ->  ../x64dbg-mcp-server-main/README.md
docs/05-mcp.md:163                  ->  ../rea-main/docs/windows-ghidra-p0.md
reports/auditoria-licencas.md:76    ->  src/Fluxzy.Core/LICENSE.md

[2] ANCORAS INEXISTENTES (2):
README.md:173             ->  reports/round-8-6-nivel-6.5.md#L244-L257
docs/06-workflows.md:446  ->  02-catalogo-ferramentas.md#5-domínio-e-formatos
```

Triagem de cada um — dois eram **defeito de verdade**, e não só “link relativo”:

- `rea-main/docs/windows-ghidra-p0.md` — **não existe em lugar nenhum da máquina preparada**: o
  pacote npm do REA não traz `docs/` (medido: `ls rea-main/docs` → *No such file or directory*;
  `rea-main/README.md:177` aponta para esse caminho e o link morre **dentro do próprio pacote**).
  Mesma coisa para `docs/evm-bytecode.md` (`docs/02:549`).
- `x64dbg-mcp-server-main/README.md` — o diretório **nunca é clonado**: o plugin vem de release
  pré-compilado (`x64dbg/release/x64/plugins/x64dbg-MCP-Server.dp64`; não há fonte em
  `x64dbg-mcp-server-main/`, que é o nome que a doc citava).

Os dois passaram a apontar para a **fonte primária no upstream**, verificada por HTTP 200 nesta
rodada: `morluto/rea/docs/windows-ghidra-p0.md`, `morluto/rea/docs/evm-bytecode.md` e
`duty1g/x64dbg-mcp-server` — com a frase honesta de que o pacote instalado não os traz.

Os outros dois eram defeitos menores de destino: `src/Fluxzy.Core/LICENSE.md` era **texto de
licença citado dentro de bloco de código** (falso positivo do meu auditor — corrigido o auditor,
que agora respeita blocos cercados) e a âncora de `docs/06` apontava para um título que não existe
(o real é `## 5. Domínio (d) — Formatos e plataformas`). No `README.md` novo, a âncora virou a
seção correta do relatório (§5.1), em vez de faixa de linhas.

Depois das correções:

```console
$ python work/audit-final-20261015/link-audit.py
arquivos .md versionados: 49 · links internos verificados: 176

[1] LINKS QUEBRADOS (0):
    nenhum ✔

[2] ANCORAS INEXISTENTES (0):
    nenhuma ✔
```

O relatório do auditor também lista 14 caminhos em crase que não existem — **triados um a um e
mantidos de propósito** (§7.3): são `docs/02` (apelido da família), nomes de exemplo em tabela de
convenção, scripts **do caso** (`work/<alvo>/scripts/…`, que a doc já explica), e linhas de comando
capturadas com as flags junto.

---

## 4. O que a auditoria corrigiu (e por quê)

| # | Onde | O que estava errado para um usuário novo | Correção |
|---|---|---|---|
| 4.1 | `scripts/identify-protections.mjs` | `--help` (e rodar sem argumento) saía **2** — quem encadeia script lê 2 como “não consegui ler o arquivo”, então pedir ajuda parecia erro | passa a sair **0** com texto de uso, como os 16 irmãos `.mjs` |
| 4.2 | `scripts/README.md` | nenhum lugar dizia como ver o uso de um `.ps1`, e `Get-Help` está quebrado neste host | seção nova “Como ver o uso de um script”, com a limitação **medida** (inclusive o controle mínimo) e o caminho que funciona |
| 4.3 | `README.md` (novo) | o exemplo do passo 2 do bootstrap não instalava (faltava `-Apply`) e havia caminho fixo de uma máquina | `-DryRun` + `-Apply` explícitos; caminhos genéricos (`<raiz-do-toolkit>`), com exemplos **rodados** nesta rodada |
| 4.4 | `docs/02`, `docs/05` | link relativo para `rea-main/docs/…` e `x64dbg-mcp-server-main/` — arquivos que não existem na máquina preparada | apontam para a fonte primária no upstream, verificada; dito o que o pacote não traz |
| 4.5 | `docs/06`, `reports/unpack-iat-hardcase.md` | âncora para título inexistente; e um bloco copiável chamava `./scripts/run-and-probe.ps1` (script **do caso**) como se fosse do toolkit | âncora corrigida; caminho virou `work/iat-hardcase/scripts/…` com a marca “script DO CASO” |
| 4.6 | `docs/02`, `docs/05` | exemplos de config MCP com o caminho absoluto desta máquina no meio | `<raiz-do-toolkit>` no template |

---

## 5. Entregáveis desta rodada

- **`README.md` em inglês**, inteiro: o que é (1 parágrafo), requisitos, quick start verificado,
  layout, **4 exemplos de execução real** (triagem de packer com força de evidência, leitura de um
  endereço, triagem de JAR com DLL nativa, diagnóstico de loader), seção de **prompts para agente**
  (estático, container/JVM, dinâmico, verificação) e a nota declarando que `docs/` segue em pt-BR
  de propósito.
- **`reports/sequencia-nivel-1-a-6.5.md`**: uma página, uma linha por alvo — o que exigiu, o que
  entrou no toolkit por causa dele, o que ficou aberto — para quem não vai ler seis relatórios.
- Correções da §4 e este relatório.

---

## 6. Verificação final (comando → saída)

```console
$ node scripts/check-consistency.mjs
  núcleo: 4 · catálogo: 31 · perfis: 13 · flags MCP: 9
  licenças com linha verificada: 28/31 do bootstrap · registradas: 79
  [OK] nenhuma divergência encontrada (198 verificações).
exit=0

$ node scripts/verify-licenses.mjs
  (…) 79 licenças declaradas contra a fonte primária
  [OK] 79 licenças declaradas batem com a fonte primária.
exit=0

$ powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\health-check.ps1 -Json
  "ok": 41, "warn": 0, "fail": 0
```

CI do commit de conteúdo (`c2ab5da`) — **4/4 jobs verdes**:

```console
$ gh run view 38763144715
✓ main CI · 38763144715
✓ Scan de segredos e binários in 13s
✓ Documentação e estrutura in 18s
✓ Licenças contra a fonte primária in 1m7s
✓ Ponte MCP do REA sobe e responde in 16s
```

`https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38763144715`

---

## 7. O que NÃO fechou, e o que continua em aberto (sem maquiagem)

### 7.1 Não fecha neste host (limitação medida, não contornada)

- **`Get-Help` em `.ps1`**: `HelpNotFound` em todos — inclusive no script mínimo de controle — e
  `-?` sai mudo. Não é defeito dos nossos arquivos e não há como consertar por documentação
  de comentário. O que a rodada fez foi **parar de prometer** o que não funciona: o caminho
  documentado passou a ser o bloco de cabeçalho (`Get-Content … -TotalCount 60`), que foi medido
  funcionando nos 3 scripts testados.
- **`pwsh` (PowerShell 7) não está instalado**: então “instale o PowerShell 7 e o `Get-Help`
  volta” fica como hipótese, não como afirmação.
- **`.ps1` sem parâmetro obrigatório trava em terminal interativo** (pede o valor). Para agente e
  CI: sempre passar parâmetros. Não mudei esse comportamento — ele é do PowerShell, e a mensagem
  de erro existe quando a entrada não é interativa.

### 7.2 `verify-licenses.mjs` com a API do GitHub bloqueada

O check passou (exit 0), mas parte das linhas conferiu pela **fonte bruta** (`raw:ok`) porque a API
de licenças respondeu **HTTP 403** nesta rodada para vários projetos (rate limit do IP).
Isso não afrouxa a verificação — a comparação é contra o texto da licença no upstream — mas está
registrado porque o log mostra `api:n/a` e alguém poderia ler como falha.

### 7.3 Os 14 “caminhos que não existem” que ficaram **de propósito**

O auditor também lista caminhos em crase que não resolvem no disco. Triados um a um:

| Caso | Exemplo | Por que fica |
|---|---|---|
| Apelido da família de docs | `docs/02`, `docs/06` | significa “o doc 02/06”, não um arquivo |
| Nome de **exemplo** em tabela de convenção | `reports/acme-cad-static-overview.md` | é o exemplo da regra de nome, não um arquivo do repo |
| Script **do caso** | `scripts/run-and-probe.ps1`, `solve-vm.py`, `x.py`, `diff-dump.py` | a doc diz que scripts de alvo vivem em `work/<alvo>/scripts/`; são o registro do que aquela rodada usou |
| Linha de comando capturada com flags | `scripts/start-x64dbg.ps1 -Check` | o padrão pegou a linha inteira; o arquivo existe |

Nenhum deles é link markdown (os links estão em 0/0), então nenhum quebra no GitHub.

### 7.4 O que esta rodada **não** re-exercitou (e por quê)

- **`fetch-tools.ps1 -Apply` / `bootstrap -Apply` a partir de um clone vazio**: nesta máquina os 4
  itens do núcleo e as 6 dependências **já estavam instalados**, então o que foi medido é o
  **plano** (dry-run, exit 0, 4/4 e 6/6) e o estado instalado — não o download do zero. É
  exatamente o limite desta evidência: o caminho “baixar” não foi exercido hoje.
- **Ponte do x64dbg ao vivo** (HTTP, dentro do processo): não foi re-subida nesta rodada — abrir o
  debugger para provar o handshake é evidência das rodadas 8.x e de
  [verification-2026-10-14.md](verification-2026-10-14.md); o que esta rodada confirmou foi a
  ponte do **REA** (stdio), pelo comando da §1.3.
- **GUI Ghidra/x64dbg**: fora do escopo de uma rodada de documentação/auditoria.

### 7.5 Artefato da própria auditoria

Os instrumentos da auditoria (auditor de links, coleta de saídas) ficaram em
`work/audit-final-20261015/` — **não versionados**, como manda a regra da casa. Um detalhe do
host: o console aqui usa cp1252, então o auditor precisa de `PYTHONIOENCODING=utf-8` para imprimir
`✔`; sem isso ele imprime até a §2 e estoura no símbolo. É limitação do **instrumento**, não do
toolkit.

---

## 8. Como citar isto

Cada número acima veio de um comando desta rodada, e os artefatos brutos estão em
`work/audit-final-20261015/` (`health.json`, `help-after.txt`, `link-audit.txt`, `mcpsmoke.txt`,
`fetch-plan.txt`, `bootstrap-plan.txt`, `exemplos/`). Para repetir: rode os mesmos comandos —
dry-run não muda nada no disco e `--help` não toca em alvo nenhum.

Run que inclui **este relatório** (`0facd44`) — também **4/4 verdes**:

```console
$ gh run view 38763593399 --json status,conclusion,jobs
{"status":"completed","conclusion":"success",
 "jobs":[{"conclusion":"success","name":"Documentação e estrutura"},
         {"conclusion":"success","name":"Licenças contra a fonte primária"},
         {"conclusion":"success","name":"Ponte MCP do REA sobe e responde"},
         {"conclusion":"success","name":"Scan de segredos e binários"}]}
```

`https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38763593399`

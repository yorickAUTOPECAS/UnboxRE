# AGENTS.md — como operar o UnboxRE

Este arquivo é para **qualquer agente de IA (ou humano novo) que acabou de clonar o
repositório**. Ele diz o que o projeto é, o que é inegociável, onde as coisas ficam e
como provar que algo funciona — sem precisar de explicação manual.

## O que é o UnboxRE

Um **toolkit de engenharia reversa com o Windows como escopo validado**, feito para ser
operado por uma IA com evidência rastreável. Ele **não** redistribui as ferramentas de
terceiros: ele as baixa do upstream (`fetch-tools.ps1`), declara a licença de cada uma
(`config/tools.json`, `config/licenses.json`) e deixa o material de alvo fora do Git.

- Licença do próprio projeto: **MIT** ([LICENSE](LICENSE)).
- Escopo validado: **Windows 10/11** (x64). Linux/WSL e macOS são **roadmap**, não
  suportados nesta rodada — não descreva como "funciona" o que não foi exercitado.
- Índice da documentação: [README.md](README.md) → `docs/00` a `docs/08` + `docs/tools/`.

## Regras inegociáveis

1. **Nada de terceiros/alvo no Git.** `work/`, `ghidra/`, `x64dbg/`, `rea-main/`,
   `.cache/`, `config/env/unboxre.env` são gitignored — e o CI tem uma barreira que
   falha se um binário de terceiro ou arquivo sensível for rastreado. Nunca "conserte"
   isso adicionando ao git.
2. **Nunca `sudo`/elevação** por conta própria. Se um instalador exigir, ele mesmo pede.
3. **Dry-run primeiro.** Os scripts mostram o plano e só agem com `-Apply`/`--apply`.
4. **Evidência antes de interpretação.** Grave o artefato (`evidence/`, `unpacked/`,
   `captures/`) e só depois escreva a conclusão em `notes/`. Sem isso, nenhuma conclusão
   é reproduzível. Ver [docs/06-workflows.md](docs/06-workflows.md).
5. **Toda afirmação de licença vem da fonte primária**, nunca de memória — o job
   `licenses` do CI revalida contra o upstream e reprova quem divergir.

## Mapa do repositório

```
docs/                 documentação (00-diagnostico … 08-higiene, tools/ por ferramenta)
scripts/              automação — mapa completo em scripts/README.md
config/               tools.json (manifesto do núcleo), licenses.json (SPDX verificado),
                      mcp/ (templates), env/ (exemplo de variáveis)
reports/              evidência de verificação (o que foi REALMENTE medido)
work/<alvo>/          alvo em análise — src/ unpacked/ notes/ scripts/ captures/ evidence/
.github/workflows/    CI: validate · licenses · mcp-smoke · secrets
```

## Comandos que importam

```powershell
# 1. O que falta nesta máquina?
.\scripts\health-check.ps1 -Json          # {ok,warn,fail}

# 2. Traga o núcleo de terceiros (clone limpo não traz ghidra/, x64dbg/, rea-main/)
.\scripts\fetch-tools.ps1                 # plano
.\scripts\fetch-tools.ps1 -Apply

# 3. Checagens offline (rodam no CI, exit 0 quando tudo bate)
node scripts/check-consistency.mjs        # docs <-> código <-> licenças
node scripts/verify-licenses.mjs          # (rede) licença vs fonte primária
node scripts/gen-mcp-config.mjs --list --json

# 4. Triagem e diagnóstico de um alvo
node scripts/identify-protections.mjs <alvo.exe>   # "está protegido? com o quê?"
node scripts/diagnose-load.mjs <alvo.exe>          # "por que ele não carrega? (0xC000007B)"

# 5. Dinâmico (Windows, GUI)
.\scripts\start-x64dbg.ps1 -Check         # sobe o x64dbg e prova o MCP ao vivo
node scripts/smoke-mcp.mjs                # handshake do MCP do REA (stdio)
```

## Contrato de artefatos (resumo)

Cada alvo vive em `work/<alvo>/`; `new-case.ps1` cria a árvore e o intake com hash.
O fluxo canônico é **hash → triagem → estático/dinâmico → síntese**, e cada transição
grava o artefato antes da interpretação. Detalhes e os 12 cenários:
[docs/06-workflows.md](docs/06-workflows.md).

## Armadilhas já pagas (não repita)

- **`-Tool a,b` sob `powershell -File`** chega como uma única string — o `fetch-tools.ps1`
  já separa a vírgula; use a forma documentada.
- **O token do MCP do x64dbg** é gravado ao lado do `x64dbg.exe`
  (`x64dbg/release/<arch>/mcp_config.json`), não na raiz `x64dbg/`.
- **`tar` do Git for Windows** lê `C:\…` como host remoto — a extração do REA usa isso
  contornado; veja o histórico do `fetch-tools`.
- **`0xC000007B`** numa amostra protegida é o **loader** rejeitando a imagem, não a
  virtualização da máquina. Rode `diagnose-load.mjs` antes de investigar hardware:
  [reports/root-cause-0xc000007b.md](reports/root-cause-0xc000007b.md).
- **Não escreva `sudo`/elevação** em scripts nem em relatórios.

## Como provar que algo funciona

`reports/verification-2026-10-13.md` é o modelo: cada afirmação tem **comando + saída**,
e o que **não** funcionou fica numa seção separada. Ao terminar uma rodada, **commite e
empurre antes de reportar como concluído** — sem isso nada pode ser auditado de forma
independente, e limitações reportadas com honestidade valem mais que sucesso narrado.

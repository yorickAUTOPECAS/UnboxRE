# 01 — Arquitetura e organização

## 1. Estrutura de diretórios

```
UnboxRE/                          # raiz do monorepo
│
├── README.md                      # porta de entrada
├── LICENSE                        # MIT (código próprio)
├── .gitignore                     # bloqueia binários, amostras, segredos
│
├── docs/                          # toda a documentação (a entrega mais importante)
│   ├── 00-diagnostico.md
│   ├── 01-arquitetura.md          # ← você está aqui
│   ├── 02-catalogo-ferramentas.md
│   ├── 03-licencas.md
│   ├── 04-instalacao.md
│   ├── 05-mcp.md
│   ├── 06-workflows.md
│   ├── 07-operacao-por-ia.md
│   ├── 08-higiene-e-seguranca.md
│   └── tools/                     # uma ficha por ferramenta central
│
├── scripts/                       # automação (idempotente, dry-run por padrão)
│   ├── health-check.ps1           # diagnóstico (PS 5.1 e 7)
│   ├── health-check.sh            # diagnóstico (Git Bash)
│   ├── bootstrap-windows.ps1      # install por perfil
│   ├── bootstrap-wsl.sh           # provisiona Ubuntu no WSL
│   ├── re-build.ps1               # compila componentes locais
│   ├── setup-ghidra-extensions.ps1
│   ├── gen-mcp-config.mjs         # gera/valida configs MCP
│   └── lib/                       # helpers compartilhados
│
├── config/
│   ├── mcp/                       # templates de configuração MCP por cliente
│   └── env/
│       └── unboxre.env.example   # todas as variáveis de ambiente suportadas
│
├── tools/<nome>/                  # FERRAMENTAS NOVAS instaladas pelo bootstrap
│                                  # (cada uma com seu próprio .gitignore interno)
├── work/<alvo>/                   # área de trabalho por alvo (fora do Git)
│   ├── src/         binário original + hash
│   ├── unpacked/    dump pós-unpack
│   ├── notes/       notas, pseudocódigo extraído
│   ├── scripts/     scripts Ghidra/x64dbg/r2 daquele alvo
│   ├── captures/    pcaps, HAR, traces
│   └── evidence/    evidência estruturada (JSON)
└── reports/                       # relatórios consolidados (.md/.json) versionáveis
```

### Por que essa divisão

- **`docs/` fora das ferramentas.** A doc precisa sobreviver a upgrades de
  ferramenta. Fichas por ferramenta ficam em `docs/tools/`, não dentro de
  `tools/<nome>/`, para não serem apagadas por um `rm -rf` de atualização.
- **`work/` fora do Git.** Amostras de software comercial e dumps de memória
  **não podem** ser publicados. O `.gitignore` cobre `work/*` e `reports/*.raw`.
- **`tools/` isolado.** Cada ferramenta recebe seu diretório; evita colisão de DLLs
  e permite remover uma ferramenta com `rm -rf tools/<nome>`.

---

## 2. Convenções de nomeação

| Tipo | Convenção | Exemplo |
|---|---|---|
| Diretório de ferramenta | `kebab-case`, sem versão no nome | `tools/radare2/`, `tools/pe-sieve/` |
| Script de automação | `verbo-substantivo.{ps1,sh,mjs}` | `bootstrap-windows.ps1`, `gen-mcp-config.mjs` |
| Documento | `NN-tema.md`, dois dígitos | `05-mcp.md` |
| Ficha de ferramenta | `docs/tools/<ferramenta>.md` | `docs/tools/ghidra.md` |
| Projeto de análise | `work/<slug-do-alvo>[-<versão>]/` | `work/acme-cad-2026.4/` |
| Evidência | `evidence/<AAAAMMDD>-<ação>-<seq>.json` | `evidence/20261013-ghidra-decompile-001.json` |
| Script de alvo (Ghidra) | `work/<alvo>/scripts/<Funcao>.java` (PascalCase, exigência do Ghidra) | `ExportPseudocode.java` |
| Script de alvo (Python) | `work/<alvo>/scripts/<funcao>.py` (snake_case) | `find_license_check.py` |
| Variável de ambiente | `UNBOXRE_*` (próprias) ou nome nativo da ferramenta | `UNBOXRE_WORKSPACE`, `GHIDRA_INSTALL_DIR` |
| Relatório | `reports/<alvo>-<tema>.md` | `reports/acme-cad-static-overview.md` |

Regra de ouro: **nomes de terceiros nunca são renomeados** (`GHIDRA_INSTALL_DIR`,
`JAVA_HOME`, `REA_*`). Adaptamos nós, não eles.

---

## 3. Por que não movemos os diretórios existentes

Você poderia esperar `vendor/ghidra/`, `vendor/x64dbg/`. Optamos por **não mover**:

1. **`rea-main/` é um checkout Git com submódulos.** Mover o diretório muda os
   caminhos registrados em `.git/modules`; um `git submodule update` depois do
   movimento pode reconstruir caminhos errados. Risco real, ganho cosmético zero.
2. **Caminhos absolutos já gravados.** Configurações de MCP, `GHIDRA_INSTALL_DIR` e
   perfis de cliente apontam para os caminhos atuais. Mover invalida todos de uma vez.
3. **Custo de falha assimétrico.** Mover errado quebra um setup que hoje funciona;
   não mover não quebra nada.

Se você *quiser* a raiz limpa, o caminho seguro é documentado e reversível:

```powershell
# Só depois de fechar Ghidra/x64dbg/agentes. Não faça isso com processo ativo.
Move-Item ghidra, x64dbg, rea-main, x64dbg-mcp-server-main .\vendor\
# então repare os caminhos:  scripts\health-check.ps1 -Fix-Paths
```

Por padrão **novas** ferramentas vão para `tools/`, mantendo a distinção entre
"o que veio antes" e "o que o bootstrap instalou".

---

## 4. Fluxo de trabalho canônico

```
   ┌────────────┐
   │  1. INTAKE │  registrar alvo, hash, origem, licença de uso
   └─────┬──────┘  → work/<alvo>/src/ + work/<alvo>/notes/intake.md
         │
   ┌─────▼──────────────┐
   │  2. TRIAGEM        │  detecção de formato, packer, compilador, entropia
   └─────┬──────────────┘  ghidra? radare2? DIE? binwalk?
         │                 produto: work/<alvo>/notes/triage.md
   ┌─────▼──────────────┐
   │  3. DESEMPACOTAR   │  se empacotado: OEP (x64dbg DetectOEP / Scylla)
   └─────┬──────────────┘  produto: work/<alvo>/unpacked/<alvo>.exe
         │
   ┌─────▼──────────────┐
   │  4. ESTÁTICA       │  Ghidra (headless p/ lote, GUI p/ explorar)
   └─────┬──────────────┘  produto: pseudocódigo + mapa de funções
         │
   ┌─────▼──────────────┐
   │  5. DINÂMICA       │  x64dbg (MCP) + Frida/DBI + TTD
   └─────┬──────────────┘  produto: traces, valores observados
         │
   ┌─────▼──────────────┐
   │  6. REDE/IO        │  mitmproxy/tshark se houver tráfego
   └─────┬──────────────┘  produto: captures/ + protocolo documentado
         │
   ┌─────▼──────────────┐
   │  7. RECONSTRUÇÃO   │  spec comportamental → sua implementação
   └─────┬──────────────┘  produto: reports/<alvo>-spec.md
         │
   ┌─────▼──────────────┐
   │  8. EVIDÊNCIA      │  consolidar: o que foi observado vs. inferido
   └────────────────────┘
```

**Regra de ouro da operação por IA:** cada passo 2–7 escreve um artefato em disco.
Se um passo não deixou artefato, ele não aconteceu. Isso é o que permite retomar
uma análise dias depois (e é o que o REA chama de *Evidence*).

---

## 5. Contrato de artefatos por passo

| Passo | Artefato obrigatório | Formato mínimo |
|---|---|---|
| 1 Intake | `work/<alvo>/notes/intake.md` | origem, licença de uso, SHA-256, tamanho, data |
| 2 Triagem | `work/<alvo>/notes/triage.md` | formato, arquitetura, compilador/linguagem, packer, entropia por seção |
| 3 Unpack | `work/<alvo>/unpacked/` + `notes/unpack.md` | método, OEP, IAT reconstruída (sim/não) |
| 4 Estática | `work/<alvo>/notes/static.md` + `evidence/*.json` | top-N funções, xrefs, strings relevantes |
| 5 Dinâmica | `work/<alvo>/notes/dynamic.md` + `captures/*` | comandos executados, endereços, valores observados |
| 6 Rede | `work/<alvo>/captures/` + `notes/network.md` | endpoints, formato, se TLS foi interceptado |
| 7 Recon | `reports/<alvo>-spec.md` | comportamento observado por feature, com nível de confiança |
| 8 Evidência | `reports/<alvo>-evidence.json` | `observed` vs `inferred` separados |

---

## 6. Portas, sockets e recursos

| Recurso | Porta/path padrão | Observação |
|---|---|---|
| x64dbg-MCP (x64) | `9094` | HTTP + Bearer token em `mcp_config.json` |
| x64dbg-MCP (x32) | `9095` | idem |
| Ghidra GUI | `~/.ghidra` | projeto em `work/<alvo>/ghidra-proj/` |
| Ghidra Server (opcional) | `13100` | só para análise multi-usuário |
| REA MCP | stdio | sem porta |
| mitmproxy | `8080` | proxy; certificado em `~/.mitmproxy` |
| Frida | `27042` | `frida-server` em alvo Android |

Todos os servidores MCP escutam em **loopback** por padrão. Se precisar expor
(container, VM), exija o token e o firewall — nunca `0.0.0.0` sem token.
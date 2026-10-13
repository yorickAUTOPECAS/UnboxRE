# UnboxRE — Toolkit de Engenharia Reversa operado por IA

Monorepo de ferramentas, documentação e automação para **engenharia reversa de software**
(análise estática, dinâmica, desobfuscação, formatos de binário, rede e fuzzing),
com foco em **operação por LLM/agentes** através de CLI e MCP.

> **Contexto declarado de uso:** análise competitiva de software comercial e pesquisa
> técnica, para reimplementação própria. Ver [docs/03-licencas.md](docs/03-licencas.md)
> e a seção [Escopo e limites](#escopo-e-limites) antes de operar.

---

## 1. Mapa rápido do stack

O ambiente roda em **dois terrenos**, e saber qual usar resolve 80% das dúvidas:

| Terreno | O que cobre | Por que |
|---|---|---|
| **Host Windows** (`C:\Users\Admin\Desktop\UnboxRE`) | PE/PE+, .NET/IL, drivers, kernel Windows, processos vivos, GUI (Ghidra/x64dbg), MCP servers | A maioria dos alvos comerciais de desktop é Windows; debug usermode+kernel e DBI maduros só existem aqui |
| **WSL2 Ubuntu 24.04** (a instalar — ver bootstrap) | ELF, Android/APK, firmware/IoT, fuzzing (AFL++), angr/Qiling, símbolos DWARF, toolchain nativa | Metade das ferramentas de RE é Linux-only, e o ecossistema de build/emulação é muito melhor |

```
                    ┌──────────────────── LLM / Agente ────────────────────┐
                    │  Claude Code · Codex · Cursor · OpenCode · Gemini …  │
                    └───────┬──────────────┬───────────────┬───────────────┘
                            │ MCP (stdio)  │ MCP (HTTP)    │ MCP (stdio)
                    ┌───────▼───────┐ ┌────▼──────────┐ ┌──▼────────────┐
                    │  REA (bridge) │ │ x64dbg-MCP    │ │ r2 / IDA /    │
                    │  ghidra/ida/  │ │ (in-process   │ │ GhidraMCP …   │
                    │  jeb/hopper   │ │  no x64dbg)   │ │               │
                    └───────┬───────┘ └────┬──────────┘ └──┬────────────┘
                            │              │               │
              ┌─────────────▼──┐   ┌───────▼───────┐  ┌────▼─────────────┐
              │ Ghidra 12.1.4  │   │ x64dbg 2026.05│  │ radare2 / IDA    │
              │ + JDK 27       │   │ + plugins     │  │ Free / JEB       │
              │ (estático)     │   │ (dinâmico)    │  │ (estático)       │
              └────────────────┘   └───────────────┘  └──────────────────┘
                            │              │
              ┌─────────────▼──────────────▼──────────────────────────────┐
              │  Frida · DynamoRIO · TinyInst · Qiling · WinDbg/TTD       │
              │  Unicorn · Speakeasy · VM/Windows Sandbox (isolamento)    │
              └───────────────────────────────────────────────────────────┘
              ┌───────────────────────────────────────────────────────────┐
              │  mitmproxy · Wireshark/tshark · Kaitai · boofuzz · AFL++   │
              └───────────────────────────────────────────────────────────┘
```

---

## 2. Estado atual (auditado em 2026-10-13)

| Ferramenta | Versão instalada | Estado | Observação |
|---|---|---|---|
| Ghidra | 12.1.4 PUBLIC (build 20260921) | ✅ funcional | `analyzeHeadless` executa |
| JDK | 27 (Oracle) em `ghidra/jdk-27` | ⚠️ funciona, mas | Ghidra 12.1.4 só exige `>=21` e **não fixa máximo** — ok, porém JDK 21 LTS é o alvo *verificado* pelos fornecedores (REA) |
| x64dbg | snapshot 2026-05-27 (`9c8ca1c`) | ✅ funcional | falta a pasta `plugins/` para os addons |
| REA (`rea-main`) | 6.4.0, **fonte sem build** | ❌ não instalado | sem `node_modules`, `dist`, submodules vazios |
| x64dbg-MCP Server | 1.0.0, **fonte sem build** | ❌ não compilado | requer **Zig ≥0.14 (ausente)** |
| Toolchain auxiliar | — | ❌ ausente | sem `zig`, `7z`, `cmake`, `clang/gcc`, sem distro WSL |

Detalhes, causa-raiz e plano de correção: **[docs/00-diagnostico.md](docs/00-diagnostico.md)**.

---

## 3. Comece aqui (3 comandos)

```powershell
# 1) Verificar o estado real do ambiente (somente leitura, não instala nada)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\health-check.ps1

# 2) Instalar/atualizar dependências (dry-run primeiro!)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1 -Profile core

# 3) Gerar as configurações MCP para os clientes de IA
node .\scripts\gen-mcp-config.mjs --client vscode --check
```

Em Git Bash, o health check equivalente é `bash scripts/health-check.sh`.

| Perfil do bootstrap | Conteúdo | Tempo aproximado |
|---|---|---|
| `core` | Corrige os 4 itens quebrados do setup atual (REA, MCP, plugins, Zig) | ~10 min |
| `static` | + radare2/rizin, LIEF, capstone, YARA, DIE, ghidriff, ImHex | ~15 min |
| `dynamic` | + Frida, DynamoRIO, WinDbg/TTD, ScyllaHide, PE-sieve, Moneta, Sysinternals | ~15 min |
| `formats` | + Android (jadx/apktool), .NET (dnSpyEx/ILSpy), WASM (wabt), firmware (binwalk/unblob) | ~20 min |
| `network` | + Wireshark/tshark, Kaitai, boofuzz, Scapy | ~10 min |
| `wsl` | Cria WSL2 Ubuntu 24.04 e provisiona a toolchain Linux/Android/firmware/fuzzing | ~25 min |
| `full` | Tudo acima, em ordem | ~1 h |

---

## 4. Índice da documentação

| Documento | Para que serve |
|---|---|
| [00-diagnostico.md](docs/00-diagnostico.md) | Auditoria: o que funciona, o que falta, causa-raiz, risco |
| [01-arquitetura.md](docs/01-arquitetura.md) | Estrutura de diretórios, convenções de nome, fluxo de trabalho, onde cada artefato mora |
| [02-catalogo-ferramentas.md](docs/02-catalogo-ferramentas.md) | **Catálogo exaustivo** por domínio (a–g), com "quando usar", "como usar", integração e licença |
| [03-licencas.md](docs/03-licencas.md) | Matriz de licenças, compatibilidade MIT, o que pode/não pode ir para o GitHub |
| [04-instalacao.md](docs/04-instalacao.md) | Instalação passo a passo, por perfil, com verificação |
| [05-mcp.md](docs/05-mcp.md) | Todos os servidores MCP, variáveis, tokens, ordem de subida, troubleshooting |
| [06-workflows.md](docs/06-workflows.md) | **Guias passo-a-passo** para os 12 cenários mais comuns |
| [07-operacao-por-ia.md](docs/07-operacao-por-ia.md) | Contrato de operação para LLM: o que pode fazer sozinha, quando parar, como reportar evidência |
| [08-higiene-e-seguranca.md](docs/08-higiene-e-seguranca.md) | Isolamento de amostras, snapshots de VM, rede, cadeia de custódia |
| [tools/ghidra.md](docs/tools/ghidra.md) | Ficha da ferramenta: Ghidra |
| [tools/x64dbg.md](docs/tools/x64dbg.md) | Ficha da ferramenta: x64dbg |
| [tools/rea.md](docs/tools/rea.md) | Ficha da ferramenta: REA |
| [tools/x64dbg-mcp.md](docs/tools/x64dbg-mcp.md) | Ficha da ferramenta: x64dbg-MCP Server |

Automação:

| Script | Função |
|---|---|
| [scripts/health-check.ps1](scripts/health-check.ps1) | Diagnóstico do ambiente (PS 5.1), com `-Json` para consumo por IA |
| [scripts/health-check.sh](scripts/health-check.sh) | Mesmo diagnóstico em Git Bash |
| [scripts/bootstrap-windows.ps1](scripts/bootstrap-windows.ps1) | Instalação por perfil, idempotente, com `-DryRun` |
| [scripts/bootstrap-wsl.sh](scripts/bootstrap-wsl.sh) | Provisionamento da toolchain Linux dentro do WSL |
| [scripts/gen-mcp-config.mjs](scripts/gen-mcp-config.mjs) | Gera/valida os blocos `mcpServers` para cada cliente de IA |
| [scripts/setup-ghidra-extensions.ps1](scripts/setup-ghidra-extensions.ps1) | Instala a extensão Jython e prepara PyGhidra (Python 3) |
| [scripts/re-build.ps1](scripts/re-build.ps1) | Compila os componentes locais (REA, x64dbg-MCP) |

---

## 5. Convenções

- **Diretórios existentes não são movidos.** `ghidra/`, `rea-main/`, `x64dbg/`,
  `x64dbg-mcp-server-main/` continuam na raiz — mover instalação funcionando é
  risco sem ganho. Novas ferramentas vão para `tools/<nome>/`.
  O motivo e a alternativa (migração opcional) estão em
  [docs/01-arquitetura.md](docs/01-arquitetura.md#3-por-que-não-movemos-os-diretórios-existentes).
- **Scripts:** `kebab-case.ps1` / `.sh` / `.mjs`. Todo script aceita `-DryRun`
  (ou `--dry-run`) e nunca assume privilégio administrativo silenciosamente.
- **Docs:** numerados, em PT-BR, com comandos copiáveis e *verificação* ao final de
  cada seção.
- **Idioma de código:** identificadores e comentários em inglês; documentação em PT-BR.
- **Saídas:** todo artefato de análise vai para `work/<alvo>/` (ignorado no Git);
  relatórios consolidados para humanos vão em `reports/`.

---

## 6. Escopo e limites

Este toolkit é para **análise legítima**: interoperabilidade, pesquisa de segurança,
resposta a incidentes, recuperação de dados e análise competitiva de produtos que
você tem direito de estudar (licença de uso válida, ou software que você adquire
legalmente para avaliação).

O que o toolkit **faz**: entender binários, protocolos e formatos; documentar
comportamento; medir desempenho; detectar e reproduzir falhas.

O que o toolkit **não é**: catálogo de quebra de proteção de cópia de terceiros.
Se a sua finalidade envolve contornar DRM/licenciamento de software de terceiros,
a análise em si é lícita em muitos contextos, mas **a distribuição de contramedidas
pode não ser** — leia [docs/03-licencas.md §4](docs/03-licencas.md) antes de publicar
qualquer coisa derivada de análise de proteção.

Ao publicar este toolkit no GitHub: publique **apenas o seu código e a sua
documentação** (MIT), nunca binários de terceiros, amostras de alvos comerciais ou
chaves. O [.gitignore](.gitignore) já bloqueia o essencial.

---

## 7. Licença e atribuições

O código próprio deste repositório (scripts, docs, configs) é **MIT** — ver
[LICENSE](LICENSE), © UnboxRE contributors.

Ferramentas de terceiros mantêm suas próprias licenças e **não são redistribuídas**
aqui; são instaladas localmente pelo bootstrap. Todo o crédito pertence aos seus
autores — autor, licença e upstream de **cada projeto** referenciado estão em
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). O UnboxRE é independente e **não é
afiliado nem endossado** por nenhum deles.

> Se você for usar o UnboxRE para empacotar algo, publique apenas o que é seu (MIT).
> Redistribuir ferramenta de terceiro exige cumprir a licença dela — a matriz de
> compatibilidade está em [docs/03-licencas.md](docs/03-licencas.md).
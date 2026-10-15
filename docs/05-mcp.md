# 05 — Servidores MCP e integração com IA

O toolkit é operado primariamente por LLM. A ponte entre o agente e as ferramentas é
o **MCP** (Model Context Protocol). Este documento é o mapa: quais servidores existem,
como sobem, o que expõem, em que ordem, e o que dá errado.

---

## 1. Panorama

```
   cliente MCP (Claude Code / Codex / Cursor / OpenCode / Gemini / VS Code)
        │
        ├── stdio ──▶ REA  (rea-main/scripts/rea.mjs mcp)      ← orquestração + evidência
        │              ├── provider Ghidra   (estático, PE x86/x64 no Windows)
        │              ├── provider IDA      (se instalado)
        │              ├── provider JEB      (Android, se instalado)
        │              ├── provider Hopper   (macOS, se instalado)
        │              └── bridges: android, firmware, process, mitmproxy, pwndbg, wasm
        │
        ├── http ──▶ x64dbg-MCP :9094 (x64) / :9095 (x32)      ← debug controlado por IA
        │
        └── stdio ──▶ GhidraMCP                                 ← Ghidra via MCP (decompile/rename/xref)
```

Três servidores, três papéis distintos:

| Servidor | Papel | Transporte | Porta | Token |
|---|---|---|---|---|
| **REA** | orquestração de alto nível, análise semântica, evidência | stdio | — | — |
| **x64dbg-MCP** | controle total do debugger (usermode) | HTTP + SSE | 9094/9095 | **sim** (Bearer) |
| **GhidraMCP** | operações pontuais no Ghidra (decompile, rename, xrefs) | stdio | — | — |

---

## 2. x64dbg-MCP Server (o mais importante)

### 2.1 Subida

**Um comando (recomendado):**

```powershell
PS> .\scripts\start-x64dbg.ps1 -Check    # sobe minimizado, espera a porta e chama o MCP de verdade
PS> .\scripts\start-x64dbg.ps1 -Stop     # encerra o que ele subiu
```

O script reaproveita um x64dbg já aberto em vez de subir um segundo (conflito de
porta), grava o PID em `.cache/run/` e com `-Check` delega ao
`scripts/mcp-x64dbg-smoke.mjs` — que faz `initialize → tools/list → tools/call`.
Saída real nesta máquina (2026-10-13):

```
[OK  ] porta 9094 respondendo (PID 21476)
[OK  ] token do plugin: x64dbg\release\x64\mcp_config.json
[OK  ] initialize    x64dbg-MCP Server 1.6 (protocolo 2024-11-05)
[OK  ] tools/list    80 tools expostas
[OK  ] tools/call GetDebugState  isDebugging: false status: NO_TARGET
```

**Na mão:**

1. Compile (`.\scripts\bootstrap-windows.ps1 -Profile core`) ou rode
   `.\scripts\fetch-tools.ps1 -Tool x64dbg,x64dbg-mcp -Apply` (release pré-compilado).
2. Abra o x64dbg (`x96dbg.exe`). O plugin carrega sozinho e sobe o servidor HTTP.
3. No primeiro run ele **gera o token** e grava em
   `x64dbg/release/<arch>/mcp_config.json` — **ao lado do `x64dbg.exe`**, não na raiz
   `x64dbg/` (a raiz só é aceita como legado).
4. Para mudar porta/token: menu **Plugins → x64dbg-MCP Server → Configure MCP Server…**
   (o servidor reinicia ao salvar).

### 2.2 Verificação

```powershell
PS> Get-Content x64dbg\release\x64\mcp_config.json   # mostra porta + token (NÃO comitar)
PS> Test-NetConnection 127.0.0.1 -Port 9094           # TcpTestSucceeded = True
```

```bash
$ curl -s -X POST http://127.0.0.1:9094/ \
    -H "Authorization: Bearer $X64DBG_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -c 400
```

Se responder com a lista de tools → está no ar. Se `401` → token errado. Se não
conectar → o plugin não carregou (pasta `plugins/` inexistente — G4).

### 2.3 Ferramentas expostas (resumo por grupo)

| Grupo | Exemplos |
|---|---|
| Sessão | `LoadBinary`, `AttachProcess`, `GetDebugState`, `RunToAddress`, `WaitForPause` |
| Execução | `StepInto`, `StepOver`, `StepOut`, `run`, `PauseDebug`, `TraceInto`, `TraceOver` |
| Breakpoints | `SetBreakpoint`, `SetHardwareBreakpoint`, `SetConditionalBreakpoint`, `SetMemoryBreakpoint`, `SetExceptionBreakpoint`, `ListBreakpoints` |
| Memória | `ReadMemory`, `WriteMemToAddress`, `AllocateMemory`, `RestorePatches`, `FindPattern`, `GetMemoryMap` |
| Registradores/threads | `GetAllRegisters`, `SetRegister`, `GetThreads`, `SwitchThread`, `GetCallStack` |
| Módulos/PE | `ListModules`, `AnalyzeModule`, `GetImports`, `GetExports`, `GetPEB`, `GetSEHChain` |
| Unpack/dump | `DetectOEP`, `DumpModule`, `DumpMemory`, `GetDumpableRegions` |
| Análise | `Disassemble`, `DisassembleFunction`, `GetFunctions`, `GetReferences`, `SearchSymbols`, `GetStrings` |
| Controle genérico | `ExecuteDebuggerCommand`, `EvalExpression`, `Assemble`, `CommentOrLabelAtAddress` |
| Eventos | `GetEventLog`, `ClearEventLog`, `WaitForEvent` |

O catálogo completo (84 tools no README do upstream) está em
[duty1g/x64dbg-mcp-server](https://github.com/duty1g/x64dbg-mcp-server#tools). O plugin é
instalado do release pré-compilado — **não há clone da fonte** em
`x64dbg-mcp-server-main/`, então esse caminho não existe numa máquina preparada.

**Ao parar em código que o packer ainda pode reescrever, use `SetHardwareBreakpoint`, não
`SetBreakpoint`:** o breakpoint de software grava `int3` (`0xCC`) na memória e, ao parar, o
debugger devolve o byte *pré-modificação* — o dump sai com uma instrução trocada (medido). O
hardware (DR0-DR3, **4** por thread) não escreve nada; o 5º é descartado em silêncio, então
confira o `ListBreakpoints` depois de cada um (`scripts/x64dbg-drive.mjs --hw-break` já confere e
falha se não foi armado). Passo a passo: [06-workflows.md](06-workflows.md) Cenário 1.

### 2.4 Config por cliente

**Streamable HTTP (recomendado):**

```json
{
  "mcpServers": {
    "x64dbg": {
      "type": "http",
      "url": "http://localhost:9094/",
      "headers": { "Authorization": "Bearer ${X64DBG_TOKEN}" }
    }
  }
}
```

**SSE (clientes legados):** troque `"type": "sse"` e a URL para `http://localhost:9094/sse`.

De WSL/VM: use o IP do host e mude o bind para `0.0.0.0` no diálogo do plugin — mas
**só** com o token ativo e a rede confiável (HTTP puro, sem TLS).

---

## 3. REA (orquestrador)

### 3.1 Subida

```powershell
PS> node .\rea-main\scripts\rea.mjs --help
PS> node .\rea-main\scripts\rea.mjs doctor            # checa providers e dependências
PS> node .\rea-main\scripts\rea.mjs mcp               # sobe o servidor MCP (stdio)
```

O REA descobre o Ghidra via `GHIDRA_INSTALL_DIR` e o Java via `JAVA_HOME`. Exporte os
dois antes de subir (ou use o `config/env/unboxre.env.example`). Se um deles estiver
apontando para um caminho que não existe mais, `.\scripts\health-check.ps1 -Fix-Paths`
reescreve `config/env/unboxre.env` com o Ghidra de `ghidra/` e o JDK 21 LTS.

### 3.2 O que ele traz

- **Providers:** Ghidra (P0 no Windows: read-only, só PE x86/x64), IDA, JEB, Hopper.
- **Bridges:** android, firmware (`binwalk`/`unblob`), nativeaot, process, pwndbg,
  pwntools, mitmproxy, web-network-captures, wasm (`wabt`/`wakaru`), evmole.
- **Skills:** `.agents/skills/reverse-engineer-anything/` (o REA é orientado a skills).
- **Contrato de evidência:** cada achado vem com proveniência — é o que permite
  separar *observado* de *inferido* em [06-workflows.md](06-workflows.md).

### 3.3 Limitação no Windows (importante)

O provider Ghidra no Windows é **experimental, somente leitura, apenas PE x86/x86-64**
(doc do upstream: [docs/windows-ghidra-p0.md](https://github.com/morluto/rea/blob/main/docs/windows-ghidra-p0.md) —
o pacote npm não traz `docs/`, então `rea-main/docs/` não existe).
Não conte com anotar/renomear funções pelo REA no Windows — use a GUI do Ghidra ou
`analyzeHeadless` com scripts próprios. O REA brilha mesmo em: leitura semântica,
Android, firmware, rede, JS/Electron, WASM, .NET.

### 3.4 Config

```json
{
  "mcpServers": {
    "rea": { "command": "node", "args": ["<raiz-do-toolkit>\\rea-main\\scripts\\rea.mjs", "mcp"] }
  }
}
```

---

## 4. GhidraMCP (opcional, complementa o REA)

Expõe o Ghidra por MCP para operações pontuais: decompilar uma função, renomear,
listar xrefs, aplicar tipos. Útil quando você quer "conversar" com o Ghidra sem abrir
a GUI.

- **Como obter:** clone do projeto GhidraMCP, build, e aponte para o `GHIDRA_INSTALL_DIR`.
- **Subida:** o servidor sobe junto com um Ghidra (GUI ou headless com o plugin).
- **Uso típico:** `decompile_function 0x401000`, `rename_function 0x401000 check_license`,
  `list_methods`.

> **Por quê manter os dois:** o REA é melhor para *pipeline + evidência*; o GhidraMCP é
> melhor para *interação pontual*. Não são concorrentes.

---

## 5. Ordem de subida (importa)

```
1. x64dbg (GUI)            → o plugin MCP sobe sozinho na :9094/:9095
2. Ghidra (se for usar)    → GhidraMCP sobe junto
3. REA (`rea mcp`)         → stdio, sob demanda pelo cliente
4. cliente MCP (LLM)       → conecta nos três
```

**Por quê essa ordem:** o x64dbg-MCP é um servidor *dentro* do processo do x64dbg — se
o x64dbg não estiver aberto, a porta não existe e o cliente MCP falha ao conectar. Já
o REA e o GhidraMCP são stdio: o cliente os *spawna*, então não precisam estar
previamente no ar — mas precisam que o Ghidra/x64dbg que eles controlam existam.

---

## 6. Variáveis de ambiente

Todas as variáveis suportadas estão em
[config/env/unboxre.env.example](../config/env/unboxre.env.example). As que
importam para MCP:

| Variável | Usada por | Exemplo |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | REA, GhidraMCP, `analyzeHeadless` | `C:\...\ghidra\ghidra_12.1.4_PUBLIC` |
| `JAVA_HOME` | Ghidra, REA | JDK 21 LTS (pin); `ghidra\jdk-27` existe, mas não é o padrão |
| `X64DBG_TOKEN` | cliente MCP | lido de `x64dbg/mcp_config.json` |
| `UNBOXRE_WORKSPACE` | scripts próprios | `C:\Users\Admin\Desktop\UnboxRE` |
| `UNBOXRE_WORK` | scripts próprios | `%UNBOXRE_WORKSPACE%\work` |
| `SSLKEYLOGFILE` | Wireshark/tshark | `%UNBOXRE_WORK%\<alvo>\captures\tls.keys` |

O `gen-mcp-config.mjs` resolve `${X64DBG_TOKEN}` a partir do `mcp_config.json` para
que você não cole o token à mão.

---

## 7. Geração de configuração

```powershell
PS> node .\scripts\gen-mcp-config.mjs --client vscode --check    # valida sem escrever
PS> node .\scripts\gen-mcp-config.mjs --client claude-code --apply   # escreve em config/mcp/generated/
PS> node .\scripts\gen-mcp-config.mjs --client claude-code --apply --install  # também no local real do cliente
PS> node .\scripts\gen-mcp-config.mjs --list                     # clientes suportados
```

Clientes e onde o arquivo mora:

| Cliente | `--client` | Arquivo |
|---|---|---|
| Claude Code | `claude` | `.mcp.json` (raiz) |
| Cursor | `cursor` | `.cursor/mcp.json` |
| VS Code (Copilot) | `vscode` | `.vscode/mcp.json` |
| OpenCode | `opencode` | `opencode.json` |
| Gemini CLI | `gemini` | `.gemini/settings.json` |
| genérico | `generic` | imprime o JSON no stdout |

---

## 8. Troubleshooting

| Sintoma | Causa provável | Correção |
|---|---|---|
| Cliente não conecta em `:9094` | x64dbg fechado ou plugin não carregado | abra o x64dbg; verifique `plugins/x64dbg-MCP-Server.dp64` |
| `401 Unauthorized` | token divergente | releia `mcp_config.json` e regenere o header |
| `tools/list` vazio | plugin carregou mas SDK não resolveu | confirme que `x64bridge.dll`/`x64dbg.dll` estão ao lado |
| REA não acha o Ghidra | `GHIDRA_INSTALL_DIR` ausente | exporte o caminho absoluto |
| REA: "provider read-only" | comportamento P0 no Windows | esperado; use a GUI/headless para anotar |
| WSL não alcança o MCP | bind em `127.0.0.1` | mude para `0.0.0.0` **com** token e firewall |
| Cliente stdio não sobe o REA | caminho do `node`/`rea.mjs` errado | use caminho absoluto no JSON |
| Porta 9094 já em uso | dois x64dbg abertos | feche um ou mude a porta no diálogo |

---

## 9. Segurança do MCP (leia antes de expor)

- O x64dbg-MCP dá **controle total do debugger** (leitura/escrita de memória,
  execução). Trate o token como uma credencial de administrador.
- **Nunca** coloque `mcp_config.json` no Git — o `.gitignore` já cobre.
- **Nunca** exponha a `0.0.0.0` em rede não confiável: o transporte é HTTP puro.
- Se expuser (WSL/VM), use firewall + rede host-only, nunca a rede corporativa.
- Rotacione o token quando compartilhar logs/prints de tela.

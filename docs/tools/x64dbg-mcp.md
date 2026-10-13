# x64dbg-MCP Server 1.0.0
**Licença:** MIT · **Status:** código presente, **não compilado** · **Camada:** núcleo

Caminhos: `x64dbg-mcp-server-main/` (fonte) → `dist/` (binário) → `x64dbg/release/x64/plugins/`

## O que faz

Plugin de x64dbg que sobe um servidor **MCP** (HTTP + SSE) dentro do debugger, expondo
72–84 tools que dão a um agente de IA **controle total** sobre a sessão: carregar
binário, breakpoints, memória, registradores, threads, módulos, dumps, disassembly,
OEP detection, eventos.

Escrito em **Zig** (`build.zig.zon`, `minimum_zig_version = 0.14.0`). Portas padrão:
**9094** (x64) e **9095** (x32). Autenticação por **Bearer token**, gerado no primeiro
run e salvo em `x64dbg/mcp_config.json`.

## Quando usar

- O agente precisa **inspecionar** estado vivo: memória, registradores, stack, módulos.
- O agente precisa **automatizar** debug: breakpoints condicionais, tracing, dumps.
- Unpacking guiado por IA (OEP → dump → reparo de IAT).
- Triagem dinâmica: "este processo se comporta diferente quando depurado?".

## Quando NÃO usar

- **Sem x64dbg aberto.** O servidor vive dentro do processo do x64dbg; porta fechada =
  nada funciona. Não é um daemon independente.
- **Em rede não confiável.** É HTTP puro com Bearer. Expor em `0.0.0.0` na LAN
  corporativa é entregar o controle do debugger.
- **Para escrita cega.** `WriteMemToAddress`/`Assemble`/`RestorePatches` são poderosos e
  perigosos. Sempre sobre `unpacked/`, sempre com os bytes originais anotados.
- **Kernel.** O x64dbg é usermode.

## Instalação / estado

```bash
$ cat x64dbg-mcp-server-main/build.zig.zon    # confirma: Zig 0.14.0 mínimo
$ zig version                                 # precisa ser >= 0.14.0
$ cd x64dbg-mcp-server-main && zig build -Doptimize=ReleaseFast
```

O CI do projeto (`.github/workflows/ci.yml`) faz exatamente isso — use-o como
referência de comando canônico se o `build.zig` divergir.

Depois, copie o artefato para a pasta de plugins do x64dbg **da arquitetura correta**
(`x64/plugins/` para 64 bits). O bootstrap e o `re-build.ps1` fazem isso com verificação.

## Uso — receitas curtas

**Verificar que está no ar:**

```bash
$ curl -s -X POST http://127.0.0.1:9094/ \
    -H "Authorization: Bearer $X64DBG_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -c 400
```

`401` → token errado. Conexão recusada → x64dbg fechado ou plugin ausente.

**Config de cliente (Streamable HTTP):**

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

**Fluxo de unpack (o caso de uso mais valioso):**

```text
LoadBinary → RunToAddress → StepOver → DetectOEP → SetBreakpoint
→ run → DumpModule → AnalyzeModule
```

## Integração com o resto do setup

- **x64dbg** é o hospedeiro — ver [x64dbg.md](x64dbg.md).
- **Ghidra** consome o dump (`AnalyzeModule` reconstrói a IAT; o Ghidra lê o resultado).
- **REA** faz a camada semântica em cima do que o MCP coletou.
- `scripts/gen-mcp-config.mjs` lê o `mcp_config.json` e injeta o token no JSON do
  cliente — você nunca cola o token à mão.
- **Portas 9094/9095** estão reservadas no [01-arquitetura.md](../01-arquitetura.md) §6.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| Zig < 0.14.0 | build falha | instale Zig 0.14+ |
| `plugins/` inexistente | plugin não carrega | crie a pasta da arquitetura |
| token comitado | controle do debugger no GitHub | `.gitignore` cobre; rode `scan-secrets.mjs` |
| bind `0.0.0.0` | exposto em HTTP puro | só com firewall + rede isolada |
| dois x64dbg abertos | conflito de porta | feche um ou mude a porta no diálogo |
| assumir persistência | sessão some ao fechar o x64dbg | reconecte o cliente MCP |

## Referências

- `x64dbg-mcp-server-main/README.md` — catálogo completo das tools
- `x64dbg-mcp-server-main/src/` — implementação Zig
- `docs/05-mcp.md` §2 — subida, verificação e troubleshooting

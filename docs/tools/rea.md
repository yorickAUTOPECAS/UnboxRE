# REA 6.4.0
**Licença:** MIT (o REA); submódulos têm licenças próprias ·
**Status:** presente, **não construído** · **Camada:** núcleo

Caminho: `rea-main/`

## O que faz

Camada de **orquestração por agente** sobre analisadores (Ghidra, IDA, JEB, Hopper) e
sobre domínios específicos (Android, firmware, rede, JS/Electron, WASM, .NET,
nativeaot, EVM). Expõe MCP, um sistema de *skills* e — o mais importante — um
**contrato de evidência**: cada achado carrega de onde veio.

## Quando usar

- Você quer resposta em linguagem natural com proveniência ("o que esta função faz?").
- Análise **Android**, **firmware**, **rede**, **JS/Electron**, **WASM**, **.NET** —
  domínios em que o REA tem bridges prontos.
- Pipeline em lote: "analise estes 40 arquivos e me diga quais falam com a rede".
- Quando você quer que a IA leia o binário **através de uma interface controlada**, e
  não escrevendo scripts soltos.

## Quando NÃO usar

- **Windows/PE nativo em profundidade.** O provider Ghidra no Windows é P0:
  read-only, apenas PE x86/x64 (`rea-main/docs/windows-ghidra-p0.md`). Para anotar,
  renomear e tipar, use a GUI do Ghidra ou `analyzeHeadless` com scripts próprios.
- **Quando você já sabe o comando exato.** Abrir o REA para rodar `strings` é overhead.
- **Como substituto do x64dbg.** O REA orquestra análise; não é debugger.

## Instalação / estado

A auditoria encontrou o checkout sem build (`dist/` incompleto). Construa antes de usar:

```bash
$ cd rea-main
$ cat package.json | grep -A5 '"scripts"'   # confira os scripts reais antes de rodar
$ npm ci                                     # respeita o lockfile
$ npm run build                              # se existir script de build
```

O `scripts/re-build.ps1` do toolkit faz isso com log e sem inventar comandos.

## Uso — receitas curtas

```powershell
PS> node .\rea-main\scripts\rea.mjs --help
PS> node .\rea-main\scripts\rea.mjs doctor      # valida providers e dependências
PS> node .\rea-main\scripts\rea.mjs mcp         # sobe o servidor MCP (stdio)
```

Antes de subir, exporte:

```powershell
PS> $env:GHIDRA_INSTALL_DIR = "$PWD\ghidra\ghidra_12.1.4_PUBLIC"
PS> $env:JAVA_HOME          = "$PWD\ghidra\jdk-27"
```

**Skills:** o REA é orientado a skills em `rea-main/.agents/skills/`. Leia a skill
antes de inventar fluxo — ela codifica o procedimento correto por domínio.

## Integração com o resto do setup

- **Ghidra** é o provider P0: `GHIDRA_INSTALL_DIR` aponta para `ghidra/ghidra_12.1.4_PUBLIC`.
- **x64dbg-MCP** é o complemento dinâmico: o REA não debuga; o MCP debuga.
- **Bridges** consomem ferramentas do catálogo: `binwalk`/`unblob` (firmware),
  `wabt`/`wakaru` (WASM), `mitmproxy` (rede), `pwndbg` (native).
- Alimenta `notes/findings.md` seguindo o contrato de evidência de
  [07-operacao-por-ia.md](../07-operacao-por-ia.md).

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| `GHIDRA_INSTALL_DIR` ausente | provider Ghidra não sobe | exporte o caminho absoluto |
| `JAVA_HOME` errado | doctor falha | use o JDK aceito pelo Ghidra |
| esperar escrita no Windows | "read-only" | esperado no P0; use GUI/headless |
| rodar `mcp` sem build | erro de módulo | `npm ci && npm run build` |
| assumir que os submódulos estão clonados | bridges vazios | `git submodule status` em `rea-main/` |

## Referências

- `rea-main/docs/installation.md`
- `rea-main/docs/windows-ghidra-p0.md`
- `rea-main/README.md`

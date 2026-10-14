# Fichas por ferramenta

Uma ficha por ferramenta central. Ficam **fora** de `tools/<nome>/` de propósito: um
`rm -rf tools/radare2` numa atualização não pode levar a documentação embora
([01-arquitetura.md](../01-arquitetura.md) §"Por que essa divisão").

O catálogo completo, com todas as ferramentas por domínio, é
[02-catalogo-ferramentas.md](../02-catalogo-ferramentas.md). Aqui só entram as
ferramentas que você vai tocar toda semana — as que merecem mais que uma tabela.

## Template (toda ficha segue esta ordem)

```markdown
# <Ferramenta> <versão>
**Licença:** <SPDX> · **Status:** instalado | a instalar | comercial · **Camada:** núcleo | domínio

## O que faz
## Quando usar (e quando NÃO usar)
## Instalação
## Uso — receitas curtas
## Integração com o resto do setup
## Limites e armadilhas conhecidas
## Referências
```

A seção **"quando NÃO usar"** é obrigatória. A causa mais comum de trabalho perdido não
é ferramenta ruim — é ferramenta certa no problema errado.

---

## Índice

### Núcleo (já no workspace)

| Ficha | Licença | Papel |
|---|---|---|
| [ghidra.md](ghidra.md) | Apache-2.0 | descompilador + análise estática multi-arquitetura |
| [x64dbg.md](x64dbg.md) | GPL-3.0 | debugger usermode Windows x32/x64 |
| [rea.md](rea.md) | MIT | orquestração por agente + contrato de evidência |
| [x64dbg-mcp.md](x64dbg-mcp.md) | MIT | ponte MCP → controle do x64dbg por IA |

### Análise estática

| Ficha | Licença | Papel |
|---|---|---|
| [radare2.md](radare2.md) | LGPL-3.0 | CLI/scriptável, disassembly, diff de binários |
| [lief.md](lief.md) | Apache-2.0 | parsing e **edição** de PE/ELF/Mach-O |
| [detect-it-easy.md](detect-it-easy.md) | MIT | identificação de packer/compilador/protetor |
| [yara-capa.md](yara-capa.md) | BSD-3 / Apache-2.0 | regras e capacidades (triage semântico) |

### Análise dinâmica

| Ficha | Licença | Papel |
|---|---|---|
| [frida.md](frida.md) | wxWindows | instrumentação em runtime (multi-plataforma) |
| [windbg-ttd.md](windbg-ttd.md) | EULA Microsoft | kernel/user + time-travel debugging |
| [unicorn-qiling.md](unicorn-qiling.md) | GPL-2.0 | emulação de CPU e de sistema |
| [pwndbg-gef.md](pwndbg-gef.md) | GPL-3.0 / MIT | GDB turbinado para ELF |

### Diagnóstico do loader (Windows)

| Ficha | Licença | Papel |
|---|---|---|
| [gflags.md](gflags.md) | `[COMERCIAL]` (EULA Microsoft) | *loader snaps*: ver a decisão do loader quando um `.exe` é recusado com 0xC000007B |

### Desobfuscação

| Ficha | Licença | Papel |
|---|---|---|
| [scyllahide.md](scyllahide.md) | GPL-3.0 | esconder o debugger (anti-anti-debug) |
| [de4dot.md](de4dot.md) | MIT | remover ofuscação .NET |

### Formatos

| Ficha | Licença | Papel |
|---|---|---|
| [jadx.md](jadx.md) | Apache-2.0 | DEX/APK → Java legível |
| [binwalk-unblob.md](binwalk-unblob.md) | MIT / MIT | extração de firmware |
| [wasm-toolchain.md](wasm-toolchain.md) | Apache-2.0 | WASM/WAT/WASM→C |

### Rede

| Ficha | Licença | Papel |
|---|---|---|
| [mitmproxy.md](mitmproxy.md) | MIT | interceptação e reversão de protocolo |

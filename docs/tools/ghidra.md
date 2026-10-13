# Ghidra 12.1.4
**Licença:** Apache-2.0 (descompilador nativo tem licença própria, uso livre) ·
**Status:** instalado · **Camada:** núcleo

Caminho: `ghidra/ghidra_12.1.4_PUBLIC/`

## O que faz

Suíte SRE da NSA: descompilador multi-arquitetura, análise automática, CFG, call graph,
data flow, type propagation, scripting (Java, Python 3 via **PyGhidra**, Jython legado
via extensão), headless para lote, e versionamento de projeto (Ghidra Server).

Arquiteturas relevantes em `Ghidra/Processors/`: x86, ARM/AArch64, MIPS, PowerPC,
RISC-V, SPARC, 6502, 68000, AVR, MSP430, PIC, Z80, e mais.

## Quando usar

- **Sempre** que a pergunta for estática: o que faz, quem chama, que dados fluem.
- Binários grandes — não há limite de tamanho nem custo por análise.
- Arquiteturas exóticas (MIPS de firmware, RISC-V, AVR).
- Análise em lote de firmware com dezenas de ELFs.

## Quando NÃO usar

- **Runtime.** Ghidra não executa nada. Para "o que acontece quando eu clico aqui", use
  x64dbg/Frida. Tentar responder pergunta dinâmica com Ghidra é o erro mais comum.
- **VMProtect/Themida pesados.** A VM aparece como blobs de bytecode; o descompilador
  não tem o que analisar. Não é falha do Ghidra — é limite do problema.
- **Como primeiro passo em binário empacotado.** Desempacote antes (Cenário 1), senão
  você analisa o stub.
- **Diff de binários em lote.** Use `ghidriff`/BinDiff sobre o Ghidra, não a GUI.

## Instalação / estado

Já presente. Requer JDK compatível:

```bash
$ ls ghidra/ghidra_12.1.4_PUBLIC/../    # confira se há um jdk-* ao lado
$ export JAVA_HOME="$PWD/ghidra/jdk-27" # ou o JDK 21 do PATH
```

O `LaunchSupport` valida o JDK na primeira execução e grava em `support/launch.properties`.

## Uso — receitas curtas

**GUI:**

```powershell
PS> .\ghidra\ghidra_12.1.4_PUBLIC\ghidraRun.bat
```

**Headless (lote, CI, pipeline):**

```bash
$ ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat \
    work/acme/src-proj acme \
    -import work/acme/src/target.exe \
    -processor x86:LE:64:default \
    -postScript ExportPseudocode.java \
    -scriptPath work/acme/scripts \
    -deleteProject \
    -log work/acme/notes/ghidra.log
```

Flags que você vai usar de verdade:

| Flag | Por quê |
|---|---|
| `-import <file>` | importa binário (ou `-import dir/` para lote) |
| `-processor <lang>` | **obrigatório em firmware** — não deixe o auto-detect errar |
| `-loader <name>` | força loader (ex.: `BinaryLoader` para blob cru) |
| `-postScript <S>` | roda script após análise — onde vive sua automação |
| `-scriptPath <dir>` | pasta de scripts do alvo (`work/<alvo>/scripts/`) |
| `-deleteProject` | não polui o disco em análise descartável |
| `-log <file>` | **grave sempre** — é a evidência do que o Ghidra fez |

**Script Python 3 (PyGhidra):**

```python
# work/acme/scripts/export_pseudocode.py
# @category UnboxRE
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

di = DecompInterface(); di.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()
for f in fm.getFunctions(True):
    res = di.decompileFunction(f, 60, ConsoleTaskMonitor())
    if res.decompileCompleted():
        print("// === %s @ %s" % (f.getName(), f.getEntryPoint()))
        print(res.getDecompiledFunction().getC())
```

```bash
$ ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat proj acme \
    -import target.exe -postScript export_pseudocode.py -scriptPath work/acme/scripts
```

> **Java vs Python:** scripts Java (`.java`) compilam na hora e são mais rápidos; Python
> é melhor para prototipar. Nome do arquivo Java é `PascalCase` (exigência do Ghidra);
> Python é `snake_case`.

## Integração com o resto do setup

- `GHIDRA_INSTALL_DIR` é lido pelo **REA** — sem ele, o provider Ghidra não sobe.
- **x64dbg** dá os endereços em runtime; Ghidra dá a estrutura. Case o rebase: o x64dbg
  carrega em `ImageBase + ASLR`; use `AnalyzeModule` para obter a base e subtrair.
- **BinDiff/Ghidriff** operam sobre projetos Ghidra — é assim que você faz o Cenário 11.
- `analyzeHeadless -postScript` é o ponto de entrada do pipeline de automação (domínio f).

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| JAVA_HOME apontando para JDK incompatível | Ghidra não abre / headless falha | use o JDK que o `LaunchSupport` aceita |
| auto-detect de arquitetura em firmware | descompilação sem sentido | `-processor` explícito |
| analisar binário empacotado | você analisa o stub | desempacote primeiro |
| `-import` em lote sem `-recursive` | só o primeiro arquivo | leia `-help` |
| Projeto grande + `-deleteProject` | perde anotações | não use em análise que você vai retomar |
| Provider Ghidra do REA no Windows | read-only, só PE x86/x64 | use a GUI ou headless para anotar |

## Referências

- `ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadlessREADME.md` (local)
- `ghidra/ghidra_12.1.4_PUBLIC/docs/` (local)
- Ghidra API: `ghidra_12.1.4_PUBLIC/docs/GhidraAPI_javadoc.zip`

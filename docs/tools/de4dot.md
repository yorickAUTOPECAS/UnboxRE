# de4dot-cex (+ dnSpy / ILSpy / dnlib)
**Licença:** MIT · **Status:** a instalar · **Camada:** desobfuscação

Caminho após bootstrap: `tools/de4dot/`

## O que faz

**de4dot** desofusca assemblies .NET: remove renaming, control flow flattening,
criptografia de strings, proxies de chamada, anti-debug/anti-tamper, e detecta o
ofuscador usado (ConfuserEx, .NET Reactor, Eazfuscator, SmartAssembly, Dotfuscator,
Babel, etc.). O fork `-cex` mantém suporte a ofuscadores recentes.

O ecossistema ao redor:

| Ferramenta | Papel | Licença |
|---|---|---|
| **de4dot-cex** | desofuscar | MIT |
| **dnSpy / dnSpyEx** | navegar, editar, depurar, exportar projeto C# | MIT |
| **ILSpy** | decompilador C#/IL, integra ao VS Code | MIT |
| **dnlib** | biblioteca para ler/escrever IL (automação) | MIT |

## Quando usar

- **.NET é o caso mais fácil de RE.** Depois do de4dot, o resultado costuma ser código C#
  quase original — nomes de variáveis perdidos, mas lógica intacta. Isso muda a economia
  do trabalho completamente.
- Sempre que o DIE/capa indicar `.NET` ou um ofuscador .NET.
- Para **automatizar** com dnlib: aplicar patches em IL programaticamente.

## Quando NÃO usar

- **Se o alvo tem native AOT / ReadyToRun compilado.** Aí não há IL para desofuscar; é
  código nativo — vá para o Ghidra (e considere o bridge `nativeaot` do REA).
- **Esperando nomes originais.** de4dot recupera **estrutura**, não nomes. Variáveis viram
  `num1`, `text`, `flag2`. Você renomeia conforme entende.
- **Se a lógica está em native libs** chamadas via P/Invoke. A IL só mostra a chamada; a
  lógica está na DLL nativa.
- **Em assembly com licenciamento híbrido** (parte .NET, parte nativa protegida).

## Instalação

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile dotnet
# ou baixe o release do de4dot-cex para tools/de4dot/
```

## Uso — receitas curtas

```powershell
PS> .\tools\de4dot\de4dot.exe -f .\obfuscated.dll -o .\unpacked\clean.dll
PS> .\tools\de4dot\de4dot.exe -f --dont-rename .\app.exe       # preserva nomes se já são úteis
```

Flags que importam:

| Flag | Por quê |
|---|---|
| `-f` | força, mesmo se não detectar ofuscador |
| `--dont-rename` | preserva nomes existentes (evita piorar) |
| `-p <tipo>` | força o tipo do ofuscador (`un`, `cn`, `dr`, …) |
| `--strtyp` | tipo de decriptação de strings |
| `-o <file>` | saída (nunca sobrescreva o original) |

Depois:

```powershell
PS> .\tools\dnspy\dnSpy.exe .\unpacked\clean.dll
# File → Export to Project → gera um projeto .csproj navegável
```

## Integração com o resto do setup

- **DIE** primeiro: confirma .NET e o ofuscador.
- **REA** tem bridge .NET/nativeaot — útil para o que sobra de nativo.
- **dnlib** (via script C#/PowerShell) entra no pipeline de automação para patch de IL.
- Se o assembly chama DLLs nativas, **elas** vão para o Ghidra; a IL mostra a interface.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| assumir que todo .NET é fácil | ReadyToRun/AOT não tem IL | cheque antes; se for nativo, Ghidra |
| sobrescrever o original | perde a referência | saída sempre em `unpacked/` |
| renomear sem `--dont-rename` | nomes úteis viram `num1` | use a flag |
| esquecer o P/Invoke | conclusão incompleta | procure `DllImport` e siga a DLL |
| ofuscador muito novo | de4dot falha | ILSpy + paciência, ou dnlib |

## Referências

- `docs/06-workflows.md` Cenário 3 (.NET)
- `docs/02-catalogo-ferramentas.md` §4 (c.5) e §5 (d.6)

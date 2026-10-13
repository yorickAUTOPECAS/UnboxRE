# scripts/ — automação do UnboxRE

Todos os scripts são **idempotentes** e **dry-run por padrão**: rodar duas vezes
não quebra nada, e nada é instalado/compilado/copiado sem uma flag explícita
(`-Apply` / `--apply`).

> Caminhos abaixo assumem a raiz do toolkit. No Windows use PowerShell; no WSL/Git
> Bash use `bash`.

---

## Mapa

| Script | Ambiente | O que faz | Escreve? |
|---|---|---|---|
| `health-check.ps1` | Windows (PS 5.1/7) | diagnóstico completo; `-Fix-Paths` cria diretórios e repara `GHIDRA_INSTALL_DIR`/`JAVA_HOME` | só com `-Fix-Paths` |
| `health-check.sh` | Git Bash / WSL | versão POSIX do diagnóstico | não |
| `bootstrap-windows.ps1` | Windows | instala ferramentas por perfil (winget/choco/pip/npm) | com `-Apply` |
| `bootstrap-wsl.sh` | WSL (Ubuntu) | instala o lado Linux (gdb, angr, pwndbg, gef, unblob…) | com `--apply` (pede confirmação; `--yes` pula) |
| `re-build.ps1` | Windows | compila x64dbg-MCP (Zig) e REA (npm), instala plugins | com `-Apply` |
| `setup-ghidra-extensions.ps1` | Windows | instala extensões `.zip` no Ghidra | com `-Apply` |
| `new-case.ps1` | Windows | cria `work/<slug>/` com intake e hash | sim |
| `scan-secrets.ps1` | Windows (pwsh) | procura segredos e arquivos indevidos | não |
| `gen-mcp-config.mjs` | Node | gera/valida as configs MCP por cliente | com `--write` |
| `lib/common.ps1` | — | helpers compartilhados (dot-source) | — |

---

## Sequência recomendada (primeira vez)

```powershell
# 1. Veja o que falta
.\scripts\health-check.ps1

# 2. Instale o toolchain e as ferramentas que você quer
.\scripts\bootstrap-windows.ps1 -Profile core            # mostra o plano
.\scripts\bootstrap-windows.ps1 -Profile core -Apply     # instala

# 3. Compile os componentes locais
.\scripts\re-build.ps1 -Apply

# 4. (Opcional) provisione o lado Linux
wsl -d Ubuntu -- bash -lc "cd $(wslpath -u 'C:\Users\Admin\Desktop\UnboxRE') && bash scripts/bootstrap-wsl.sh --apply --yes"

# 5. Gere as configs de MCP para o seu cliente
node .\scripts\gen-mcp-config.mjs --client claude-desktop --write

# 6. Confirme tudo
.\scripts\health-check.ps1
```

---

## Perfis do bootstrap

`-Profile` aceita: `core`, `static`, `dynamic`, `mobile`, `firmware`, `net`,
`plugins`, `all`. Cada ferramenta carrega o motivo de existir e a licença; o
bootstrap nunca instala nada fora do catálogo declarado.

## Convenções

- **Dry-run sempre primeiro.** Sem `-Apply`, o script mostra o plano exato.
- **Nunca sudo.** Se um instalador exigir elevação, ele mesmo pede — o script não
  contorna.
- **Exit codes:** `0` sucesso · `1` falha de verificação · `2` erro de execução.
- **Saída JSON** (`health-check.ps1 -Json`, `scan-secrets.ps1 -Json`) para CI.

## CI

`.github/workflows/ci.yml` valida, a cada push: arquivos obrigatórios, JSON dos
templates MCP, sintaxe dos scripts shell, e roda o `scan-secrets` — a barreira que
impede publicar um token ou um binário de alvo por engano.

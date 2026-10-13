# 04 — Instalação e provisionamento

Instalação por **perfis**, sempre idempotente e sempre com verificação. Nada aqui
depende de "funcionou na minha máquina": cada seção termina com um comando que prova
que a etapa passou.

> **Ordem obrigatória.** Fase 1 (`core`) destrava o que já existe. As fases seguintes
> assumem a anterior. Se um `health-check` falhar, **não avance** — o erro se propaga
> e você depura duas coisas ao mesmo tempo.

---

## 0. Pré-requisitos e o que o bootstrap NÃO faz

**Já presente e suficiente** (auditado em [00-diagnostico.md](00-diagnostico.md)):
Node 24.18, npm 11.16, Java 21 LTS no PATH, JDK 27 em `ghidra/jdk-27`, Git 2.55,
Rust 1.98, PowerShell 5.1, winget, Chocolatey, `uv` 0.11.

**O bootstrap não faz** (por decisão de segurança/escopo):
- não pede privilégio administrativo silenciosamente (avisa e você reexecuta elevado);
- não altera configuração de sistema (firewall, Defender, variáveis de máquina) sem `-AllowSystemChanges`;
- não instala VMs nem licenças comerciais;
- não faz `git push` nem publica nada.

**Antes de tudo**, rode o diagnóstico e leia o resumo:

```powershell
PS> powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\health-check.ps1
```

---

## 1. Fase 1 — `core`: destravar o que já existe

Corrige G1–G6 do diagnóstico. É a fase de maior retorno: transforma quatro
ferramentas "presentes mas inertes" em um setup funcional.

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile core -DryRun   # 1) ver o plano
PS> .\scripts\bootstrap-windows.ps1 -Profile core           # 2) executar
```

### 1.1 O que `core` faz, passo a passo

| # | Ação | Corrige | Verificação |
|---|---|---|---|
| 1 | Cria `x64dbg/release/{x32,x64}/plugins/` | G4 | `Test-Path x64dbg\release\x64\plugins` |
| 2 | Instala **Zig 0.14.0** (a versão do CI) | G3 | `zig version` → `0.14.0` |
| 3 | `git submodule update --init --recursive` no `rea-main` | G2 | `third_party/binwalk` não vazio |
| 4 | `npm ci` no `rea-main` | G1 | `node_modules/` existe |
| 5 | `npm run build` no `rea-main` | G1 | `node rea-main/scripts/rea.mjs --help` responde |
| 6 | Compila o x64dbg-MCP e copia `dist/` | G3 | `x64dbg/release/x64/plugins/x64dbg-MCP-Server.dp64` existe |
| 7 | Instala **PyGhidra** + extensão **Jython** | G5,G6 | `python -c "import pyghidra"`; `Extensions/Ghidra/*Jython.zip` extraído |

### 1.2 Comandos manuais equivalentes (se preferir sem script)

```powershell
# 1) pasta de plugins
New-Item -ItemType Directory -Force x64dbg\release\x32\plugins, x64dbg\release\x64\plugins

# 2) Zig 0.14.0 (winget costuma trazer a mais nova; fixe a versão)
winget install -e --id zig.zig --version 0.14.0

# 3) submódulos + build do REA
Push-Location rea-main
git submodule update --init --recursive
npm ci
npm run build
Pop-Location

# 4) compilar o plugin MCP
Push-Location x64dbg-mcp-server-main
zig build -Doptimize=ReleaseSafe --prefix dist
Copy-Item -Recurse -Force dist\* ..\x64dbg\
Pop-Location

# 5) PyGhidra + Jython
uv pip install pyghidra
Expand-Archive ghidra\ghidra_12.1.4_PUBLIC\Ghidra\Extensions\Ghidra\*_Jython.zip `
             -DestinationPath ghidra\ghidra_12.1.4_PUBLIC\Ghidra\Extensions\Ghidra\
```

### 1.3 Verificação da Fase 1

```powershell
PS> .\scripts\health-check.ps1 | Select-String 'G1|G2|G3|G4|G5|G6'
PS> node .\rea-main\scripts\rea.mjs doctor --provider ghidra
PS> Get-ChildItem x64dbg\release\x64\plugins
```

Esperado: os seis gaps em `ok`; `rea doctor` reconhece o Ghidra; a pasta de plugins
tem `x64dbg-MCP-Server.dp64`.

**Se falhar:**
- `zig build` com erro de API → confirme `zig version` = 0.14.0 (0.15/0.16 mudaram APIs).
- `npm ci` falha → apague `node_modules` e repita; **não** use `npm install` (altera o lock).
- `rea doctor` não acha o Ghidra → exporte `GHIDRA_INSTALL_DIR` para o caminho absoluto.

---

## 2. Fase 2 — `static`: análise estática profissional

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile static
```

| Ferramenta | Método | Verificação |
|---|---|---|
| radare2 / rizin | winget (`radareorg.radare2`) | `r2 -v` |
| LIEF, capstone, keystone, angr, Triton, pyelftools, pefile | `uv pip install` | `python -c "import lief,angr,capstone"` |
| YARA + yara-x | winget / `uv pip` | `yara --version` |
| Detect It Easy | winget / release | `diec --version` |
| ghidriff | `uv pip install ghidriff` | `ghidriff --help` |
| ImHex | winget (`WerWolv.ImHex`) | menu Iniciar |
| RetDec | release oficial | `retdec-decompiler --version` |
| GhidraMCP | clone + build | ver [05-mcp.md](05-mcp.md) |

**Verificação de ponta a ponta** (faça com um binário qualquer que você já tem):

```bash
$ diec -j target.exe | head            # triagem
$ r2 -A -q -c 'afl~+main' target.exe   # funções
$ python -c "import lief;print(lief.parse('target.exe').header.entrypoint)"
```

---

## 3. Fase 3 — `dynamic`: análise dinâmica profissional

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile dynamic
```

| Ferramenta | Método | Verificação |
|---|---|---|
| WinDbg + TTD | `winget install Microsoft.WinDbg` | `windbgx -version` |
| Frida (+ tools) | `uv pip install frida-tools` | `frida --version` |
| DynamoRIO | release oficial | `drrun -version` |
| TinyInst | clone + build (cmake) | build ok |
| ScyllaHide | plugin → `plugins/` | aparece no menu do x64dbg |
| TitanHide | driver + plugin | carrega |
| PE-sieve / HollowsHunter | release → `tools/` | `pe-sieve64 --help` |
| Moneta | release → `tools/` | roda |
| Sysinternals | `winget install Microsoft.Sysinternals` | `procmon /?` |
| al-khaser / pafish | release → `tools/` | roda (é um *teste* de detecção) |

**Verificação:**

```powershell
PS> frida-ps -Uai | Select-Object -First 5
PS> .\tools\pe-sieve\pe-sieve64.exe /pid $PID /shellc /dir $env:TEMP\ps
```

**Atenção:** DynamoRIO/TinyInst/Frida disparam antivírus (são ferramentas de
instrumentação legítimas, mas assinadas como "hacktool" às vezes). Em ambiente
corporativo, adicione as pastas à exclusão do Defender — **com** aprovação.

---

## 4. Fase 4 — `formats`: formatos e plataformas

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile formats
```

| Alvo | Ferramentas | Verificação |
|---|---|---|
| Android | apktool, jadx, d2j-dex2jar, baksmali, Il2CppDumper | `jadx --version`, `apktool --version` |
| .NET | dnSpyEx, ILSpy + `ilspycmd`, de4dot-cex, dotnet SDK | `ilspycmd --version` |
| WASM | wabt, binaryen | `wasm-decompile --version` |
| Firmware | binwalk, unblob, UEFITool | `binwalk --help` |
| Go/Rust | GoReSym, redress, rustfilt | `GoReSym -h` |
| Java | CFR, vineflower | `java -jar cfr.jar` |

**Nota Android:** o `adb` e o `frida-server` são *separados* — você precisa de um
device/emulador. Instale o `adb` via Android Platform Tools.

---

## 5. Fase 5 — `network`: rede e protocolo

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile network
```

| Ferramenta | Método | Verificação |
|---|---|---|
| Wireshark + tshark | winget (`WiresharkFoundation.Wireshark`) | `tshark -v` |
| mitmproxy + mitmproxy2swagger | `uv pip install mitmproxy mitmproxy2swagger` | `mitmdump --version` |
| Kaitai Struct | release / `uv pip install kaitaistruct` | `ksc --version` |
| Scapy | `uv pip install scapy` | `python -c "import scapy"` |
| boofuzz | `uv pip install boofuzz` | `python -c "import boofuzz"` |
| objection | `uv pip install objection` | `objection version` |

**Verificação (interceptação HTTPS):**

```bash
$ mitmdump -p 8080 &
$ curl -x http://127.0.0.1:8080 https://example.com -k   # deve passar pelo proxy
```

---

## 6. Fase 6 — `wsl`: laboratório Linux

```powershell
PS> .\scripts\bootstrap-wsl.sh          # executa dentro do WSL
# ou, do zero:
PS> wsl --install -d Ubuntu-24.04
```

O script `bootstrap-wsl.sh` provisiona: binutils, pyelftools, patchelf, gdb+gef,
pwndbg, AFL++, angr, Qiling, qemu-user, sasquatch, firmware-mod-kit.

**Verificação:**

```bash
$ wsl -d Ubuntu-24.04 -- bash -lc 'readelf --version && afl-fuzz -h | head -1'
$ wsl -d Ubuntu-24.04 -- bash -lc 'python3 -c "import angr,qiling;print(\"ok\")"'
```

**Por que WSL:** ELF/DWARF, Android tooling, AFL++ e emulação de firmware são
Linux-first. Rodar no host Windows é atrito desnecessário.

---

## 7. Fase 7 — isolamento (não é um perfil; é uma decisão)

Antes de rodar **qualquer** amostra desconhecida:

1. **Windows Sandbox** (rápido, efêmero): `PS> WindowsSandbox.exe` — descartável.
2. **VM com snapshot** (sério): crie uma VM, tire um snapshot "limpo", e reverta após
   cada amostra. Documente em [08-higiene-e-seguranca.md](08-higiene-e-seguranca.md).
3. **Rede:** modo host-only ou sem rede; nunca a rede da empresa.

Verificação: a VM tem snapshot; o compartilhamento de pasta do host está **desligado**;
não há credenciais reais na VM.

---

## 8. Fase 8 — MCP e automação

```powershell
PS> node .\scripts\gen-mcp-config.mjs --client vscode --check
PS> node .\scripts\gen-mcp-config.mjs --client claude --write
```

Detalhes em [05-mcp.md](05-mcp.md).

---

## 9. Sequência completa (do zero ao setup pronto)

```powershell
PS> .\scripts\health-check.ps1                                    # 0) diagnóstico
PS> .\scripts\bootstrap-windows.ps1 -Profile core                 # 1) destravar
PS> .\scripts\health-check.ps1 | Select-String 'G[1-8]'           #    validar
PS> .\scripts\bootstrap-windows.ps1 -Profile static               # 2)
PS> .\scripts\bootstrap-windows.ps1 -Profile dynamic              # 3)
PS> .\scripts\bootstrap-windows.ps1 -Profile formats              # 4)
PS> .\scripts\bootstrap-windows.ps1 -Profile network              # 5)
PS> .\scripts\bootstrap-windows.ps1 -Profile wsl                  # 6)
PS> .\scripts\gen-mcp-config.mjs --client claude --write          # 7)
PS> .\scripts\health-check.ps1 -Json | Set-Content reports\health-final.json
```

Ou, em um passo: `.\scripts\bootstrap-windows.ps1 -Profile full` (~1 h).

---

## 10. Troubleshooting dos erros mais comuns

| Sintoma | Causa | Correção |
|---|---|---|
| `python3` não encontrado / abre a Store | alias quebrado da Microsoft Store | use `py` ou `python`; o bootstrap normaliza via `uv` |
| Ghidra reclama de versão do Java | `JAVA_HOME` apontando p/ JDK 27 | aponte para o JDK 21 LTS; o health-check avisa |
| `zig build` falha com API desconhecida | Zig ≠ 0.14.0 | instale exatamente 0.14.0 |
| x64dbg não mostra o plugin MCP | `plugins/` não existe ou falta o `.dp64` | crie a pasta, copie `dist/`, reinicie o x64dbg |
| `rea doctor` não acha o Ghidra | `GHIDRA_INSTALL_DIR` não exportado | exporte o caminho absoluto |
| Frida não conecta no Android | `frida-server` ausente ou arquitetura errada | empurre o `frida-server` da arch correta e rode como root |
| mitmproxy não vê o tráfego | app com certificate pinning | use Frida unpinning/objection |
| antivírus bloqueia DynamoRIO/Frida | assinatura heurística | exclusão de pasta, com aprovação |

Cada correção acima é exatamente o que o `health-check.ps1` reporta no campo `fix`.

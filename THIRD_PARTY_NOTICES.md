# Third-Party Notices — UnboxRE

> **English:** UnboxRE is a *toolkit and documentation* project. It **redistributes no
> third-party software**. Every project listed below is referenced, documented and
> installed locally by the user through `scripts/bootstrap-*.ps1`/`.sh`. All credit for
> those projects belongs to their authors; UnboxRE claims none of it.
>
> **Português:** O UnboxRE é um projeto de *toolkit e documentação*. Ele **não
> redistribui software de terceiros**. Todo projeto listado abaixo é referenciado,
> documentado e instalado localmente por você via `scripts/bootstrap-*`. Todo o crédito
> desses projetos pertence aos seus autores; o UnboxRE não reivindica nenhum.

---

## 0. Como este arquivo funciona

| Pergunta | Resposta |
|---|---|
| O UnboxRE inclui código de terceiros no repositório? | **Não.** `ghidra/`, `x64dbg/`, `rea-main/`, `x64dbg-mcp-server-main/` e `tools/` estão no [.gitignore](.gitignore). |
| Então por que este arquivo existe? | Para **atribuir crédito** a tudo que o toolkit orquestra e para deixar explícito o que é de quem. |
| E o código próprio (`scripts/`, `docs/`, `config/`)? | É **MIT**, © UnboxRE contributors — ver [LICENSE](LICENSE). |
| Posso redistribuir algo daqui? | Só o que é MIT próprio. Para cada ferramenta, use o upstream indicado na tabela. |
| O que a [LICENSE](LICENSE) cobre? | Apenas o código e a documentação originais deste repositório (`scripts/`, `docs/`, `config/`). Ferramentas de terceiros mantêm as próprias licenças. |

**Não afiliação.** O UnboxRE é um projeto independente e **não é afiliado, endossado
ou patrocinado** por nenhum dos projetos citados. Nomes de produtos são marcas dos
respectivos titulares e são usados aqui apenas para identificação e atribuição
(*nominative fair use*).

---

## 1. Componentes usados localmente (não redistribuídos)

Estes dois são o núcleo que o toolkit compila localmente e expõe por MCP. O código
deles **não** é publicado aqui — apenas referenciado, com crédito:

| Projeto | Versão de referência | Licença | Autor / Upstream |
|---|---|---|---|
| **REA — Reverse Engineer Anything** (`rea-agents`) | 6.4.0 | MIT | © 2026 **morluto** — <https://github.com/morluto/rea> |
| **x64dbg-MCP Server** | 1.0.0 | MIT | © 2026 **duty1g** — <https://github.com/duty1g/x64dbg-mcp-server> |

> Ambos foram obtidos por você e permanecem em `rea-main/` e
> `x64dbg-mcp-server-main/`, que estão fora do controle de versão. Se você quiser
> redistribuí-los, faça-o a partir do upstream, mantendo o aviso de copyright MIT de
> cada autor.

---

## 2. Ferramentas centrais de análise

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **Ghidra** | Apache-2.0 | NSA / <https://github.com/NationalSecurityAgency/ghidra> |
| **x64dbg** | GPL-3.0 | <https://github.com/x64dbg/x64dbg> |
| **radare2** | LGPL-3.0 | <https://github.com/radareorg/radare2> |
| **rizin** | LGPL-3.0 | <https://github.com/rizinorg/rizin> |
| **IDA Pro / Hex-Rays** | `[COMERCIAL]` | Hex-Rays SA / <https://hex-rays.com> |
| **Hopper** | `[COMERCIAL]` | <https://www.hopperapp.com> |
| **JEB** | `[COMERCIAL]` | PNF Software / <https://www.pnfsoftware.com> |
| **BinDiff** | `[COMERCIAL]` (grátis) | Google / <https://github.com/google/bindiff> |
| **RetDec** | MIT | Avast / <https://github.com/avast/retdec> |
| **rev.ng** | `[FREEMIUM]` | <https://rev.ng> |
| **Tigress** | `[COMERCIAL]` | <https://tigress.wtf> |
| **capa** (`flare-capa`) | Apache-2.0 | Mandiant / FLARE / <https://github.com/mandiant/capa> |
| **retoolkit** | Apache-2.0 | mentebinaria / <https://github.com/mentebinaria/retoolkit> |

---

## 3. Análise estática e bibliotecas de parsing

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **LIEF** | Apache-2.0 | Quarkslab / <https://github.com/lief-project/LIEF> |
| **Capstone** | BSD-3 | <https://github.com/capstone-engine/capstone> |
| **Keystone** | BSD-3 | <https://github.com/keystone-engine/keystone> |
| **YARA** | BSD-3 | VirusTotal / <https://github.com/VirusTotal/yara> |
| **YARA-X** | Apache-2.0 | VirusTotal / <https://github.com/VirusTotal/yara-x> |
| **Detect It Easy (DIE)** | MIT | horsicq / <https://github.com/horsicq/Detect-It-Easy> |
| **ghidriff** | Apache-2.0 | <https://github.com/clearbluejar/ghidriff> |
| **Diaphora** | GPL-3.0 | <https://github.com/joxeankoret/diaphora> |
| **angr** | BSD-2 | <https://github.com/angr/angr> |
| **Triton** | Apache-2.0 | Jonathan Salwan / <https://github.com/JonathanSalwan/Triton> |
| **msynth** | BSD-3 | <https://github.com/mrphrazer/msynth> |
| **Miasm** | GPL-2.0 | CEA / <https://github.com/cea-sec/miasm> |
| **ImHex** | GPL-2.0 | WerWolv / <https://github.com/WerWolv/ImHex> |
| **pefile** | MIT | Ero Carrera / <https://github.com/erocarrera/pefile> |
| **pyelftools** | Unlicense / public domain | Eli Bendersky / <https://github.com/eliben/pyelftools> |
| **patchelf** | GPL-3.0 | NixOS / <https://github.com/NixOS/patchelf> |
| **dwarves (`pahole`)** | GPL-2.0 | <https://github.com/acmel/dwarves> |
| **PE-bear** | MIT | hasherezade / <https://github.com/hasherezade/pe-bear> |
| **CFF Explorer** | Grátis (NTCore) | <https://ntcore.com/?page_id=388> |
| **pestudio** | `[FREEMIUM]` | <https://www.winitor.com> |
| **PDB Downloader** | MIT | <https://github.com/rajkumar-rangaraj/PDB-Downloader> |
| **class-dump** | MIT | <https://github.com/nygard/class-dump> |
| **dsdump** | MIT | Derek Selander / <https://github.com/DerekSelander/dsdump> |
| **GoReSym** | MIT | Mandiant / <https://github.com/mandiant/GoReSym> |
| **redress** | MIT | <https://github.com/goretk/redress> |
| **rustfilt** | MIT / Apache-2.0 | <https://github.com/luser/rustfilt> |
| **bincat** | MIT | Airbus SecLab / <https://github.com/airbus-seclab/bincat> |
| **ROPgadget** | BSD-3 | Jonathan Salwan / <https://github.com/JonathanSalwan/ROPgadget> |
| **pwntools** | MIT (com trechos GPL-2.0/BSD-2) | Gallopsled / <https://github.com/Gallopsled/pwntools> |

---

## 4. Análise dinâmica, tracing e emulação

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **Frida (core)** | `wxWindows`/LGPL-like | <https://frida.re> · <https://github.com/frida/frida> |
| **Frida (bindings Python/Node)** | MIT | <https://github.com/frida/frida-python> |
| **objection** | MIT | SensePost / <https://github.com/sensepost/objection> |
| **DynamoRIO** | BSD-3 | <https://github.com/DynamoRIO/dynamorio> |
| **Dr. Memory** | LGPL-2.1 | <https://github.com/DynamoRIO/drmemory> |
| **TinyInst** | Apache-2.0 | Google Project Zero / <https://github.com/googleprojectzero/TinyInst> |
| **Unicorn** | GPL-2.0 | <https://github.com/unicorn-engine/unicorn> |
| **Qiling** | GPL-2.0 | <https://github.com/qilingframework/qiling> |
| **Speakeasy** | Apache-2.0 | Mandiant / <https://github.com/mandiant/speakeasy> |
| **GDB** | GPL-3.0 | GNU Project / <https://sourceware.org/gdb> |
| **gef** | MIT | <https://github.com/hugsy/gef> |
| **pwndbg** | MIT | <https://github.com/pwndbg/pwndbg> |
| **LLDB** | Apache-2.0 (LLVM) | <https://lldb.llvm.org> |
| **WinDbg + TTD** | `[COMERCIAL]` (grátis) | Microsoft / <https://learn.microsoft.com/windows-hardware/drivers/debugger/> |
| **Sysinternals** (Procmon, ProcExp, TCPView, Autoruns) | `[COMERCIAL]` (grátis) | Microsoft / <https://learn.microsoft.com/sysinternals/> |
| **frida-tools** (pacote CLI) | `wxWindows`/LGPL-like | parte do projeto Frida — Ole André V. Ravnås / <https://github.com/frida/frida-tools> |
| **PE-sieve** | BSD-2 | hasherezade / <https://github.com/hasherezade/pe-sieve> |
| **HollowsHunter** | BSD-2 | hasherezade / <https://github.com/hasherezade/hollows_hunter> |
| **Moneta** | licença não declarada pelo autor (freeware) | hasherezade / <https://hasherezade.net> |
| **QEMU** (`qemu-user`) | GPL-2.0 | <https://www.qemu.org> |
| **API Monitor** | `[COMERCIAL]` (freeware, sem redistribuição) | Rohitab Batra / <http://www.rohitab.com/apimonitor> |

---

## 5. Desobfuscação, unpacking e anti-anti-debug

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **UPX** | GPL-2.0 | <https://github.com/upx/upx> |
| **Scylla** | GPL-3.0 | <https://github.com/NtQuery/Scylla> |
| **ScyllaHide** | GPL-3.0 | x64dbg team / <https://github.com/x64dbg/ScyllaHide> |
| **TitanHide** | GPL-3.0 | mrexodia / <https://github.com/mrexodia/TitanHide> |
| **al-khaser** | GPL-3.0 | <https://github.com/LordNoteworthy/al-khaser> |
| **pafish** | GPL-3.0 | <https://github.com/a0rtega/pafish> |
| **VBoxHardenedLoader** | GPL-3.0 | hfiref0x / <https://github.com/hfiref0x/VBoxHardenedLoader> |
| **D-810** | MIT | joydo / <https://github.com/joydo/d810> |
| **HexRaysDeob** | MIT | Rolf Rolles / <https://github.com/RolfRolles/HexRaysDeob> |
| **Hikari** | BSD-3 | <https://github.com/HikariObfuscator/Hikari> |
| **OLLVM** (obfuscator-llvm) | NCSA | <https://github.com/obfuscator-llvm/obfuscator> |
| **VTIL** | BSD-3 | <https://github.com/vtil-project/VTIL-Core> |
| **NoVmp** | GPL-3.0 | can1357 / <https://github.com/can1357/NoVmp> |
| **VMHunt** | GPL-3.0 | <https://github.com/s3team/VMHunt> |
| **VMProtect** | `[COMERCIAL]` | VMProtect Software / <https://vmpsoft.com> |
| **Themida** | `[COMERCIAL]` | Oreans / <https://www.oreans.com> |
| **Enigma Protector** | `[COMERCIAL]` | <https://enigmaprotector.com> |

---

## 6. .NET, Java e JavaScript

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **de4dot** (original) | GPL-3.0 | <https://github.com/de4dot/de4dot> |
| **de4dot-cex** | MIT | ViRb3 / <https://github.com/ViRb3/de4dot-cex> |
| **dnlib** | MIT | 0xd4d / <https://github.com/0xd4d/dnlib> |
| **Mono.Cecil** | MIT | Jb Evain / <https://github.com/jbevain/cecil> |
| **ConfuserEx** | MIT | yck1509 / <https://github.com/yck1509/ConfuserEx> |
| **NETReactorSlayer** | GPL-3.0 | SychicBoy / <https://github.com/SychicBoy/NETReactorSlayer> |
| **dnSpyEx** | GPL-3.0 | <https://github.com/dnSpyEx/dnSpy> |
| **ILSpy / ilspycmd** | MIT | icsharpcode / <https://github.com/icsharpcode/ILSpy> |
| **.NET SDK / ILAsm** | MIT | Microsoft / <https://github.com/dotnet/sdk> |
| **Procyon** | Apache-2.0 | <https://github.com/mstrobel/procyon> |
| **CFR** | MIT | Lee Benfield / <https://github.com/leibnitz27/cfr> |
| **Vineflower** | Apache-2.0 | <https://github.com/Vineflower/vineflower> |
| **jd-cli** | MIT | <https://github.com/intoolswetrust/jd-cli> |
| **wakaru** | MIT | <https://github.com/pionxzh/wakaru> |
| **js-beautify** | MIT | <https://github.com/beautifier/js-beautify> |

---

## 7. Formatos: PE, ELF, Mach-O, APK/DEX, firmware, WASM, EVM

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **apktool** | Apache-2.0 | <https://github.com/iBotPeaches/Apktool> |
| **jadx** | Apache-2.0 | skylot / <https://github.com/skylot/jadx> |
| **baksmali / smali** | BSD-3 | <https://github.com/JesusFreke/smali> |
| **dex2jar** | Apache-2.0 | <https://github.com/pxb1988/dex2jar> |
| **ADB (platform-tools)** | Apache-2.0 | Google / <https://developer.android.com/tools/adb> |
| **Android Emulator (AVD)** | Apache-2.0 | Google / <https://developer.android.com/studio> |
| **Genymotion** | `[COMERCIAL]` | <https://www.genymotion.com> |
| **MobSF** | GPL-3.0 | <https://github.com/MobSF/Mobile-Security-Framework-MobSF> |
| **Il2CppDumper** | MIT | Perfare / <https://github.com/Perfare/Il2CppDumper> |
| **Il2CppInspector** | MIT | djkaty / <https://github.com/djkaty/Il2CppInspector> |
| **binwalk** | MIT | ReFirmLabs / <https://github.com/ReFirmLabs/binwalk> |
| **unblob** | MIT | OneKey / <https://github.com/onekey-sec/unblob> |
| **UEFITool** | BSD-2 | <https://github.com/LongSoft/UEFITool> |
| **FACT** | GPL-3.0 | Fraunhofer FKIE / <https://github.com/fkie-cad/FACT_core> |
| **sasquatch / unsquashfs** | GPL-2.0 | <https://github.com/devttys0/sasquatch> |
| **firmware-mod-kit** | GPL-2.0 | <https://github.com/mirror/firmware-mod-kit> |
| **wabt** | Apache-2.0 | <https://github.com/WebAssembly/wabt> |
| **binaryen** | Apache-2.0 | <https://github.com/WebAssembly/binaryen> |
| **evmole** | MIT | <https://github.com/cdump/evmole> |
| **panoramix** | LGPL-3.0 | <https://github.com/eveem-org/panoramix> |
| **heimdall-rs** | MIT | <https://github.com/Jon-Becker/heimdall-rs> |
| **Foundry (`cast`)** | MIT / Apache-2.0 | <https://github.com/foundry-rs/foundry> |
| **Jython** | PSF | <https://www.jython.org> |
| **PyGhidra** | Apache-2.0 | parte do Ghidra / <https://github.com/NationalSecurityAgency/ghidra> |
| **jefferson** | MIT | Sviehb / <https://github.com/sviehb/jefferson> |
| **ubi_reader** | GPL-3.0 | JR Spruitt — mantido por onekey-sec / <https://github.com/onekey-sec/ubi_reader> |

---

## 8. Rede, protocolos e fuzzing

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **Wireshark / tshark** | GPL-2.0 | <https://www.wireshark.org> |
| **mitmproxy** | MIT | <https://github.com/mitmproxy/mitmproxy> |
| **mitmproxy2swagger** | MIT | <https://github.com/alufers/mitmproxy2swagger> |
| **Burp Suite** | `[FREEMIUM]` | PortSwigger / <https://portswigger.net/burp> |
| **HTTP Toolkit** | `[FREEMIUM]` | <https://httptoolkit.com> |
| **Kaitai Struct** | MIT | <https://kaitai.io> · <https://github.com/kaitai-io/kaitai_struct> |
| **Scapy** | GPL-2.0 | <https://github.com/secdev/scapy> |
| **boofuzz** | GPL-2.0 | <https://github.com/jtpereyda/boofuzz> |
| **AFL++** | Apache-2.0 | <https://github.com/AFLplusplus/AFLplusplus> |
| **Fluxzy** | GPL-3.0 (Core em dupla licença: GPL-3.0 ou comercial) | Haga Rakotoharivelo / <https://github.com/haga-rak/fluxzy.core> |

---

## 9. Integração LLM / MCP

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **Model Context Protocol** | MIT | Anthropic / <https://modelcontextprotocol.io> |
| **GhidraMCP** | Apache-2.0 | LaurieWired / <https://github.com/LaurieWired/GhidraMCP> |
| **ida-pro-mcp** | MIT | mrexodia / <https://github.com/mrexodia/ida-pro-mcp> |
| **jadx-headless-mcp** | Apache-2.0 | parte do REA / <https://github.com/morluto/rea> |

---

## 10. Isolamento e laboratório

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **Windows Sandbox** | `[COMERCIAL]` (grátis) | Microsoft / <https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/> |
| **VMware Workstation/Player** | `[FREEMIUM]` | Broadcom / <https://www.vmware.com> |
| **Oracle VirtualBox** | GPL-2.0 | Oracle / <https://www.virtualbox.org> |
| **Hyper-V** | `[COMERCIAL]` | Microsoft / <https://learn.microsoft.com/virtualization/hyper-v-on-windows/> |
| **WSL2** | `[COMERCIAL]` (grátis) | Microsoft / <https://learn.microsoft.com/windows/wsl/> |
| **FLARE VM** | MIT (scripts) | Mandiant / <https://github.com/mandiant/flare-vm> |
| **REMnux** | GPL-3.0 | <https://remnux.org> |
| **Docker / Podman** | Apache-2.0 | <https://www.docker.com> · <https://podman.io> |

---

## 11. Ferramental de build e runtime (dependências de execução)

| Projeto | Licença | Autor / Upstream |
|---|---|---|
| **Node.js** | MIT | OpenJS Foundation / <https://nodejs.org> |
| **Python** | PSF-2.0 | Python Software Foundation / <https://www.python.org> |
| **OpenJDK** | GPL-2.0 + Classpath | Oracle / <https://openjdk.org> |
| **Rust toolchain** (`rustc`, `cargo`, `rust-demangler`) | MIT / Apache-2.0 | Rust Project Developers / <https://www.rust-lang.org> |
| **Zig** | MIT | Zig Software Foundation / <https://ziglang.org> |
| **`uv`** | MIT / Apache-2.0 | Astral / <https://github.com/astral-sh/uv> |
| **`just`** | CC0 | <https://github.com/casey/just> |
| **GNU Make / binutils** | GPL-3.0 | GNU Project / <https://www.gnu.org/software/binutils> |
| **Rich** | MIT | <https://github.com/Textualize/rich> |
| **Typer** | MIT | <https://github.com/fastapi/typer> |
| **Chocolatey** | Apache-2.0 | <https://chocolatey.org> |
| **winget** | MIT | Microsoft / <https://github.com/microsoft/winget-cli> |
| **Xcode Command Line Tools** (`otool`, `nm`, `codesign`, `atos`) | `[COMERCIAL]` (grátis, sem redistribuição) | Apple / <https://developer.apple.com/xcode> |
| **CMake** | BSD-3 | Kitware / <https://cmake.org> · <https://github.com/Kitware/CMake> |
| **Ninja** | Apache-2.0 | <https://ninja-build.org> · <https://github.com/ninja-build/ninja> |

---

### 11.1 Pacotes de base instalados pelos bootstraps (Debian/Ubuntu)

Estes não são ferramentas de RE: são as dependências de sistema que os bootstraps
instalam (`apt-get install`) mais os utilitários que acompanham o host. Os créditos e
as licenças são dos projetos de origem; o empacotamento é do Debian/Ubuntu.

| Pacote | Licença | Autor / Upstream |
|---|---|---|
| **Ubuntu (base do WSL)** | múltiplas (sobretudo GPL-2+/MIT), marca Canonical | Canonical / <https://ubuntu.com/legal> |
| **build-essential** | GPL-2+ (metapacote: apenas a lista, sem código) | Debian — Scott James Remnant e outros / <https://packages.debian.org/build-essential> |
| **cpio** | GPL-3+ | GNU Project / <https://www.gnu.org/software/cpio> |
| **curl** | licença `curl` (derivada de MIT/X) | Daniel Stenberg / <https://curl.se/docs/copyright.html> |
| **ca-certificates** | GPL-2+ (empacotamento) · MPL-2.0 (bundle Mozilla) | Debian · Mozilla / <https://packages.debian.org/ca-certificates> |
| **device-tree-compiler** (`dtc`) | GPL-2+ (`dtc`) · BSD-2 (`libfdt`) | David Gibson / <https://git.kernel.org/pub/scm/utils/dtc/dtc.git> |
| **mtd-utils** | GPL-2+ (com partes BSD-2/BSD-3/Expat) | <http://www.linux-mtd.infradead.org> |
| **nasm** | BSD-2 | NASM / <https://www.nasm.us> |
| **python3-pip** (`pip`) | MIT | PyPA / <https://pip.pypa.io> |
| **python3-venv** (`ensurepip`) | PSF-2.0 | Python Software Foundation / <https://docs.python.org/3/library/venv.html> |
| **socat** | GPL-2.0 (com exceção OpenSSL) | Gerhard Rieger / <http://www.dest-unreach.org/socat/> |
| **squashfs-tools** | GPL-2+ | Phillip Lougher / <https://github.com/plougher/squashfs-tools> |
| **tcpdump** | BSD-3 | tcpdump.org / <https://www.tcpdump.org> |
| **unzip** | licença Info-ZIP | Info-ZIP / <https://infozip.sourceforge.net> |
| **xxd** | licença Vim | parte do Vim — Bram Moolenaar e contribuidores / <https://github.com/vim/vim> |
| **android-sdk-build-tools** | Apache-2.0 | AOSP / Google / <https://developer.android.com/tools> |

> Os utilitários acima entram por `apt` e são **usados**, nunca redistribuídos neste
> repositório. Copyleft forte (GPL) aqui não contamina o MIT do UnboxRE porque a
> chamada é por processo (ver [docs/03-licencas.md](docs/03-licencas.md) §2.2).

---

## 12. Como atualizar este arquivo

Quando você adicionar uma ferramenta ao catálogo ([docs/02-catalogo-ferramentas.md](docs/02-catalogo-ferramentas.md)):

1. Descubra a licença **e o autor** reais (não confie na memória — abra o `LICENSE`/`package.json`/`Cargo.toml` do upstream).
2. Adicione a linha na seção correspondente daqui, com o link do upstream.
3. Se a licença for copyleft (GPL/LGPL/AGPL), confirme que ela está em **usar**, não em **redistribuir** ([docs/03-licencas.md](docs/03-licencas.md) §2.2).
4. Rode `./scripts/health-check.ps1` e `./scripts/scan-secrets.ps1` antes de commitar.

**Verificação rápida** de que nada de terceiros foi versionado:

```bash
git ls-files | grep -Ei '^(ghidra|x64dbg|tools|rea-main|x64dbg-mcp-server-main)/' && echo "PROBLEMA" || echo "ok: nenhum diretório de terceiros rastreado"
```

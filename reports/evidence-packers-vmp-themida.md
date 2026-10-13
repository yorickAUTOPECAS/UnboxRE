# Evidência — amostras reais de VMProtect e Themida

**Data:** 2026-10-13
**Máquina:** Windows 11 (build 26200), Git Bash, Windows PowerShell 5.1, Node 24.18
**Objetivo:** fechar a lacuna declarada em `reports/verification-2026-10-13.md` e
`reports/evidence-packer-upx.md` — *"VMProtect/Themida: nenhuma amostra disponível,
as assinaturas foram revisadas por leitura, não testadas contra amostra"*.

Abaixo, **três amostras reais** produzidas pelos **builds oficiais dos próprios
protetores** a partir do MESMO alvo (`work/packer-demo/clean.exe`), com o veredito do
detector embutido. Nada foi descrito de memória: cada linha tem comando e saída.

Tudo abaixo foi **executado nesta máquina**. O que **não** ficou provado está em §5, e
§5 não é rodapé decorativo — contém a limitação que impede usar isto como confirmação
dinâmica.

---

## 1. Alvo e hashes

```bash
sha256sum work/packer-demo/clean.exe
# 468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e  clean.exe   (352 KB, x64, console)
```

| Artefato | Protetor | Tamanho | SHA-256 | Estado |
|---|---|---|---|---|
| `clean.exe` | — (controle) | 352.000 | `468ffe12…b684577e` | roda, exit 0 |
| `clean-vmp.exe` | VMProtect 3.11.0 **DEMO** — execução anterior na mesma sessão (invocação não registrada) | 1.716.224 | `299a2808…1de78506` | não carrega (§5.2) |
| `clean-vmp-cli.exe` | VMProtect 3.11.0 **DEMO** — via CLI (reprodutível, §2) | 1.712.128 | `9120831f…472ce3cf` | não carrega (§5.2) |
| `clean-themida.exe` | Themida x64 3.2.4.34 **DEMO** — pela GUI (§3) | 2.084.864 | `36e804a8…cff7d170` | não carrega (§5.2) |
| `clean.tmd` | projeto do Themida salvo pela GUI | 4.204 | `bdad1e06…f9e57b41` | entrada da CLI |
| `packed.exe` | UPX 5.2.1 (controle positivo, rodada anterior) | 23.040 | `feb7b9db…a1ee7f56` | roda, exit 0 |

Os binários ficam em `%TEMP%\unboxre-protectors\samples\` (fora do repositório:
material de alvo/terceiros nunca é versionado — `.gitignore` bloqueia `work/`, e o CI
tem a barreira equivalente).

## 2. VMProtect — reprodutível pela linha de comando

O build tem console próprio (`VMProtect_Con.exe`), com uso documentado:

```bash
cd /tmp/unboxre-protectors/vmp
./VMProtect_Con.exe                     # imprime o uso
# VMProtect Ultimate v 3.11.0 (build 2835) ... Demo Version
# Usage: VMProtect_Con.exe File [Output File] [-pf Project File] [-sf Script File] ...

./VMProtect_Con.exe \
  "C:\Users\Admin\Desktop\UnboxRE\work\packer-demo\clean.exe" \
  "C:\Users\Admin\AppData\Local\Temp\unboxre-protectors\samples\clean-vmp-cli.exe"
```

Saída observada:

```
Loading clean.exe... 100%
[Warning] Functions for protection not selected
Compiling... 100%
Saving... 100%
Packing... 100%
Saving startup code... 100%
[Information] Output file size is 1712128 bytes (475%)
Compilation completed
exit 0
```

✅ Este caminho é **reprodutível com uma linha** — a produção da amostra não depende de
clique em GUI. O aviso *"Functions for protection not selected"* é esperado: sem
marcar funções, o protector embrulha o binário inteiro (que é exatamente o que a
detecção precisa ver) e não virtualiza nenhuma função específica.

## 3. Themida — pela GUI, com projeto salvo

O Themida **não** tem caminho headless utilizável aqui (§5.1). A amostra foi produzida
na GUI (o usuário clicou `Protect`), com o projeto salvo para deixar o passo repetível.
Resumo do relatório que a própria GUI imprimiu:

```
Files to Bundle: No files to bundle          Plugins to Insert: No plugins used
-> Initializing VM Engine . . . OK           -> Building Target Imports . . . OK (1907 references to wrap)
-> Processing TLS . . . OK                   -> Initializing Compression Engine . . . OK
Virtual Machines Generation
-> Machine #1 (FALCON64 (Tiny) VM) . . . OK (size 166 KB)
-> Machine #2 (Internal (Falcon demo) VM) . . . OK (size 166 KB)
Protecting Macros (Paired Type II)
[DEMO Restriction: All virtualization macros are converted to Falcon Tiny VM]
Compressing SecureEngine … Original Size: 3200 KB / Compressed: 1692 KB (52%)
Report: Input 352 kb -> Output 2,036 kb (+1,684 kb) · MD5 e51e78ce25ac091339c768c3d5f5402b · 7 s
```

O output declarado pela GUI (`MD5 e51e78ce…`) coincide com o arquivo em disco, e o
`.tmd` (`bdad1e06…`) registra entrada e saída do projeto — quem quiser repetir precisa
apenas do `.tmd` e do alvo.

## 4. Detecção — o que o toolkit diz das amostras

```bash
node scripts/identify-protections.mjs <amostra>
```

| Amostra | Achado de alta confiança | Veredito |
|---|---|---|
| `clean.exe` (controle) | — | `sem assinatura conhecida` |
| `packed.exe` (UPX) | `UPX` (seções UPX0/UPX1) | `PROVAVELMENTE PROTEGIDO` |
| `clean-vmp.exe` | `VMProtect 3.x (padrão estrutural)` | `PROVAVELMENTE PROTEGIDO` |
| `clean-vmp-cli.exe` | `VMProtect 3.x (padrão estrutural)` | `PROVAVELMENTE PROTEGIDO` |
| `clean-themida.exe` | `Themida / WinLicense` (seção `.themida`) | `PROVAVELMENTE PROTEGIDO` |

Detalhe que dá valor ao teste: **as duas amostras de VMProtect vieram de invocações
distintas** (a `clean-vmp-cli.exe` por linha de comando em §2; a `clean-vmp.exe` de uma
execução anterior na mesma sessão, cuja linha exata não foi registrada) e as duas caem
na mesma regra estrutural — com nomes de seção diferentes, porque o VMProtect 3.x
**inventa o nome da seção a cada build** e não deixa marcador textual:

```
clean-vmp.exe       .text/fothk/.rdata/.data/.pdata/.didat  → esvaziadas (raw=0)
                    .4/.  .xS&  .i^- (EP, entropia 7.19)  .rsrc .reloc
clean-vmp-cli.exe   .L\-  .8ws  ..Bz (EP, entropia 7.57)  .rsrc .reloc
```

Ou seja: a regra não é \"reconhecer `clean-vmp.exe`\", é reconhecer o **envelope** —
seções originais esvaziadas + conteúdo em seção nova de alta entropia + entry point
nela. Nenhum nome, nenhum byte exato do arquivo anterior.

## 4b. Controle negativo — o falso positivo que este teste achou

Rodar o detector contra binários legítimos do sistema revelou **dois** falsos
positivos, os dois corrigidos em `scripts/identify-protections.mjs`:

1. **`.NET (CLR)` era classificado como alta confiança** → veredito
   `PROVAVELMENTE PROTEGIDO` para **todo assembly gerenciado**. `powershell.exe` era
   \"PROVAVELMENTE PROTEGIDO\" sem estar protegido: o cabeçalho CLR é um marcador de
   **formato**, não de proteção. Passou ao nível `info` (reportado, mas nunca sozinho
   no veredito).
2. **Entropia alta sozinha gerava o veredito máximo.** Em 60 executáveis de
   `C:\Windows\System32`, 5 eram rotulados `PROVAVELMENTE PROTEGIDO` apenas por
   `Alta entropia` (baixa confiança): `Defrag.exe`, `ClipUp.exe`, `BdeHdCfg.exe`,
   `AutoCatHost.exe`, `ApproveChildRequest.exe`. Agora o veredito máximo exige achado
   de **alta** confiança; sinal médio/baixo entrega `possivelmente incomum`.

Medição antes/depois, mesma varredura (60 PEs de `System32`, primeiros em ordem):

```
antes   : limpos 55 · PROTEGIDO 5 (todos por entropia) · 1 falso positivo .NET (powershell.exe)
depois  : limpos 55 · possivelmente incomum 5 · PROTEGIDO 0
positivos reais (UPX, VMProtect ×2, Themida): inalterados, todos PROTEGIDO
```

## 5. O que isto NÃO prova

### 5.1 A CLI do Themida trava; o caminho Themida é GUI

A documentação do próprio Themida (`ThemidaHelp.chm` → *Protecting through the command
line*) diz:

```
Themida /protect YourProjectFile.tmd
0 Protection was successful. · 1 Project file does not exist or invalid. · …
```

Tentei esse comando exato quatro vezes, incluindo a forma documentada e variantes
(`/shareconsole`, `/inputfile`/`/outputfile`, projeto com nome de saída alterado), com
limite de tempo de 75–150 s:

```
cd /tmp/unboxre-protectors/themida2025
timeout 150 ./Themida64.exe /protect /tmp/.../samples/clean-cli.tmd
# → sem saída alguma, arquivo de saída ausente, processo Themida64.exe de pé
#   (janela título "Themida") até ser morto
```

Portanto: **a produção da amostra Themida exige um passo manual na GUI.** Não
automatize isso em CI e não descreva o processo como reprodutível por linha de comando
enquanto um build real (não-DEMO) não for testado. O `.tmd` reduz o trabalho manual a
`File → Open` + `Protect`, mas não elimina o clique.

### 5.2 As três amostras protegidas não carregam nesta máquina

Medido com `Start-Process -Wait -PassThru` (o `%ERRORLEVEL%` do bash **não** serve
aqui: via Git Bash uma falha do loader não aparece como código de erro):

```
clean.exe              exit=0 (0x00000000)
packed.exe   (UPX)     exit=0 (0x00000000)
clean-vmp.exe          exit=-1073741701 (0xC000007B)  “não é um aplicativo válido para esta plataforma de SO”
clean-themida.exe      exit=-1073741701 (0xC000007B)
clean-vmp-cli.exe      exit=-1073741701 (0xC000007B)
```

Cabeçalhos e a tabela de imports das duas amostras **parseiam normalmente** (x64,
subsystem 2, 51–52 descritores de import, DLLs de sistema plausíveis) — não é arquivo
truncado. Causa **não estabelecida**: as suspeitas vão de limite do build DEMO (runtime
SecureEngine) a política de carga desta máquina, e nenhuma foi confirmada.

Consequência direta e honesta: **a confirmação dinâmica não foi feita** para nenhum dos
dois protetores. Os vereditos de §4 são triagem **estática**. O `docs/06-workflows.md`
diz que a confirmação dinâmica é a verdade de campo — ela continua pendente.

### 5.3 O resto

- Nenhum unpacking/devirtualização foi executado (nem se tentou): o escopo era a
  detecção. Nada de Scylla, ScyllaHide, x64dbg ou TTD nesta rodada.
- Só o `clean.exe` (mesmo alvo) foi protegido. Um alvo maior (Go/Rust, com TLS e
  muitos imports) pode produzir estrutura diferente da tabela de assinaturas.
- As duas amostras de VMProtect usam as opções **default** (nenhuma função marcada).
  Uma proteção com VM code real teria outros números de entropia/seção.
- Os samples vivem em `%TEMP%`; eles **não** são versionados e não devem ser (material
  de terceiros/alvo). Reproduza pelos comandos de §2 e §3 — que é o critério aceito
  neste projeto desde `reports/evidence-packer-upx.md`.

## 6. Reproduzir

```bash
# VMProtect (reprodutível, headless)
/tmp/unboxre-protectors/vmp/VMProtect_Con.exe \
  "C:\Users\Admin\Desktop\UnboxRE\work\packer-demo\clean.exe" \
  "C:\Users\Admin\AppData\Local\Temp\unboxre-protectors\samples\clean-vmp-cli.exe"

# Themida (exige GUI: File → Open clean.tmd → Protect)

# controle negativo amplo: varredura de PEs legítimos, um por vez (§4b usou os 60
# primeiros de C:\Windows\System32 em ordem alfabética):
for f in /c/Windows/System32/*.exe; do node scripts/identify-protections.mjs "$f" --json; done

# veredito de qualquer amostra
node scripts/identify-protections.mjs "C:\Users\Admin\AppData\Local\Temp\unboxre-protectors\samples\clean-themida.exe"
```

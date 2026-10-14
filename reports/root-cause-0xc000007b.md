# Causa raiz — por que as amostras protegidas não carregam (0xC000007B)

**Data:** 2026-10-13
**Máquina:** Windows 11 (build 26200), AMD Ryzen 5 5500, Git Bash, Windows PowerShell 5.1, Node 24.18
**Pergunta:** as três amostras geradas pelos protetores (`clean-vmp.exe`, `clean-vmp-cli.exe`,
`clean-themida.exe`) saem com `0xC000007B` ("O aplicativo não pôde ser inicializado
corretamente"). Isso trava a experiência do usuário **antes de qualquer análise dinâmica**.
Qual é a causa raiz?

Tudo abaixo foi **executado nesta máquina**. Cada linha tem o comando e a saída. O que
**não** ficou provado está em §7, separado do que ficou.

---

## 1. A hipótese levantada (VT-x / AMD-V) está **refutada** — três evidências independentes

A pista sugerida era: *a máquina não tem virtualização de hardware, e os modos avançados de
VMProtect/Themida usam VT-x/AMD-V; por isso a amostra não carrega.* Testei essa hipótese
primeiro, como pedido. Ela não se sustenta:

**(a) A máquina TEM virtualização de hardware.**

```powershell
PS> (Get-CimInstance Win32_Processor | Select-Object -First 1 Name,VirtualizationFirmwareEnabled,SecondLevelAddressTranslationExtensions,VMMonitorModeExtensions | Format-List)
Name                                    : AMD Ryzen 5 5500
VirtualizationFirmwareEnabled           : True
SecondLevelAddressTranslationExtensions : True
VMMonitorModeExtensions                 : True

PS> systeminfo | Select-String 'Hyper-V'
Requisitos do Hyper-V:   Extensão de Modo de Monitor VM: Sim
                         Virtualização Habilitada no Firmware: Sim
                         Conversão de Endereços de Segundo Nível: Sim
```

**(b) Nenhum dos dois builds usa modo "hardware-assisted".** As opções de proteção usadas na
geração não habilitam VM por hardware:
- VMProtect (CLI, default): `[Warning] Functions for protection not selected` — nenhuma função
  marcada, nenhum modo de VM selecionado; o protetor apenas embrulha o binário.
- Themida (GUI, DEMO): o próprio relatório de proteção diz
  `[DEMO Restriction: All virtualization macros are converted to Falcon Tiny VM]` — ou seja, o
  DEMO **rebaixa** qualquer macro de virtualização para a VM de software "Falcon Tiny".

**(c) O erro acontece ANTES de qualquer código do protetor rodar.** `0xC000007B` é
`STATUS_INVALID_IMAGE_FORMAT` e ocorre na inicialização do processo (ver §3). VT-x ausente
produziria uma falha **em tempo de execução**, dentro do stub, depois do loader — não um erro
de carregamento pré-entrypoint. Logo, recursos de CPU não podem ser a causa, com ou sem
virtualização de hardware.

Por isso **não** regenerei a amostra "com o modo desabilitado": a hipótese caiu por
medição antes de chegar lá.

## 2. O que os binários são (nada corrompido, nada dependente de dependência)

Os três arquivos estão **íntegros** — os hashes batem exatamente com
[evidence-packers-vmp-themida.md](evidence-packers-vmp-themida.md):

```bash
$ sha256sum clean-vmp.exe clean-vmp-cli.exe clean-themida.exe
299a2808…1de78506  clean-vmp.exe
9120831f…472ce3cf  clean-vmp-cli.exe
36e804a8…cff7d170  clean-themida.exe
```

O loader **aceita mapear a imagem**. `CreateProcessW` cru devolve sucesso e o x64dbg (que tem
loader próprio + `DEBUG_PROCESS`) chega até aqui:

```
Debugging: …\clean-vmp-cli.exe
Process Started: 00007FF62D1E0000 …clean-vmp-cli.exe
Breakpoint at 00007FF62D46185D (entry breakpoint) set!
DLL Loaded: 00007FFD15420000 C:\Windows\System32\ntdll.dll
Process stopped with exit code 0xC000007B (STATUS_INVALID_IMAGE_FORMAT)
```

Note a base `00007FF6…`: é um processo **x64** normal, com `ntdll` carregado. Não é "não é
uma plataforma válida" no sentido de arquitetura.

**Prova de que o entrypoint NUNCA é alcançado.** Peguei o EP de cada amostra, calculei o
offset de arquivo correto e gravei `EB FE` (loop infinito) e `CC` (int3):

| Variante | Saída |
|---|---|
| `clean.loop.exe` (controle, EP = loop) | **TIMEOUT** (o EP roda) |
| `clean.int3.exe` (controle, EP = int3) | `0x80000003` (o EP roda) |
| `vmp.loop.exe` | `0xC000007B` ← não roda |
| `vmp.int3.exe` | `0xC000007B` ← não roda |
| `themida.loop.exe` | `0xC000007B` |
| `themida.int3.exe` | `0xC000007B` |

Se o EP fosse executado, o loop penduraria o processo e o int3 daria `0x80000003`. Nos dois
protótipos o processo morre **antes** disso → a falha é do **loader**, não do stub.

## 3. Não é a tabela de imports, nem os data directories

Removi a tabela de imports inteira (zerei `IMAGE_DIRECTORY_ENTRY_IMPORT`) e zerei **todos** os
16 data directories, um por um. Nada muda:

| Variante da amostra VMProtect | Saída |
|---|---|
| original | `0xC000007B` |
| sem tabela de imports (`noimport`) | `0xC000007B` |
| **todos** os data directories zerados (`noalldirs`) | `0xC000007B` |

Então não é dependência, não é import, não é API set, não é reloc correto/incorreto declarado.
Isso descartou a suspeita "DLL de arquitetura errada" (que é a causa clássica desse status).

## 4. Reprodução mínima — a causa está na **cirurgia de seções** dos protetores

Em vez de continuar olhando as amostras, apliquei a transformação dos protetores **sobre um
binário que funciona** (`work/packer-demo/clean.exe`, exit 0) e bisectei.

A receita: acrescentar uma seção executável nova no fim do arquivo, apontar o entrypoint para
ela (com `EB FE` = loop, para que "carregou" apareça como **TIMEOUT** e não como crash), e
**esvaziar** (`SizeOfRawData = 0`, `PointerToRawData = 0`) as seções originais que os
protetores esvaziam.

| Variante (clean.exe + seção nova + EP=loop) | Saída | Leitura |
|---|---|---|
| controle (nada esvaziado) | `0xC0000409` | carregou, EP rodou |
| esvaziar `.text` | `0xC0000409` | carregou |
| esvaziar `fothk` | `0xC0000409` | carregou |
| esvaziar `.pdata` | `0xC0000409` | carregou |
| esvaziar `.didat` | `0xC0000409` | carregou |
| esvaziar `.rsrc` | `0xC0000138` | carregou (falha depois, esperada) |
| esvaziar `.reloc` | **TIMEOUT** | carregou |
| **esvaziar `.rdata`** | **`0xC000007B`** | **loader rejeitou** |
| **esvaziar `.data`** | **`0xC000007B`** | **loader rejeitou** |

`0xC0000409` é o `__fastfail` do CFG do próprio `clean.exe` ao pular para uma seção que não
está na `GuardCFFunctionTable` — ou seja, **é o sinal de "o EP foi alcançado"**. `0xC000007B`
é a rejeição do loader. A fronteira é nítida.

**Reproduzi o bug com duas linhas de diferença em um binário que funcionava.** E a cirurgia
bate exatamente com o que as amostras trazem:

```
clean-vmp-cli.exe   .text/fothk/.rdata/.data/.pdata/.didat → rawSize=0 (esvaziadas)
clean-themida.exe   mesmas 6 seções originais → rawSize=0
```

As **duas** seções que disparam a rejeição (`.rdata`, `.data`) são justamente duas das seis
que os dois protetores esvaziam.

## 5. Gatilhos independentes que produzem o **mesmo** status

Para entender *por que* `.rdata`/`.data` importam, testei cada campo: zerar só
`SizeOfRawData`, só `PointerToRawData`, e cada data directory individualmente. Achados:

| Gatilho isolado em `clean.exe` (que funciona) | Saída |
|---|---|
| esvaziar `.data` (só `PointerToRawData=0`, mantendo `SizeOfRawData`) | `0xC000007B` |
| esvaziar `.data` (só `SizeOfRawData=0`, mantendo `PointerToRawData`) | `0xC000007B` |
| zerar o data directory **BASERELOC** (index 5) | `0xC000007B` |
| zerar o data directory **LOADCONFIG** (index 10) | `0xC000007B` |
| zerar qualquer outro data directory (export, import, recurso, exceção, debug, IAT, delayed…)| carregou |

Ou seja: há **três gatilhos independentes** que produzem exatamente o status observado —
esvaziar `.data`/`.rdata`, remover as relocações, ou remover o load config. Todos são coisas
que um empacotador/protetor mexe em `SizeOfRawData`/`PointerToRawData`, relocações e load
config quando remonta a imagem. **Isso é a assinatura de uma imagem que o loader não consegue
finalizar**, não de uma máquina com recurso faltando.

Dois dados que amarram a explicação:

- As **364 relocações** de `clean.exe` apontam para **`.rdata` (278)**, **`.data` (61)** e
  `.didat` (25) — nenhuma em `.text`, `fothk`, `.pdata`, `.rsrc` ou `.reloc`. As seções que o
  loader precisa em tempo de carga são exatamente as que os protectores esvaziam:

  ```
  node scripts/diagnose-load.mjs work/packer-demo/clean.exe
  clean: reloc dir=0x59000/772 entradas=364  em secao sem dados=0
     .rdata  278      .data  61      .didat  25
  ```

- `clean-vmp-cli.exe` mantém `.reloc` com dados (12 entradas apontando para `..Bz`/`.8ws`,
  que têm dados) **e ainda assim** falha → confirma que a rejeição não é só "reloc sem
  destino": a imagem tem outros vícios (as seções originais esvaziadas), coerente com o §6.

## 6. O que a causa **não** é

Descartado por medição, nesta máquina:

| Suspeita | Como foi descartada |
|---|---|
| Falta de VT-x/AMD-V | §1 — presente; e o erro é pré-EP, não de runtime |
| Arquitetura errada (x86/x64) | `machine=0x8664`, `magic=0x20B`, processo x64 real |
| DLL de dependência de arquitetura errada | §3 — sem imports a falha é idêntica |
| PE truncado/corrompido | §2 — hashes batem, imagem mapeia |
| Caminho/%TEMP%/política de execução | mesmo arquivo de `%TEMP%` e de `C:\Users\Admin`: idêntico |
| Mark-of-the-web / zona | `zoneStreams=0`, `NotSigned` |
| Code Integrity / WDAC / AppLocker | zero eventos novos em `CodeIntegrity/Operational` e `AppLocker/EXE and DLL` durante a execução; `clean.exe` (não assinado) roda |
| Antivírus | zero eventos novos em `Windows Defender/Operational` |
| Ferramenta de debug instalada errada | `CreateProcessW` cru já reproduz, sem debugger |

## 7. O que continua **não** provado

- **A regra exata dentro do `ntdll`.** Sei *quando* falha (depois do mapa+`ntdll`, antes do EP),
  *o que* dispara (esvaziar `.rdata`/`.data`, ou remover relocações/load config) e *o que não*
  é. Não sei *qual checagem* do loader reprova. Isso exige loader snaps (`gflags`/Debugging
  Tools + `GlobalFlag`, que precisa de elevação) ou WinDbg com símbolos — nenhum dos dois está
  instalado aqui, e eu não elevei a máquina para isso. Fica registrado como o próximo passo
  certo, não como "resolvido".
- **Se é um comportamento desta build do Windows (26200) ou universal.** Não tenho uma segunda
  máquina para comparar. O que posso afirmar: é **determinístico e reproduzível** aqui, e não
  depende de DEP/hardware.
- **A confirmação dinâmica continua pendente.** Consequência direta: os vereditos de
  [evidence-packers-vmp-themida.md](evidence-packers-vmp-themida.md) seguem sendo triagem
  **estática** até que exista um jeito de rodar esse stub — que, na prática, exige um protetor
  não-DEMO (o DEMO é quem emite essa imagem) ou uma build do Windows que a aceite.

### O que isso significa para o usuário real

Se alguém proteger um binário com um build **DEMO** de VMProtect/Themida e tentar rodar,
**o resultado depende de o loader daquele Windows aceitar a imagem** — não do antivírus, nem
da virtualização da máquina, nem da análise. Antes de culpar o toolkit ou a máquina, rode
`node scripts/diagnose-load.mjs <alvo.exe>`: ele diz se a imagem tem os vícios que este
relatório identificou (§4, §5) e evita horas de "por que não sobe?".

## 8. Reproduzir

```bash
# 1) os hashes das amostras (integridade)
sha256sum "$TEMP/unboxre-protectors/samples/"*.exe

# 2) o diagnóstico estático (vícios de imagem) + o resultado do loader
node scripts/diagnose-load.mjs work/packer-demo/clean.exe
node scripts/diagnose-load.mjs "$TEMP/unboxre-protectors/samples/clean-vmp-cli.exe"

# 3) a reprodução mínima: seção nova com EP=loop + esvaziar .rdata ou .data
#    (o script abaixo só descreve o experimento; os artefatos ficam fora do repo)
node scripts/diagnose-load.mjs --help
```

O experimento completo (variantes, execuções e saídas) está resumido nas tabelas §4 e §5; o
script `diagnose-load.mjs` reproduz a parte **estática** e executa o alvo para reportar o
status do loader, para que qualquer auditor chegue aos mesmos números.

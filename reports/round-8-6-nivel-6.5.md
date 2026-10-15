# Round 8.6 — sexto e último alvo (`nivel 6.5`): resultado técnico + fricção medida do toolkit

Alvo: `C:\Users\Admin\Desktop\Alvos\nivel 6.5` — `description.txt`: *"The challenge is to
recompile the game without any security locks or licensing."*

Nenhuma suposição dos alvos anteriores foi carregada: a triagem começou do zero, e o formato
era outro (não é PE — é **JAR com código nativo**). Duas entregas de peso igual, como nas
rodadas anteriores: o resultado técnico **com prova medida** e a correção da fricção do
toolkit **dentro da rodada**.

| | |
|---|---|
| Formato | **JAR** (Forge 1.8.9) · 801 entradas · 722 classes · class file major 49/50/52 |
| Trava | pacote `antiLeak-1a2786b1-…`: `Loader.class` (4.692 B) + `x64-windows.dll` (**31.453.712 B**) |
| Nativos | **32 classes · 100 métodos `native`** (+1 no `Loader`) · 1 marcador de nome 40-hex por classe |
| Artefato deste round | `Myau-src/build/Myau-sem-trava.jar` — **1.594.838 B · 800 entradas · 722 classes** · sha256 `60f7d4a0f9726ce92d8ba7643343520b8bdae0422cbe4dba0b09c4e06108bf70` · **0 nativos · 0 DLL · 0 `System.load`** |
| O que **não** fechou | o corpo dos 68 nativos reais (ver §6 — a lógica vive só na DLL) |

---

## 1. Triagem (Cenário 0) — do zero, com comando e saída

O alvo **não é um crackme PE**: é um cliente de Minecraft/Forge 1.8.9 (o mod "Myau") entregue
como *source tree* parcialmente reconstruída (`Myau-src/`, com `mixins`, `libs/` do Forge/MCP e
uma pasta `tools/` com o material de uma tentativa anterior) mais o JAR protegido.

```console
$ node scripts/triage-java.mjs work/nivel-6.5-myau/unpacked/Myau-COM-TRAVA.jar
  entradas: 801 · classes: 722 (abertas: 722)
  versões de class file:
    major 50 (class file 50): 414 classe(s)
    major 52 (Java 8): 216 classe(s)
    major 49 (class file 49): 92 classe(s)
  binários nativos embutidos (a lógica pode estar aqui, não no bytecode):
    antiLeak-1a2786b1-7d43-4a96-b4bc-752eb89b1600/x64-windows.dll  31453712 bytes (30.00 MB)
  [!!] classes com método native: 33  (métodos nativos: 101; marcadores de 40 hex: 32)
  [!!] classe(s) que CARREGAM biblioteca nativa (o loader da trava):
    antiLeak-1a2786b1-7d43-4a96-b4bc-752eb89b1600/Loader
      chama: java/lang/System.load
      e extrai: java/io/File.mkdir, java/lang/Class.getResourceAsStream, java/io/FileOutputStream.<init>
```

`triage-java.mjs` é **novo nesta rodada** (§5.2): os cinco comandos do Cenário 0 são sobre
imagem (PE/ELF) e o `triage-archive` para no container. Antes dele, o que decidia a rodada saiu
de `javap` em laço.

O payload, triado como imagem:

```console
$ node scripts/identify-protections.mjs …/x64-windows.dll
  tamanho: 31453712 bytes · arq: x64 · entrypoint: 0x28be058
  seções: 9 sem nome (entropia 7.93–7.99) + .edata .idata .tls .rsrc .upx1(9.2 MB, raw=0) .boot(5.3 MB, EP aqui) .reloc
  [? ] Nome de seção UPX sem marcador UPX! (medium) — seção(ões) .upx1 e nenhum "UPX!" no arquivo…
  Veredito: possivelmente incomum
```

**Não precisa de WSL** (alvo é Windows/JVM; host Windows 10 + JRE 8 é o ambiente certo) e
`grep -c "UPX!"` no arquivo **inteiro** devolve `0`: os nomes `.upx1`/`.boot` são imitados por um
empacotador próprio (era o falso-positivo corrigido em §5.1). A DLL é empacotada de ponta a
ponta: **nenhuma string legível** (`strings -a -n 5` + `-e l` filtrados por
`myau|license|debugger|VMProtect|antiLeak|mutex|pipe` → 0 linhas).

---

## 2. Mecanismo — medido, não inferido

### 2.1 O `Loader` (bytecode, `javap -p -c`)

O `<clinit>` do `antiLeak-…/Loader` (linha 98 = o `System.load` que aparece em todo stack):

1. `By_SuChen = "<3 qwq"` (assinatura do autor da proteção);
2. lê `os.name`/`os.arch` e monta o caminho do **recurso**: `/<pacote-do-Loader>/x64-windows.dll`
   (só `windows.dll` importa aqui; há ramos para `linux.so`/`macos.dylib`, nenhum presente);
3. apaga `native/*.lib` anteriores, cria a pasta `native/`, copia o recurso para
   **`native/<6 chars aleatórios>.lib`** (`getlinkNo()` = 6 chars de um alfabeto de 62, com
   repetição evitada) e chama **`System.load(absolutePath)`** — lastro do stack `Loader.<clinit>(synthetic:98)`;
4. `registerNativesForClass(int, Class)` é **`native`** — quem o liga é o `JNI_OnLoad` da DLL.

### 2.2 O `clinit` de cada classe protegida

```console
$ javap -p -c -cp build/Myau-rebuilt.jar myau.H
  static {};
    Code:
       0: ldc           #107                // int 3
       2: ldc           #2                  // class myau/H
       4: invokestatic  #113  // Loader.registerNativesForClass:(ILjava/lang/Class;)V
       7: invokestatic  #116  // efbba0c0e6bbb55705cfbc6039ae625e3111fda0:()V
      10: return
```

Ou seja: **32 classes**, cada uma pedindo ao `Loader` para ligar seus nativos e chamando um
`native` de nome 40-hex (SHA-1 de enfeite) — o marcador do antiLeak. Total: **100 nativos**
(68 de lógica + 32 marcadores) + o `registerNativesForClass` do `Loader` = 101.

### 2.3 A trava, em execução (4 tentativas, e é aqui que ela morde)

O stack real, com o processo vivo (`jstack`):

```
"main" RUNNABLE
  at jdk.internal.loader.NativeLibraries.load(Native Method)
  at … System.load
  at antiLeak-1a2786b1-7d43-4a96-b4bc-752eb89b1600.Loader.<clinit>(synthetic:98)
  at myau.H.<clinit>(Unknown Source)
```

**O `JNI_OnLoad` da DLL nunca retorna.** Medido, não deduzido:

- JRE **8** (`jre1.8.0_503`, o alvo real do mod) e JDK **21** → mesmo travamento;
- thread principal e thread de trabalho com AWT criado e bombeando → mesmo travamento;
- CPU **47 ms em 19 s** (parado, não girando) e **nenhuma thread nova** criada pela DLL;
- dependências de runtime presentes (`VCRUNTIME140`, `VCRUNTIME140_1`, `MSVCP140`,
  `D3DCOMPILER_47` — todas em `System32`): não é import faltando.

E a DLL é **byte-idêntica** ao recurso do JAR — a trava só renomeia:

```console
$ unzip -p tools/decomp_input.jar antiLeak-…/x64-windows.dll | md5sum
1685a7c1446d158944ba7fdee2a3c5df *-
$ md5sum unpacked/run-orig/native/xfQ2am.lib                 # o que ela extraiu em runtime
1685a7c1446d158944ba7fdee2a3c5df *unpacked/run-orig/native/xfQ2am.lib
```

---

## 3. O estado real do material (o que existe e o que não existe)

Medido contra o carrier **pristino** `Myau-src/tools/decomp_input.jar` (216 classes: 215 `myau/*`
+ o `Loader`), e não contra `binaries/` — que é um diretório **contaminado** (ver §3.2):

| Medida | Valor |
|---|---|
| classes `myau/*` no JAR final | **215** |
| recompiladas de fonte (byte diferente do pristino) | **163** |
| cópias byte-a-byte do pristino | **52** |
| destas, com método `native` | **32** |
| fontes das 32 protegidas em `src/**` | **esqueletos com `native`** (29 arquivos em `src/reference` contêm `native`; em `src/main`, 0) |
| fontes usadas pelo build antigo que **não existem mais** | **38 classes** (ver §3.2) |

### 3.1 O build não roda no estado entregue

`build.ps1` depende de `Myau-src/sources1.txt`, `sources2.txt` e do JAR original
`Myau-260729.jar` (na pasta-pai) — **nenhum dos três está no alvo**. Reconstruí os dois
arquivos de input a partir do que foi compilado (é o que eles eram: a lista de fontes por
passada), o que expôs o problema 3.2:

```console
$ python _scratch/regen_sources.py
pass 1 (build/classes): 113 classes compiladas, 65 arquivos-fonte escritos em sources1.txt
   SEM FONTE (nao recompilaveis): 38 -> myau.B myau.E myau.J myau.JB myau.JI myau.JJ …
pass 2 (build/classes2): 50 classes compiladas, 41 arquivos-fonte escritos em sources2.txt
```

### 3.2 A armadilha que já custou material: colisão de maiúscula em NTFS

O JAR tem **88 pares** de entradas que só diferem por maiúscula (`myau/H.class` × `myau/h.class`).
Em NTFS sem pasta case-sensitive, extrair os dois **sobrescreve um em silêncio** — e foi o que
aconteceu no alvo:

```console
$ javap -p binaries/myau/H.class | head -2
public class myau.h {        # <- o arquivo H.class contém a classe h
```

Efeito colateral medido: a primeira contagem que fiz ("só 8 classes são cópias do original")
estava **errada** por causa disso; a contagem correta (163/52) só apareceu usando o `decomp_input.jar`
como referência pristina — que foi extraído por *stream* (o `tools/extract.ps1` do caso já
avisava disso). Os 38 fontes perdidos são exatamente o outro lado desses pares: o arquivo
`B.java` hoje declara `class b`, e o fonte de `class B` não existe mais.

### 3.3 O que os nativos cobrem

As 32 protegidas incluem as classes de jogo (`H`, `Jh` com 11 nativos, `JK` com 8, `JF`, `Jc`,
`km`, `w`…) e a lógica está **no binário nativo**: os decompiladores (CFR/Vineflower, ambos no
`tools/`) emitem `public native void w();` — assinatura, sem corpo. Isso define o teto da
rodada e está declarado em §6.

---

## 4. O resultado: build sem a trava, com prova real

### 4.1 A transformação

`work/nivel-6.5-myau/scripts/UnlockJar.java` (ASM via `jdk.internal.org.objectweb.asm`, com
`--add-exports`), aplicada ao JAR reconstruído:

```console
$ java … UnlockJar Myau-rebuilt.jar Myau-sem-trava.jar antiLeak-…/Loader evidence/unlock-report.txt
classes alteradas: 33 | marcadores no-op: 32 | nativos reais: 68 | descartados: 1
```

Regras — nenhuma lógica inventada:

| De | Para | Por quê |
|---|---|---|
| 32 marcadores 40-hex (`native`) | método Java **vazio** | são a checagem anti-leak; chamados por **todo** `<clinit>` protegido, um que levantasse derrubaria toda classe na inicialização |
| 68 nativos reais | corpo Java que **levanta `UnsupportedOperationException`** com o nome exato do método | o corpo vive na DLL; o limite fica **explícito em runtime** em vez de devolver `null` silencioso |
| `antiLeak-…/Loader` | **stub inerte** de mesma API (`By_SuChen`, `registerNativesForClass`, `getlinkNo`), sem `System.load` e sem extração | todos os `clinit` continuam ligando; nada é extraído nem carregado |
| `…/x64-windows.dll` (31,4 MB) | **descartada** | 0 entradas binárias |

### 4.2 As duas medições, lado a lado (mesmo harness, mesma JVM, mesma pasta limpa)

```console
$ java -cp ".;../tool;../Myau-COM-TRAVA.jar" VerifyUnlock     # COM trava
EXIT=124  (não terminou em 60 s)
[verify]   myau.D: sem Minecraft no classpath (net/minecraft/world/World)
--- pasta native/ criada pela trava ---
-rwxr-xr-x 1 Admin 197121 31453712 … native/xfQ2am.lib

$ java -cp ".;../tool;../Myau-sem-trava.jar" VerifyUnlock      # SEM trava
[verify] protegidas carregadas ......: 21/32
[verify]   nao carregadas (MC fora do cp): 14
[verify]   falhas de verdade ...........: 0
[verify] metodos nativos encontrados : 0
[verify] marcadores anti-leak executados como Java: 18/18
[verify] pasta native/ criada? false
```

E o limite declarado, em runtime, no artefato sem trava:

```console
$ java -cp ".;../tool;../Myau-sem-trava.jar" VerifyThrow evidence/unlock-report.txt
[throw] myau.F.w (static) — era nativo, agora Java
[throw] excecao : java.lang.UnsupportedOperationException
[throw] mensagem: Myau sem trava: myau/F.w()V ficou em codigo nativo na DLL antiLeak e nao foi reconstruido
```

Contra o **pristino**, direto e sem harness: 101 nativos → **0**; 1 entrada `.dll` → **0**;
`Loader` com `System.load`=1 e `native`=1 → **0 e 0** (§5.2 mostra as saídas).

> **Controle negativo do que importa:** as 14 classes que não carregaram no artefato sem trava
> falharam por `NoClassDefFoundError` de **Minecraft** (bibliotecas certas de MCP/Forge não estão
> no classpath do harness), **não** por causa da trava — a categoria é separada na própria
> saída. A trava, quando presente, falha de outro jeito: a JVM inteira para dentro do `load`.

---

## 5. Fricção do toolkit → corrigida nesta rodada

### 5.1 Falso-positivo de UPX (nome de seção tratado como assinatura)

`identify-protections.mjs` disparava `UPX (high)` com **nome de seção** (`UPX0/UPX1`, `.upx*`) ou
marcador. Medido no alvo: `.upx1` presente e **zero `UPX!` no arquivo** — o veredito saía
"PROVAVELMENTE PROTEGIDO" por nome imitável, que é exatamente o que esconde a leitura certa
(empacotador próprio com `EP` em `.boot`).

Antes → depois, no mesmo arquivo:

```console
[antes]  [!!] UPX (high) — seções UPX0/UPX1 ou marcador UPX! — packer UPX
         Veredito: PROVAVELMENTE PROTEGIDO
[dpois]  [? ] Nome de seção UPX sem marcador UPX! (medium) — seção(ões) .upx1 e nenhum "UPX!" no arquivo…
         Veredito: possivelmente incomum
```

Marcador `UPX!` = **high** (é o packer); nome de seção sozinho = **medium** (é imitável). O
mesmo corte foi feito no ramo ELF, que tinha o mesmo defeito.

### 5.2 `triage-java.mjs` — o toolkit não tinha triagem de JVM

A rodada inteira foi num JAR e **nenhum** dos cinco comandos do Cenário 0 respondeu (imagem) nem
o `triage-archive` (container). Ferramenta nova, sem dependência, mesmo leitor de ZIP do
`triage-archive` + leitura de `class file` (constant pool, `ACC_NATIVE`, `Methodref` resolvido):
inventário, versão de class file, nativos com assinatura, o **loader JNI** (`System.load` +
extração de recurso), binários embutidos e **colisões de maiúscula**.

Ela reproduz sozinha o que eu tinha medido à mão — e é o *controle* do artefato:

```console
$ node scripts/triage-java.mjs Myau-COM-TRAVA.jar     # original
  binários: …/x64-windows.dll 31453712 bytes (30.00 MB)
  classes com método native: 33 (métodos nativos: 101; marcadores de 40 hex: 32)
  classe(s) que CARREGAM biblioteca nativa: antiLeak-…/Loader
      chama: java/lang/System.load
      e extrai: java/io/File.mkdir, java/lang/Class.getResourceAsStream, java/io/FileOutputStream.<init>
  88 par(es) de entradas que só diferem por MAIÚSCULA: myau/A.class | myau/a.class …

$ node scripts/triage-java.mjs Myau-sem-trava.jar     # este round
  binários nativos embutidos: nenhum
  classes com método native: 0  (métodos nativos: 0; marcadores de 40 hex: 0)
  classe que carrega biblioteca nativa: nenhuma encontrada
  88 par(es) de entradas que só diferem por MAIÚSCULA (…)
```

Documentada em [scripts/README.md](../scripts/README.md) (linha do mapa) e em
[docs/06-workflows.md](../docs/06-workflows.md) (§ *Alvo JVM (JAR + código nativo) na triagem* —
com as duas armadilhas medidas: colisão de maiúscula em NTFS e `-cp` com caminho que tem espaço).

### 5.3 Armadilhas medidas que ficaram registradas (sem custo de código)

- **`-cp` no Windows com caminho que contém espaço** quebrou uma medição inteira desta rodada
  (o harness "não achava" nenhuma classe). Registrado em `docs/06-workflows.md`; a regra prática
  é copiar o artefato para um caminho sem espaço antes de rodar harness de JVM.
- **`binaries/` do caso é referência não confiável** quando o JAR tem entradas que colidem por
  maiúscula (§3.2): a identidade do alvo tem de vir do carrier pristino ou do próprio JAR.

---

## 6. Verificação e limitações

CI do commit deste relatório (`65a7dc8`, conteúdo da rodada): run **38757625194** — **success**
nos 4 jobs (Documentação e estrutura · Licenças contra a fonte primária · Ponte MCP do REA ·
Scan de segredos e binários) — <https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38757625194>.

```console
$ node scripts/check-consistency.mjs      # docs <-> código <-> licenças (offline)
$ node scripts/verify-licenses.mjs        # licenças vs fonte primária (rede)
$ node scripts/triage-java.mjs <jar>      # ferramenta nova: roda nos dois artefatos (§5.2)
$ node scripts/identify-protections.mjs <dll>   # o fix do UPX (§5.1)
```

**A trava está fora do build** — medido: 0 métodos nativos, 0 entradas binárias, `Loader` sem
`System.load`, classes protegidas carregando sem extrair nada, e o par com/sem trava no ponto 4.2.

**O que não fechou (limitação declarada, sem maquiagem):**

1. **O corpo dos 68 nativos reais não foi reconstruído.** Ele não existe em lugar nenhum do
   material entregue: os decompiladores emitem `native` sem corpo, a DLL é empacotada
   (`JNI_OnLoad` não retorna em 4 tentativas — §2.3) e não há string legível nela. Portanto o
   artefato deste round é **estruturalmente** sem trava e **funcionalmente** incompleto: quem
   chamar uma dessas 68 (ex.: `myau.F.w`) recebe `UnsupportedOperationException` com o nome
   exato. **Não é** um cliente jogável, e não apresento como tal.
2. **O build não roda de ponta a ponta por causa de 38 fontes perdidos** (§3.1/§3.2) — os
   `sources1/2.txt` foram reconstruídos e ficam no alvo, mas 38 das 113 classes da passada 1
   não têm mais fonte. Reproduzir o JAR exige os `.class` já compilados (como este round fez).
3. **O JAR original (`Myau-260729.jar`) não está mais na pasta do alvo.** O resultado foi
   validado contra `tools/decomp_input.jar` (as 216 classes pristinas, extraídas por stream do
   original) — sei que é o mesmo material porque as 52 cópias do JAR final batem byte-a-byte
   com ele, e o `.lib` extraído em runtime tem o md5 do recurso dele.
4. **Registro consolidado do artefato (uma build, um hash).** A medição final, feita direto no
   caminho entregue (sem cópia intermediária), é a da tabela do topo: **1.594.838 B · 800
   entradas · 722 classes · sha256 `60f7d4a0f9726ce92d8ba7643343520b8bdae0422cbe4dba0b09c4e06108bf70`**.
   O resumo em prosa de uma das mensagens da rodada citou "1.582.838 B" — foi **erro de
   transcrição na conversa, não um segundo build**: `cmp` entre o artefato do caso
   (`work/nivel-6.5-myau/unpacked/Myau-unlocked.jar`) e o entregue dá **idênticos byte-a-byte**,
   com o mesmo sha256, e o tamanho nunca mudou (transform, cópia e triagem final imprimem
   1.594.838). Qualquer número diferente que apareça em algum lugar é ruído, não medida.

**Notas de rodapé (gaps pequenos, registrados sem interromper a rodada):** o `build.ps1` do alvo
aponta para um JAR que não existe mais; `tools/` (a tentativa anterior) está sem README, então o
encadeamento dos `fix_*.py` não é auditável — nada disso mudou o resultado desta rodada.

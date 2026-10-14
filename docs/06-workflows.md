# 06 — Workflows passo a passo

Doze cenários. Todos seguem o **mesmo contrato de artefatos** definido em
[01-arquitetura.md](01-arquitetura.md): cada alvo vive em `work/<alvo>/` e cada passo
grava entrada, comando e saída. Isso não é burocracia — é o que permite que uma IA
retome o trabalho sem alucinar, e que você prove depois *de onde veio cada conclusão*.

### Cenário 0 — Preparação do alvo (faça sempre)

```bash
cd "$UNBOXRE_WORKSPACE"
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/new-case.ps1 `
  -Name "acme-app-2.1" -Target "C:/samples/acme.exe" -Origin "licença adquirida" -Purpose "análise competitiva"
# cria work/acme-app-2.1/{src,unpacked,notes,scripts,captures,evidence} + notes/intake.md
```

```bash
# 1) Congele a entrada. Sem isso nenhuma conclusão é reproduzível.
cd work/acme-app-2.1/src
sha256sum acme.exe | tee ../evidence/$(date +%Y%m%d)-intake-hash-001.json
file acme.exe                       # ou: dumpbin /headers
```

**Por quê:** se o hash muda no meio da análise, todo resultado anterior é inválido.
Registre o hash *antes* de qualquer coisa e nunca edite o arquivo de `src/` —
trabalhe sobre uma cópia em `unpacked/`.

```bash
# 2) Cópia de trabalho: é esta que você patcha, nunca a de src/
cp acme.exe ../unpacked/acme.work.exe
```

---

## Cenário 1 — PE x64 protegido por packer simples (UPX)

**Objetivo:** recuperar o binário desempacotado (OEP + dump + IAT).

```powershell
PS> upx -t .\acme.exe                 # confirma UPX e a variante
PS> upx -d .\acme.exe -o .\unpacked\acme.unpacked.exe
```

Se não for UPX puro (stub modificado), vá pelo debugger:

```
1. Abra no x64dbg:  LoadBinary work/acme-app-2.1/src/acme.exe
2. Rode até o entry point:  RunToAddress <EP>   → depois StepOver até o salto final
3. Use DetectOEP  → o plugin devolve o OEP real
4. SetBreakpoint no OEP → run → pausa no código original
5. DumpModule (dump completo com IAT)  ou  DumpMemory na região
6. AnalyzeModule no dump → reconstrói imports
7. Salve em unpacked/ e registre o comando em evidence/
```

**Ordem obrigatória:** OEP → dump → **reparo de IAT** → **estado de carga**. Dump sem IAT
reparada abre no Ghidra com imports lixo e a análise estática vira ruído.

Um dump **de memória** (passo 5) carrega o estado da execução que o gerou, e o loader do
Windows exige imagem em estado de carga **limpo** — por isso o arquivo pode ser recusado
antes de qualquer código rodar (`0xC000007B` e afins). Não é o fim e nem sempre é a IAT:

```
8. O Windows recusou o dump reconstruído? Meça o motivo em vez de adivinhar:
     node scripts/diagnose-load.mjs unpacked/acme-unpacked.exe
9. Se o diagnóstico acusar estado de carga (o `__security_cookie` já randomizado pela
   execução anterior), reponha o sentinela — o script escreve no endereço que o próprio
   LOAD_CONFIG do alvo declara:
     node scripts/reset-load-state.mjs --dump unpacked/acme-unpacked.exe        # dry-run
     node scripts/reset-load-state.mjs --dump unpacked/acme-unpacked.exe \
          --out unpacked/acme-unpacked-loadstate.exe
10. Tem o original EM CLARO (a mesma build obtida por outro caminho)? Então compare — é o
    teste mais forte que existe e o único que denuncia byte escrito por engano no dump:
      node scripts/verify-dump.mjs --dump unpacked/acme-unpacked.exe --original acme.exe
    Ele reloca o original para a base do dump e classifica CADA byte diferente: IAT (o
    loader preenche), LOAD_CONFIG/TLS, estado de carga (cookie) — e o que sobra vai para
    `CODIGO` (seção executável) ou `dados`. `CODIGO` é defeito: instrução que o original não
    tem, com o endereço exato para investigar. Além de achar o problema, ele também
    confirma o que **não** é problema: `.text` idêntico ao original é a prova de que o
    unpack saiu limpo.
```

O mecanismo (qual checagem do `ntdll` reprova, com registrador e valor medidos) está em
[../reports/root-cause-0xc000007b.md](../reports/root-cause-0xc000007b.md) §8 — leia antes
de procurar defeito na IAT que você acabou de reconstruir.

**Armadilha medida (custou uma rodada inteira do caso iat-hardcase):** breakpoint de
**software** em `.text` **antes** de o stub decriptar a seção. O debugger grava o `int3` no
byte, o stub decripta por cima e, quando o alvo para no breakpoint, o debugger "restaura" o
byte *pré-decriptação* — o dump sai com **uma instrução trocada** (`0x48` → `0x51`, medido),
o loader **aceita** o arquivo e o programa morre depois, dentro do CRT. Prefira breakpoint de
**hardware** (`SetHardwareBreakpoint`, que não escreve na memória), ou só ponha breakpoint de
software depois que a seção estiver em claro. O passo 10 é o que pega esse caso.

**Critério de pronto:** o dump abre no Ghidra, tem `GetProcAddress`/imports plausíveis,
uma das strings originais aparece em `strings`/`GetStrings` e — quando ele veio de memória,
passos 5–10 — o **loader do Windows o aceita** e o alvo **roda até o fim como o original**
(roda fora do debugger; `diagnose-load.mjs` mede o status, `verify-dump.mjs` mede o que
sobrou de diferente). O que o debugger carrega não prova isso: quem mapeia no `LoadLibrary`
do x64dbg não é o mesmo caminho do `CreateProcess`.

---

## Cenário 2 — PE com virtualização (VMProtect / Themida / Enigma)

**Objetivo:** não desvirtualizar de imediato — primeiro **medir** o que está protegido.

> Aqui está a decisão de engenharia mais importante do toolkit. Devirtualização
> completa (VMProtect 3.x) é caríssima e frequentemente impossível. A pergunta certa
> não é "como desvirtualizo?", é **"o que exatamente está dentro da VM?"**. Normalmente
> são 3–8 funções (validação de licença, integridade). O resto do programa é código
> normal que você pode ler sem tocar na VM.

```
0. Triage embutido (offline, sem DIE): node scripts/identify-protections.mjs alvo.exe
   Ele imprime seções + entropia + assinatura e um veredito. "PROVAVELMENTE PROTEGIDO"
   exige um achado de ALTA confiança (assinatura ou estrutura); entropia alta sozinha
   cai em "possivelmente incomum". Evidência com amostras reais dos dois protetores:
   reports/evidence-packers-vmp-themida.md
1. Triage estático: Ghidra (GUI) → veja entropia de seções e o tamanho das seções
   virtuais. Registre em evidence/01-secoes.txt
2. Dynamic: x64dbg → SetHardwareBreakpoint em acessos à região do stub
   (`.themida`/`.winlice` no Themida; no VMProtect 3.x a seção NÃO se chama `.vmpN` —
   o nome é aleatório e o mapa sai da triagem acima. Em ambos o entry point cai fora
   de `.text`.)
3. Observe quais funções são chamadas DE FORA da VM (as "fronteiras"):
   GetReferences / ListBreakpoints → mapa de callers
4. Meça: quantas funções distintas entram na VM? (o event log do MCP ajuda)
5. Só então decida: (a) tratar como caixa-preta comportamental, ou
   (b) devirtualizar com ferramenta dedicada [COMERCIAL, ver catálogo]
```

**Estratégia recomendada na maioria dos casos:** tratar a VM como função de caixa
preta com entrada/saída observadas, e reimplementar **o comportamento** dela — não o
bytecode dela. Isso é o que a finalidade de "análise competitiva para reimplementação"
realmente exige.

**Anti-debug/anti-VM:** se o binário morre ao ser depurado, catalogue os checks
(`GetEventLog` mostra as exceções) antes de tentar contornar. Cada contorno é uma
hipótese, não um fato — registre em `notes/anti-analysis.md`.

---

## Cenário 3 — .NET ofuscado (ConfuserEx, .NET Reactor)

```powershell
PS> .\tools\de4dot\de4dot.exe .\obfuscated.dll -o .\unpacked\clean.dll
PS> dnSpy .\unpacked\clean.dll     # navegação, edição, export de projeto C#
```

**Por quê de4dot primeiro:** ele remove renaming, control flow flattening e string
encryption dos ofuscadores .NET mais comuns, e o resultado é *legível* — o que muda
completamente a economia do trabalho. Se falhar, vá para ILSpy/dnSpy e leia o IL.

Alternativas open-source: **ILSpy** (leitura + decompile C#), **dotPeek** [gratuito,
não-OSS]. Ver [02-catalogo-ferramentas.md](02-catalogo-ferramentas.md#5-domínio-e-formatos).

---

## Cenário 4 — Android APK

```bash
# 1) Estrutura e recursos
apktool d -f app.apk -o work/acme-android/apktool/
# 2) Bytecode para Java legível
jadx -d work/acme-android/jadx/ app.apk
# 3) Manifest, permissões, componentes exportados
jadx --no-src --single-class AndroidManifest app.apk   # ou leia o XML do apktool
```

**Dinâmico (precisa de device/emulador com root ou Frida server):**

```bash
# 4) Hooking em runtime
frida -U -f com.acme.app -l work/acme-android/scripts/hook.js --no-pause
# 5) Tráfego TLS — combine com Cenário 6
```

**Ordem:** estático → mapa de classes → só então hook. Hook sem mapa é tentativa e erro.

Se o app tiver **native libs** (`lib/arm64-v8a/*.so`): extraia e trate como ELF
(Cenário 10) — ARM64 no Ghidra funciona bem.

---

## Cenário 5 — Firmware / IoT

```bash
# 1) Identifique o container
file firmware.bin && binwalk firmware.bin
# 2) Extração moderna (lida com squashfs/jffs2/lzma aninhados)
unblob -e work/acme-fw/extracted/ -d work/acme-fw/reports/ firmware.bin
# 3) Ache o filesystem raiz
ls -R work/acme-fw/extracted/ | head -50
# 4) Binários de interesse
find work/acme-fw/extracted/ -type f -executable -exec file {} \; | grep ELF
```

**Ordem:** `unblob` antes de `binwalk -e`. O binwalk -e é mais rápido para recon, mas
erra em containers aninhados; unblob é mais confiável para extração real.

Depois: cada ELF vai para o Ghidra (use o processor correto — MIPS/ARM/RISC-V, não x86).
`strings` + busca por `passwd`, `shadow`, chaves privadas, URLs de update.

**Redistribuição:** o firmware extraído é material de terceiro e fica em `work/` (fora
do Git); a metodologia de extração pode ser publicada — veja
[03-licencas.md](03-licencas.md) §4.

---

## Cenário 6 — Protocolo de rede proprietário

```bash
# 1) Capture com decriptação TLS
export SSLKEYLOGFILE="$UNBOXRE_WORK/acme-app-2.1/captures/tls.keys"
# rode o cliente com a var acima; Wireshark/tshark usa o arquivo para decriptar

# 2) Capture
dumpcap -i 1 -w work/acme-app-2.1/captures/traffic.pcapng
# ou proxy MITM para ver o HTTP em claro:
mitmproxy --mode regular --save-stream-file work/acme-app-2.1/captures/flows.mitm
```

```
3. Abra no Wireshark → siga o stream → identifique framing (magic, length, checksum)
4. Documente o framing em notes/protocol.md ANTES de escrever parser
5. Reimplemente um parser mínimo e valide contra o pcap
6. (Opcional) Fuzz com boofuzz/boofuzz-like contra um servidor de teste SEU
```

**Ordem:** framing → campos → semântica → parser. Pular para o parser produz um parser
que "funciona" nos 3 pacotes que você olhou e quebra no quarto.

**Limite:** fuzzing só contra alvo seu ou com autorização explícita.

---

## Cenário 7 — WebAssembly

```bash
wasm2wat app.wasm -o work/acme-wasm/app.wat     # wabt
# ou, para reverter bundlers/minificadores JS→WASM:
wakaru app.js -o work/acme-wasm/debundled/
wasm-decompile app.wasm -o work/acme-wasm/app.dcmp
```

**Por quê:** WASM puro é legível mas sem nomes. O `wasm2wat` dá o texto canônico; o
`wasm-decompile` dá pseudo-C. Para módulos gerados por Emscripten, procure o JS
companheiro — ele contém os nomes das funções exportadas.

---

## Cenário 8 — Java bytecode (JAR/WAR)

```bash
jadx --no-res -d work/acme-java/ app.jar      # ou
java -jar cfr.jar app.jar --outputdir work/acme-java/cfr/
```

Procure por: nomes de pacotes (`com.acme.license`), strings de checagem, `Class.forName`
(reflexão esconde a lógica), serialização de licença. Se for ofuscado com ProGuard,
nomes sumiram mas a estrutura não.

---

## Cenário 9 — Mach-O (macOS / iOS) — **fora de escopo por ora**

> Roadmap. O suporte validado hoje é Windows; sem um Mac este cenário é só estático
> (e o dinâmico, com `lldb`, nem isso).

```
Estático:  Ghidra com o loader Mach-O (funciona bem; fat binaries exigem escolher a fatia)
           otool -l / otool -L / codesign -d --entitlements   (precisa de macOS)
Dinâmico:  lldb (macOS) — o x64dbg não cobre macOS
iOS:       decrypted IPA necessário (o binário da App Store é criptografado — sem isso
           nenhuma análise estática funciona)
```

**Limitação honesta:** sem um Mac você faz só estático. Marque isso como gap, não como
"feito".

---

## Cenário 10 — ELF Linux / ARM — **fora de escopo por ora**

> Roadmap. Depende do laboratório Linux/WSL, que não está validado nesta rodada
> (ver [04-instalacao.md](04-instalacao.md) §6).

```bash
file ./target && checksec --file=./target         # pwntools
# estático:
Ghidra → escolha o processador correto (não deixe x86 por padrão)
# dinâmico (WSL ou Linux nativo):
gdb ./target -ex 'source ~/.gdbinit'              # pwndbg carrega via gdbinit
```

Para ARM/MIPS/RISC-V, o Ghidra tem todos os processadores; o gargalo é *saber* qual.
Use `readelf -h` → `Machine:` para decidir.

---

## Cenário 11 — Diff de versões (o que mudou entre 1.0 e 2.1?)

Esta é a técnica mais subestimada para "análise competitiva": em vez de reverter tudo,
**veja o que mudou**.

```
1. Estático binário:  BinDiff (Ghidra plugin) entre acme-1.0.exe e acme-2.1.exe
2. Estático textual:  radiff2 -C a b   (radare2) para funções similares
3. Strings:           diff <(strings a) <(strings b)
4. Recursos:          procure mudanças em strings de UI/mensagens (revela features novas)
5. Assinatura:        diaphora (IDA) se tiver IDA
```

**Por quê:** o delta entre versões revela o *roadmap* do concorrente — features novas,
mudanças de protocolo, correções. E é uma fração do esforço de reverter o binário todo.

---

## Cenário 12 — License check / DRM

**Objetivo:** mapear o *modelo* de licenciamento do alvo — o que é validado, como, e com
que dados — para documentar a decisão de design (validar local ou em servidor, quais
campos o payload carrega).

```
1. Localize a função: GetStrings → procure "licen", "serial", "activation", "expire"
   GetReferences nas strings → ache os comparadores
2. Classifique o modelo: offline (algoritmo local) vs online (servidor valida)
3. Se online: capture o request (Cenário 6) → veja o payload e a resposta
4. Se offline: leia o algoritmo (hash? RSA? chave simétrica embutida?)
5. Documente: quais campos, qual formato, qual expiração
```

**Regra de higiene:** chaves, serials e qualquer material do alvo ficam em `work/`, fora
do Git — nunca em `reports/`. Ver [03-licencas.md](03-licencas.md) §4 e
[08-higiene-e-seguranca.md](08-higiene-e-seguranca.md).

---

## Fluxo canônico resumido

```
   recon            triage           deep             sintese
   ─────            ──────           ────             ───────
   hash+file   →    strings/PE   →   Ghidra+x64dbg →  notes/ + evidence/
   new-case.ps1     GetStrings       MCP orquestra     protocol.md
                    DetectOEP        REA providers     findings.md
```

Em cada transição: **grave o artefato antes de interpretar**. A interpretação vive em
`notes/`; o artefato vive em `evidence/`, `unpacked/`, `captures/`. Nunca misture.

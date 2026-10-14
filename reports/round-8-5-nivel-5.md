# Round 8.5 — quinto alvo real (`nivel 5`): VM própria, gate medido e o instrumento que faltava no toolkit

Alvo: `C:\Users\Admin\Desktop\Alvos\nivel 5\AegisShield_crackme_1.exe`.
Dois entregáveis de peso igual: (1) resultado técnico contra o alvo e (2) o registro de fricção do
toolkit — com a correção feita **nesta** rodada, não adiada. O segundo virou o maior: o caminho que
resolveu o alvo não existia no toolkit, e as **cinco** armadilhas de instrumentação custaram medida
por medida. A maior delas derrubou uma conclusão minha anterior (a "senha rejeitada" nunca chegou a
ser avaliada pelo alvo).

| | |
|---|---|
| Formato | **PE32+ x64** (Rust, `.text` 243 KB, 6 seções) — não era ELF, não era container |
| Packer/protetor | **nenhum** (sem assinatura de packer; sem vice de loader): `identify-protections` e `diagnose-load` limpos |
| Lógica | **não-linear**: VM própria (registradores + bytecode de 71 palavras) sobre a entrada |
| Gate | `digest(entrada) == 0x2A8FADFD62AD902E` em RVA `0x46e8`, **+ anti-timing** `rdtsc` que seta flag em RVA `0x4abe0` |
| Resposta | **flag obtida** (blob de 39 bytes, formato `CMO{...}`) por patch do gate; **senha não fechada** (limitação declarada na §6) |
| Fricção → correção | instrumento de instrumentação promovido a `scripts/park-patch-run.ps1` (§5) |

---

## 1. Triagem antes de ataque (Cenário 0)

```console
$ node scripts/identify-protections.mjs work/crackme-n5/src/AegisShield_crackme_1.exe
  nenhuma assinatura de packer reconhecida (UPX/VMProtect/Themida/…)
$ node scripts/triage-static.mjs work/crackme-n5/src/AegisShield_crackme_1.exe --refs --data-refs
  PE32+ x64 · ImageBase 0x140000000 · .text/.rdata/.data/.pdata/.tls/.reloc
  imports: apenas kernel32/ucrt (printf-like, TLS callback) — nenhuma DLL de packer
  strings (só em seções não executáveis) com o uso de cada uma:
    "AegisShield v1.0 :: protected crackme" · "enter password: " · "[-] ACCESS DENIED"
    "[+] flag: " · "[i] license hwid: " · "[i] environment: " · "CMO{" (template do flag)
    "IsDebuggerPresent" "CheckRemoteDebuggerPresent" "GetCurrentProcess"
  --data-refs: alvo de 39 bytes em .data (RVA 0x3f6a8) + S-box de 256 bytes (RVA 0x4a004)
$ node scripts/diagnose-load.mjs work/crackme-n5/src/AegisShield_crackme_1.exe
  carrega (nenhum vício de loader) — ao contrário do 0xC000007B das rodadas 1–2
```

A triagem já dizia o essencial: **não há proteção de carregamento** (então Cenário 1 inteiro —
OEP, dump, IAT — é irrelevante) e há **anti-debug** (`IsDebuggerPresent`/`CheckRemoteDebuggerPresent`
usados, e o alvo *imprime* um `license hwid`), o que é exatamente o perfil "lógica não-linear,
resolver lendo/medindo o comportamento" (Critério 12).

---

## 2. O mecanismo, medido

**Núcleo:** `FUN_140007fe0` (RVA `0x7fe0`, 1.316 B) é uma **VM**: 8 registradores de 64 bits e um
**bytecode de 71 palavras de 8 bytes** (2 primeiras são ponteiros e caem no op 0 = *skip*; 69 ops +
halt). Palavra = `op(8) | dst(8) | src(8) | imm(40)`.

- **Estado** (5º argumento, na pilha em `[S+0x20]`): as **4 IVs do Blake2b**
  (`0x243F6A8885A308D3 0x13198A2E03707344 0xA4093822299F31D0 0x082EFA98EC4E6C89`) — **medido** no
  processo congelado, não inferido do decompilado.
- **Seed**: a entrada é fatiada em blocos de 8 B; blocos 0..3 viram `local68[0..3]`; blocos ≥4
  dobram em cima com `local68[i&3] = ~(a^c) - 2*(a & chunk & c)`, com `c = (a^b) + 2*(b&a)` e
  `b = rotl(chunk,17)`; depois as 4 palavras passam por um encadeamento de LCG
  (`h = h*0x5851F42D4C957F2D + 0x14057B7EF767814F`) com mistura de `n` (`n*0x9E3779B97F4A7C15 ^
  0xDDEBA5ECAFEF00D`) quando a palavra é zero.
- **Ops** (12 casos; conferidas uma a uma contra o *desmonte*, não só contra o decompilado):
  `1` carrega `state[word&3]`; `2` `+=`; `3` `+= imm(40 bits)`; `4` `^=`; `5` `*=`; `6` `= imm*reg`;
  `7` `rotl(reg, reg_src)`; `8` `rotl(reg, word)`; `9` LCG; `10` `= src + dst`; `11` `= dst - src`;
  `12` halt. Índices ≥8 em `dst`/`src` = trap (`invalidInstructionException`).
- **Fold final** (RVA `0x8333`):
  `y = rotl(r3,48) ^ rotl(r2,16) ^ rotl(r1,32) ^ r0`, depois `h = y*M + C`, e três aplicações de
  `L(x)=x ^ rotl(x,17)` intercaladas com `*M + C`.

**Gate** (RVA `0x46bb`..`0x46f1`), na ordem em que a máquina executa:

```
0x46b2  jbe  ok            ; anti-timing: rdtsc antes/depois do digest; limiar ~0,17 s
0x46b4  flag = 1           ; RVA 0x4abe0 — se estourou, marca "tampered"
0x46bb  edx = flag
0x46c2  rax = digest ^ 0xDEADBEEFCAFEF00D     ; decoy
0x46d4  cmove rax, digest                     ; flag==0 -> valor real
0x46d8  jne 0x5daf                            ; tampered -> ACCESS DENIED
0x46de  rcx = 0x2A8FADFD62AD902E
0x46e8  cmp rax, rcx ; jne 0x5daf             ; errada -> ACCESS DENIED
0x46f1  … decifra o blob de 39 bytes e imprime "[+] flag: …"
```

**Flag** (verificação black-box, alvo **original**, nenhum arquivo tocado — patch só na cópia em
memória): forçar o digest a devolver a constante aceita faz o alvo decifrar e imprimir o flag, e o
blob decifrado de 39 bytes fica na memória do processo congelado (`captures/mem-flag/`). Evidência:
`20261014-508`/`509` (patch do prologo `movabs rax,<const>; ret` → caminho do flag) e os
`HIT VA …[+] flag:` de `20261014-506`.

---

## 3. O instrumento: congelar, patchar, alimentar e **ler**

O caminho pós-entrada do alvo dura <1 ms (medido em rodada anterior: `NtSuspendProcess` devolve
`0xC000010A` = `STATUS_PROCESS_IS_TERMINATING` até com atraso 0). A única forma determinista de ler
o que ele calcula: **instrumentar em memória enquanto ele espera a entrada** e deixá-lo congelado
(`IAT` do `exit` apontando para um `jmp $`). Foi o que permitiu medir, com comando e saída:

```console
# digest real da entrada "A" (stub pós-call: grava rax e repete os 5 bytes originais)
$ powershell -File scripts/park-patch-run.ps1 -Target <alvo> -Entrada A \
      -HookPos '0x4695' -FreezeIat 'exit=0x46644'
  gravador pos-call: RVA 0x4695 (bytes 4889c10f31 repetidos no stub 0x7ff7ef870000)
--- SCRATCH: retorno do hook = 0x4819071427dfacce
# seed real da entrada "A" (stub na 1a gravação dos registradores)
  SEED capturado: 0x0000000000000041  0x75f6ba43239c0987  0xf5aaed574222270a  0x119b83de39985411
# o bytecode EM USO (seguindo os ponteiros do call) e o estado
  param_4 = 0x47 (71 palavras)   param_5 (estado) = IVs do Blake2b   param_3[2:] == 69 ops
# o que o alvo PREPARA a partir da entrada (o call de preparação)
  retorno do call: rax=0x…c960 rdx=0x3 (3)   (ptr,len) -> 3 bytes hex: 414141  texto: AAA
```

E o resultado que corrige a conclusão anterior: com **entrada binária** a função de preparação
(RVA `0x1000`, decodificador UTF-8 de trás para frente, do tipo *trim*) devolve **len = 0** — ou
seja, a "senha candidata" binária **nunca chegou à VM**, e o digest medido era o de entrada vazia.
Isso estava sendo contado como "o alvo rejeitou a senha" — não era: era o **transporte**.

### Armadilhas medidas (todas viraram comentário no script)

1. **`call stub` que chama a função original tem de reconstruir `rsp`**, não só o alinhamento:
   se a função recebe **5º argumento na pilha** (`mov [rsp+0x20], rax` antes do call — é o caso
   aqui), um `rsp` deslocado faz ela ler ponteiro lixo → **`0xC0000005`**. Correto: `add rsp,8`
   antes do call, `sub rsp,8` depois (o stub entra com `rsp = S-8`).
2. **Não existe store absoluto de 64 bits sem registrador**: o endereço da scratch entra por
   `movabs`; em stub que devolve valor, use `r11` (únicos livres depois de um call que devolve em
   `rax`/`rdx`).
3. **Stub "montado byte a byte" erra encoding** (`disp32` de 4 bytes, não 2) e o sintoma é
   `0xC0000005` sem pista. Monte por template hex e **valide com o próprio
   `python scripts/disasm-range.py`** numa cópia do alvo (cada instrução conferida): foi assim que
   os quatro stubs desta rodada foram para produção.
4. **Cada modo de hook precisa de área própria**: `-HookCall`, `-HookPos` e `-HookStub` escrevem em
   momentos diferentes; com a mesma scratch, o último apaga o anterior (medido: seed lido como 0).
5. **Rejeição pode ser transporte, não senha** — ver acima (§3).

---

## 4. O que ficou provado, e o que não

**Provado (seed, op, fold e programa batem byte a byte com o alvo):**

| Peça | Como foi provado |
|---|---|
| bytecode | capturado do processo (`param_3`) == dump do caso (`cap[2:2+69] == PROGRAMA`) |
| estado | lido do processo == 4 IVs do Blake2b |
| seed | **capturado** == modelo para `""` e `"A"` (4 qwords idênticos) |
| ops (12) | corpo de cada caso no desmonte (`0x8188`..`0x832e`) conferido contra o modelo |
| fold | `0x8333`..`0x838c` conferido contra o modelo (`rol 0x30/0x20/0x10`, 3 LCGs) |
| gate + anti-timing | desmonte de `0x45d6`..`0x46f1` (flag em `0x4abe0`, decoy `0xdeadbeefcafef00d`) |
| flag | patch do gate → alvo decifra e imprime; blob de 39 B na memória congelada |

**Não fechado (limitação declarada, sem maquiagem):** o **digest medido** do alvo não bate com
**duas implementações independentes** — o modelo (`work/crackme-n5/scripts/n5-vm.py`) e uma
transcrição literal feita a partir do desmonte (`work/crackme-n5/scripts/n5-maq.py`, cada bloco
citando a instrução de origem). As duas concordam **entre si** e com o seed medido, e divergem do
valor que o alvo compara. Logo: há um componente do cálculo que ainda não está no modelo (o
candidato mais provável é a *entrada* que a VM realmente digere num caso de 32 bytes, onde o
caminho de preparação já mostrou que devolve `len` diferente do enviado). Sem isso, **a inversão da
senha não fecha** — e não vou apresentar a senha do modelo como se fosse a do alvo.

---

## 5. Fricção do toolkit → corrigida nesta rodada

**Lacuna real:** o toolkit tinha leitura (PE/ELF), triagem e reconstrução de dump — e **nenhuma
ferramenta para instrumentar um alvo vivo**. As rodadas 8.3/8.4 resolveram por static + emulador;
esta exigiu medir dentro do processo, e cada script era reescrito do zero no diretório do caso
(`park-freeze-dump.ps1`, `park-patch-run.ps1`, `iat-slot.mjs`, `dump-proc-mem*.ps1`).

**Correção feita agora:** [`scripts/park-patch-run.ps1`](../scripts/park-patch-run.ps1) — o
instrumento promovido ao toolkit, com as cinco armadilhas acima **medidas e embutidas** no
cabeçalho e nos comentários dos blocos. Modos:

| Modo | O que faz |
|---|---|
| `-Patch 'rva=hex'` | troca bytes em memória (imediato, prologo, salto) — nada no arquivo |
| `-FreezeIat 'nome=rva'` | congela o alvo (IAT do `exit` em `jmp $`) para ler depois do cálculo |
| `-HookCall 'rvaCall=rvaFn'` | intercepta um call e grava o que ele **retorna** (`rax` e `rdx`) |
| `-HookPos 'rva'` | grava `rax` logo **depois** de um call, sem tocar no call |
| `-HookStub 'rva=TEMPLATE'` | stub próprio por template hex (`{scratch}`/`{orig}`): grava `rsp`, vários registradores, o que precisar |
| `-SeguirRetorno` | com `-HookCall`: trata `(rax,rdx)` do retorno como `(ptr,len)` e despeja |

Documentado em [scripts/README.md](../scripts/README.md) (linha do mapa) e em
[docs/06-workflows.md](../docs/06-workflows.md) (§ *Alvo que calcula rápido demais para observar*),
com o fluxo park → patch → alimentar → ler e o porquê de cada armadilha.

---

## 6. Verificação e limitações

CI do commit deste relatório (conteúdo da rodada): `CI` run 38650513659 — **success** em
`5858849` (<https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38650513659>).

```console
$ node scripts/check-consistency.mjs      # docs <-> código <-> licenças (offline)
$ node scripts/verify-licenses.mjs        # licenças vs fonte primária (rede)
$ powershell -File scripts/park-patch-run.ps1 … -HookPos '0x4695'   # smoke do tool promovido
```

Limitações, sem maquiagem:

- **Senha não fechada** (§4) — o próximo passo é medir a *entrada efetiva da VM* num caso de 32
  bytes (o instrumento agora existe: `-HookCall` no call de preparação + `-HookStub` para gravar os
  argumentos do digest), não reescrever o modelo no escuro.
- **Ghidra/x64dbg/Unicorn não exercitados nesta rodada** — e não por falta de necessidade: o
  caminho estático (Ghidra, round 8.5 §2) e o instrumento *caseiro* resolveram a leitura; o
  instrumento agora é do toolkit, então a próxima rodada começa daqui.
- O **smoke do `-HookStub`** ficou pendente: uma rodada anterior deixou um alvo congelado vivo, o
  que travou o último teste em lote. O alvo foi encerrado (`taskkill`), e o `-HookPos`/`-HookCall`
  foram confirmados com comando + saída (§3).

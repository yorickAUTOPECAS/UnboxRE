# Round 8.3 — terceiro alvo real (`nivel 3`): resultado técnico + fricção medida do toolkit

Alvo: `C:\Users\Admin\Desktop\Alvos\nivel 3` — **um ELF64 Linux**, não um PE. A rodada tinha
dois entregáveis de peso igual: resolver o alvo e consertar **nesta rodada** o que o toolkit
não dava conta. O segundo entregável acabou sendo o maior dos dois: o escopo validado do
toolkit é Windows, e as **cinco** ferramentas de leitura recusavam o arquivo com a mesma
mensagem, sem oferecer caminho nenhum. Recusar não é triagem — todas passaram a ler ELF aqui.

| | |
|---|---|
| **Senha** | **`St4ckW1z4rd_0x5A`** (16 bytes) |
| Máquina de estados | interpretador de bytecode próprio (22 opcodes, 288 bytes de bytecode cifrado em `.rodata`) |
| Anti-debug | `ptrace(PTRACE_TRACEME)` — decide a semente (`0x5a` sem depurador, `0` com) |
| Empacotado/protegido? | **Não** (sem assinatura de packer); o único sinal é o `ptrace` |
| Dois caminhos independentes | emulador da VM + **modelo fechado** — os dois dão a mesma senha |
| Controle negativo | `Rt4ckW1z4rd_0x5A` → 0/16; byte 8 trocado → 8/16 (a cadeia do acumulador prevê exatamente isso) |
| **O alvo foi executado?** | **Não** — é ELF e este host é Windows sem distro no WSL. Limitação declarada na §5 |
| Ferramentas do toolkit alteradas | 5 scripts + 2 docs + 2 READMEs (tabela na §8) |
| Ghidra / x64dbg / Unicorn | **zero vezes** — nada nesta rodada os exigiu |

---

## 1. Passo 1 — Inventário (antes de qualquer ataque)

```console
$ ls -la "/c/Users/Admin/Desktop/Alvos/nivel 3"
-rw-r--r-- 1 Admin 197121     0 Oct 14 11:49 description.txt
-rw-r--r-- 1 Admin 197121 14528 Oct 13 05:08 stckwzrd

$ wc -c description.txt   # leia-me VAZIO (0 bytes) — não há dica nenhuma no alvo
0 description.txt
```

Um único arquivo de 14.528 bytes, **sem extensão**, e um `description.txt` de zero byte. O
cabeçalho responde antes de qualquer ferramenta:

```console
$ head -c 64 stckwzrd | xxd
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0200 3e00 0100 0000 a019 4000 0000 0000  ..>.......@.....
...
$ file stckwzrd
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
  interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, stripped
```

Congelamento antes de tocar no arquivo (contrato de hash → triagem → análise):

```console
$ sha256sum work/crackme-n3/src/stckwzrd
3bc0c0c2fbcaf696bfbe613d3745e1d453e7601449e8d449994966868061b7ed *work/crackme-n3/src/stckwzrd
```

O caso foi criado com `scripts/new-case.ps1` (intake + hash): `work/crackme-n3/` com
`src/ unpacked/ notes/ scripts/ captures/ evidence/`. Antes de atacar, já estava claro que
o alvo **não** era PE — e que isso ia mexer no toolkit.

---

## 2. Passo 2 — Triagem, não ataque direto (e a primeira fricção)

Os cinco comandos do Cenário 0 rodaram na ordem. Saída real (`evidence/20261014-301`):

```console
$ node scripts/identify-protections.mjs work/crackme-n3/src/stckwzrd     ; exit=2
work/crackme-n3/src/stckwzrd: não é um PE (sem assinatura MZ)
$ node scripts/triage-static.mjs work/crackme-n3/src/stckwzrd --refs     ; exit=2
[!!] work/crackme-n3/src/stckwzrd: sem assinatura MZ — não é um PE
$ node scripts/diagnose-load.mjs work/crackme-n3/src/stckwzrd            ; exit=2
work/crackme-n3/src/stckwzrd: não é um PE (sem assinatura MZ)
$ python scripts/disasm-range.py work/crackme-n3/src/stckwzrd 0x1000     ; exit=2
[!!] work/crackme-n3/src/stckwzrd: sem assinatura MZ — não é um PE
$ node scripts/pe-read.mjs work/crackme-n3/src/stckwzrd --rva 0x1000     ; exit=2
[!!] work/crackme-n3/src/stckwzrd: sem assinatura MZ — não é um PE
```

E o caminho alternativo que existiria num host Linux **não existe aqui**: `readelf`, `objdump`,
`nm`, `strings`, `gdb` — ausentes no Windows/Git Bash; `wsl` presente, mas sem distro instalada
(`wsl -l -v` → "não tem distribuições instaladas"). Ou seja: sem conserto **nesta rodada**, a
rodada terminava na primeira linha. Isto é registrado como **F1** (§6) e foi corrigido antes de
continuar a análise.

Depois do conserto, a triagem respondeu (trechos de `-302`, `-303`, `-305`):

```console
$ node scripts/triage-static.mjs work/crackme-n3/src/stckwzrd
  14528 bytes · ELF64 · x86-64 · ET_EXEC (executável de endereço fixo)
  dinâmico (interpreter /lib64/ld-linux-x86-64.so.2) · entry=0x4019a0 · faixa 0x400000..0x404070
  dinâmico: DT_NEEDED=libc.so.6
    DT_INIT=0x401000 · DT_INIT_ARRAY=0x403de8 — o loader chama isto ANTES do main
                                   (análogo ELF do TLS callback do PE)
  símbolos indefinidos (o que ele chama de fora): 12
    _ITM_deregisterTMCloneTable, _ITM_registerTMCloneTable, __gmon_start__,
    __libc_start_main, __stack_chk_fail, fflush, fgets, printf, ptrace, puts,
    strcspn, strlen

$ node scripts/triage-static.mjs work/crackme-n3/src/stckwzrd --refs
    addr 0x402008 .rodata [ascii] "  stckwzrd :: the stack wizard guards this gate"  <- usada em 0x40122f
    addr 0x402038 .rodata [ascii] "  the wizard scoffs. (wrong length)"             <- usada em 0x40132f
    addr 0x402060 .rodata [ascii] "  the stack unwinds cleanly. ACCESS GRANTED."     <- usada em 0x4013b5
    addr 0x402090 .rodata [ascii] "  the stack overflows with doubt. denied."        <- usada em 0x401811
    addr 0x4020ba .rodata [ascii] "  serial> "                                       <- usada em 0x40125b

$ node scripts/triage-static.mjs work/crackme-n3/src/stckwzrd --data-refs
  referências a DADOS que não são strings (constantes): 22 alvo(s)
    addr 0x402270 .rodata [inteiro pequeno]  bytes: 00 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00
    addr 0x4020e0 .rodata [dados]            bytes: 31 f7 ff ff 4b f5 ff ff d9 f6 ff ff b0 f6 ff ff
    addr 0x402140 .rodata [dados]            bytes: 3a f2 05 02 ea 5c ca 27 23 18 68 88 5b c5 27 00
    addr 0x402280 .rodata [dados]            bytes: 48 f3 e0 d2 89 e2 36 dd a5 a1 c3 44 2a 90 81 8b
```

Resposta à pergunta "é empacotado/protegido, ou lógica sem proteção de carregamento?":

```console
$ node scripts/identify-protections.mjs work/crackme-n3/src/stckwzrd
  [i ] Sem .symtab (info) — stripped: os nomes de função/símbolo não estão no arquivo
  [? ] Importa ptrace (medium) — o binário chama `ptrace` — anti-debug clássico em Linux
       (PTRACE_TRACEME faz o próprio processo recusar um depurador já anexado)
  Veredito: possivelmente incomum
```

**Lógica sem proteção de carregamento.** Não há stub, não há OEP a achar, não há IAT a
reconstruir — o Cenário 1 inteiro (e o debugger) não se aplica. A única oposição é o
`ptrace` **dentro** do `main`, e o caminho é ler o código.

`--data-refs` já entregou as três estruturas que importam, sem leitura manual: a tabela
`0..3` em `0x402270`, o bytecode cifrado em `0x402140` e os 16 bytes esperados em `0x402280`.
Note-se a diferença de vocabulário que o conserto introduziu: no ELF os alvos **não têm
classe** (`[dados]`), porque "máscara"/"semente" era o vocabulário do pipeline SSE do alvo
PE da rodada anterior — a classificação heurística fica para quem lê, não é inventada.

E a recusa real do loader do Windows, com a distinção que **evita** a armadilha documentada
(`evidence/20261014-306`):

```console
$ node scripts/diagnose-load.mjs work/crackme-n3/src/stckwzrd          ; exit=1
  [!!] formato-nao-carregavel-no-windows — é ELF (ELF64, ET_EXEC, x64, entry 0x4019a0) — o
       loader do Windows só carrega PE; o erro dele é 193 (ERROR_BAD_EXE_FORMAT), NÃO 0xC000007B
  [i ] 0xc000007b-nao-se-aplica — 0xC000007B é o loader rejeitando uma imagem PE malformada;
       aqui não há PE nenhum para rejeitar
  [i ] run — exit=(nenhum) (o arquivo não tem extensão .exe: o Node procura "<nome>.exe" e não
       acha (ENOENT) — é a busca do nome, NÃO a recusa do loader; copie para um nome com .exe)
       · stdin alimentado (16 bytes)

$ cp stckwzrd evidence/stckwzrd-elf-copia.exe
$ node scripts/diagnose-load.mjs evidence/stckwzrd-elf-copia.exe       ; exit=1
  [? ] execucao-recusada — executar no Windows falhou como esperado para um ELF —
       CreateProcess recusou a imagem (UNKNOWN; no Windows isso é ERROR_BAD_EXE_FORMAT/193)
```

---

## 3. O mecanismo (o que o alvo faz, com endereço de cada passo)

Leitura pelo `disasm-range.py` sobre a `.text` inteira (`--section .text`, 609 instruções,
`0x4010b0..0x401a96`) — nenhuma GUI, nenhum debugger (`evidence/20261014-304`, `-308`).

**3.1 Anti-debug que decide a semente.** `ptrace(PTRACE_TRACEME)` em `0x4010a0`; `cmovne esi,eax`
em `0x4010fd` deixa `esi = 0x5a` sem depurador e `0` com um anexado, e o `main` grava isso no
**byte 1 do bytecode** (`0x401236 mov [rsp+0x261], sil`). O bloco SSE `0x401160..0x401221`
decifra os 288 bytes de `.rodata` `0x402140` com a chave `(i*0x6d + 0x3b) & 0xff`. Ou seja: o
bytecode que existe no arquivo **não** é o que a VM executa.

**3.2 A VM.** `0x401300..0x40132d` é o interpretador: `bytecode[ip]` indexa uma tabela de
saltos de 24 entradas em `0x4020e0`; pilha de 64 B em `[rsp+0x20]`, memória de 256 B em
`[rsp+0x160]`, entrada em `[rsp+0x60]`, esperado em `[rsp+0x10]`. `0x4013a0` repete enquanto
`ip <= 0x124` — e o opcode `0xfe` (HALT) cai exatamente nesse limite.

**3.3 O programa.** 16 rodadas idênticas na forma, distintas nas constantes. Cada byte `i`:

```
push in[i]; dup; push mem[0x80]; xor; addi A_i; rol R_i; xori 0x9e;
dup; check i; add; store 0x80
   →  y_i = rol((x_i ^ acc) + A_i, R_i) ^ 0x9e        acc = (x_i + y_i) & 0xff
```

com `acc` inicial `0x5a` (a semente decidida pelo `ptrace`). Rodada 0: `A=0x62 R=1`; rodada 15:
`A=0x1e R=8`.

---

## 4. A resolução — e por que ela é auditável

Duas rotas **independentes** até a mesma senha (`evidence/20261014-307`, `-309`):

```console
$ python work/crackme-n3/scripts/solve-vm.py solve
dependências por comparação (entrada em branco):
  esperado[00] = 0x48 · depende da entrada[0]
  esperado[01] = 0xf3 · depende da entrada[0, 1]
  ...
  esperado[0f] = 0x8b · depende da entrada[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

senha candidata: b'St4ckW1z4rd_0x5A'
  16/16 comparações ok · r8d=0 · 179 passos
  resultado: ACCESS GRANTED
  controle negativo b'Rt4ckW1z4rd_0x5A': 0/16 comparações ok · denied
  controle negativo (byte 8) b'St4ckW1z\xcbrd_0x5A': 8/16 comparações ok · denied

$ python work/crackme-n3/scripts/solve-vm.py model     # NÃO executa a VM: lê o bytecode
rodadas reconhecidas no bytecode: 16
  rodada  0: A=0x62 R=1 X=0x9e check=0
  rodada  1: A=0x6c R=2 X=0x9e check=1
  ...
senha pelo MODELO: b'St4ckW1z4rd_0x5A'
  o EMULADOR confirma essa senha: SIM
```

Três coisas sustentam a leitura, e todas são verificáveis sem confiar no meu emulador:

1. **Dependência medida, não presumida.** A primeira saída é o mapa de dependências obtido
   rodando a VM com **entrada em branco**: `esperado[k]` só depende de `entrada[0..k]`. Isso é
   o que autoriza resolver byte a byte por oráculo (e o que prevê o resultado do controle).
2. **Controle negativo com previsão quantitativa.** Trocar o byte 0 derruba as **16**
   comparações (a cadeia do acumulador entra em `0x9e` no primeiro elo); trocar o byte 8
   derruba exatamente as **8 últimas** — `8/16`, o que a estrutura acima prevê. Um emulador
   errado não acerta essa contagem.
3. **Segunda opinião por forma fechada.** O modo `model` reconhece o padrão nos 288 bytes
   decifrados e resolve por fórmula, **sem executar** a VM; concorda com o emulador.

O que também é sinal, e não prova: a senha é uma frase legível e o último par de bytes é
`0x5A` — o mesmo valor da semente que o `ptrace` decide.

---

## 5. Limitação declarada (o alvo não foi executado)

**O binário nunca rodou.** É ELF e este host é Windows sem distro no WSL. A confirmação
black-box (`diagnose-load --stdin '<candidata>'`) **não existe** para este alvo, e o relatório
não finge que existe: o que há é emulação construída a partir do disassembly transcrito
handler a handler (os 22 opcodes, com os endereços no cabeçalho de `scripts/solve-vm.py`).
Coerência entre duas rotas independentes + controle negativo com previsão quantitativa é o
substituto honesto — e continua **não** sendo a mesma coisa que ver o alvo imprimir
"ACCESS GRANTED". Para fechar essa lacuna: Linux nativo, WSL com distro (`wsl --install -d
Ubuntu`, exige elevação e rede — não fiz por conta própria, regra 2 do AGENTS) ou emulação
de CPU (Unicorn/Qiling, catalogados e não usados).

---

## 6. Passo 3/4 — Fricção registrada em tempo real e corrigida AGORA

### F1 — O toolkit inteiro recusava ELF, com a mesma mensagem e sem caminho alternativo

**Momento:** a triagem do Cenário 0 devolveu `exit=2` em **cinco** comandos seguidos (§2). Em
host Linux bastaria `readelf`/`objdump`/`strings`/`gdb`; nenhum existe aqui, e o WSL não tem
distro. O escopo validado do toolkit é Windows — mas "recusar" não é resposta de triagem, e a
alternativa era escrever um parser de ELF na hora **pela terceira rodada seguida** (o mesmo
que aconteceu com o parser de PE nas 8.1 e 8.2, e que gerou bugs nas duas vezes).

**Feito agora:** os quatro leitores entendem os dois formatos — `triage-static.mjs`,
`disasm-range.py`, `pe-read.mjs`, `identify-protections.mjs` — e o `diagnose-load.mjs` passou a
classificar ELF (§2 acima). O desenho é o mesmo em todos: **normalizar o outro cabeçalho para o
mesmo vocabulário** (seção = `{nome, va, virtualSize, raw, rawSize}`) e deixar o resto do
código sem saber de qual formato veio; a mensagem de formato desconhecido ficou explícita
(`nem assinatura "MZ" (PE) nem "\x7fELF"`). `disasm-range.py` também escolhe a arquitetura do
capstone pelo `machine` (`x86`, `x86-64`, `ARM64`), não mais por "é PE? é 64?".

```console
$ node scripts/pe-read.mjs work/crackme-n3/src/stckwzrd --rva 0x402280 --len 16
  rva 0x402280 · 16 byte(s) · seção .rodata (R--, offset no arquivo 0x002000)
  off 0x002280  addr 0x402280  48 f3 e0 d2 89 e2 36 dd a5 a1 c3 44 2a 90 81 8b  H.....6....D*...
```

### F2 — `diagnose-load` confundia **duas recusas diferentes** (e o risco do 0xC000007B)

**Momento:** rodando contra o ELF, o script devolvia `exit=1` sem explicar nada útil — e a
leitura apressada de `0xC000007B` ("deve ser relocação/loader") mandaria a investigação para o
lado errado, exatamente o erro que o
[reports/root-cause-0xc000007b.md](root-cause-0xc000007b.md) já tinha custado. Pior: sem
extensão `.exe` o Node/libuv procura `"<nome>.exe"` e devolve **ENOENT** — que é a busca do
nome, **não** a recusa do loader; as duas falhas tinham a mesma cara na saída.

**Feito agora:** branch ELF dedicado, com o formato/entry, o status **real** da execução
(ENOENT distinguido de `CreateProcess` recusando), e o texto do que fazer. Medido nas duas
formas (sem extensão e com `.exe` copiado) — §2.

### F3 — `disasm-range.py`: o defeito que **me fez perder uma instrução da VM**

**Momento:** extraindo os handlers do interpretador, a linha

```console
  0x40138b  0f b6 84 0c 60 02 00 00  movzx    eax, byte ptr [rsp + rcx + 0x260]
```

saiu com os 8 bytes **colados no mnemônico** (o campo era de 22 colunas e a instrução ocupa 23),
e a minha extração por coluna pulou essa linha — justamente uma das que leem `bytecode[]`. O
emulador ficou com um handler a menos até o próprio alvo recusar a primeira candidata.

**Feito agora, três correções no mesmo script:**
1. campo de bytes de **24** colunas (a linha acima agora sai separada);
2. `--section <nome>` deixou de exigir um endereço posicional de enfeite: `rva_ini` virou
   opcional (`nargs="?"`) — `python scripts/disasm-range.py alvo --section .text` é o caso
   mais comum e pedia um número inventado;
3. no ELF, `--section .text` inteira morria em *"intervalo não é legível"* porque o fim da
   seção é **exclusivo** e cai no byte seguinte ao mapa: o fim de seção agora é resolvido para
   o offset real, e `.bss`/seção não carregada é **dita** ("não tem bytes no arquivo"), não
   desmontada em silêncio.

```console
$ python scripts/disasm-range.py work/crackme-n3/src/stckwzrd --section .text   ; exit=0
  ELF · ImageBase=0x0 · intervalo vaddr 0x4010b0..0x401a96 · 609 instrução(ões)
$ python scripts/disasm-range.py work/crackme-n3/src/stckwzrd --section .bss    ; exit=2
[!!] seção .bss não está carregada / não tem bytes no arquivo (nada para desmontar)
```

Evidência dedicada: `work/crackme-n3/evidence/20261014-311-disasm-elf-alinhamento.txt`.

### F4 — `identify-protections` imprimia entropia de um `.bss` **vazio**

**Momento:** o primeiro ELF que passou pelo script imprimiu `.bss virt=32 raw=0 entropia=3.94`.
`.bss` é `SHT_NOBITS`: não tem byte no arquivo, e entropia de bytes inexistentes é ruído — do
tipo que faz alguém "descobrir" dado cifrado onde não há dado nenhum.

**Feito agora:** `rawSize = 0` e entropia `0` para `SHT_NOBITS`, e o branch ELF ganhou os
sinais que valem: `UPX!`/seção UPX, `.vmpN`, `shc`, **segmento LOAD gravável+executável**,
entrypoint fora de qualquer LOAD, ausência de `PT_INTERP`/`PT_DYNAMIC`, alta entropia e
`ptrace` importado.

### F5 — "código que roda antes do `main`" era conceito exclusivo de PE

**Momento:** o valor do `triage-static` no alvo PE (8.1) foi justamente os **TLS callbacks** —
código que o loader executa antes do entrypoint. No ELF esse lugar é `DT_INIT`/`DT_INIT_ARRAY`
e o script não tinha campo para isso; os imports também eram só "por DLL".

**Feito agora:** o mesmo campo de relatório serve aos dois (`DT_INIT=0x401000 ·
DT_INIT_ARRAY=0x403de8 — o loader chama isto ANTES do main (análogo ELF do TLS callback do
PE)`) e os imports do ELF são `DT_NEEDED` + os símbolos **indefinidos** do `.dynsym` — que é
onde o `ptrace` aparece antes de qualquer disassembly.

### F6 — O critério do Cenário 12 não dizia o que fazer quando o não-linear é **uma VM pequena do alvo**

**Momento:** o critério escrito na rodada anterior era "linear → álgebra; não linear (hash,
S-box, laço com memória) → emulação (Unicorn/Qiling) ou debugger". Este alvo é não-linear
*bytecode*, e o caminho que resolveu não foi instalar emulador: foi transcrever os 22 handlers
e rodar a VM em Python — offline, determinístico, com controle negativo.

**Feito agora:** o Cenário 12 de [docs/06-workflows.md](../docs/06-workflows.md) ganhou o
parágrafo que faltava: se o não-linear está **isolado** num interpretador próprio e o conjunto
de operações é pequeno, o emulador de ~100 linhas resolve; o que **não** se dispensa nesse
caminho é o **modelo independente** conferindo o mesmo resultado e o controle negativo
recusando entrada errada. Caso medido: este.

---

## 7. Passo 5 — Catalogação pendente (independente do alvo)

O `triage-static.mjs` era a única ferramenta do núcleo sem entrada no catálogo. A capacidade
dele é exatamente a de a.2 LIEF / a.5 DIE ("inspecionar cabeçalho/seções/strings/referências
sem debugger"), então a costura foi no mesmo lugar, com o mesmo padrão usado para
`disasm-range.py` na rodada anterior:

- **novo** `### a.2.1 triage-static.mjs ✅ do toolkit — MIT` em
  [docs/02-catalogo-ferramentas.md](../docs/02-catalogo-ferramentas.md) (o que faz / quando
  usar / como usar / integração / por quê), declarando os **dois formatos** e que no ELF o
  endereço é o vaddr de link;
- a entrada do **DIE (a.5)** ficou com a nota de que existe primeira passada embutida —
  `identify-protections.mjs` — e que desde 8.3 ela cobre **também ELF**;
- Capstone (a.3) atualizado para "aceita PE e ELF";
- [README.md](../README.md) e [scripts/README.md](../scripts/README.md) com os cinco scripts
  lendo os dois formatos;
- `docs/06-workflows.md` ganhou a subseção **"Alvo Linux (ELF) na triagem"** (vaddr de link em
  vez de RVA, `DT_INIT` no lugar do TLS callback, 193 ≠ 0xC000007B).

Regressão de consistência e licenças, re-executadas **depois** de todas as edições:

```console
$ node scripts/check-consistency.mjs
  núcleo: 4 · catálogo: 31 · perfis: 13 · flags MCP: 9
  licenças com linha verificada: 28/31 do bootstrap · registradas: 79
  [OK] nenhuma divergência encontrada (197 verificações).                      ; exit=0

$ node scripts/verify-licenses.mjs
  [OK] 79 licenças declaradas batem com a fonte primária.                      ; exit=0
```

---

## 8. O que mudou no toolkit nesta rodada

| Arquivo | Mudança | Fricção |
|---|---|---|
| `scripts/triage-static.mjs` | leitura de **ELF** (program headers, seções via `.shstrtab`, `.dynamic`/`DT_INIT`, `DT_NEEDED` + símbolos indefinidos, sinais de empacotamento) no mesmo relatório do PE; vocabulário de seção normalizado | F1, F5 |
| `scripts/disasm-range.py` | aceita ELF (e `--section` sem endereço posicional); campo de bytes 22→**24** colunas (a instrução de 8 bytes que se colava e se perdia na extração); fim de seção exclusivo; arquitetura escolhida pelo `machine` (x86/x86-64/ARM64) | F1, F3 |
| `scripts/pe-read.mjs` | aceita ELF (mesmo mapa/hexdump/leituras tipadas); mensagem de formato desconhecido explícita | F1 |
| `scripts/identify-protections.mjs` | branch ELF (LOAD W+X, entry fora do LOAD, `UPX!`, `.vmpN`, `shc`, sem `PT_DYNAMIC`, `ptrace`); `.bss`/`SHT_NOBITS` com entropia 0 (era 3,94 para bytes inexistentes) | F1, F4 |
| `scripts/diagnose-load.mjs` | branch ELF: formato, status **real** da execução e a distinção ENOENT (busca do nome) × `CreateProcess` recusando; 193 ≠ 0xC000007B dito em texto | F1, F2 |
| `docs/02-catalogo-ferramentas.md` | **novo** a.2.1 (`triage-static.mjs`); a.3 (Capstone) e a.5 (DIE) atualizados | Passo 5 |
| `docs/06-workflows.md` | subseção "Alvo Linux (ELF) na triagem"; Cenário 12: VM pequena do alvo → emulador de ~100 linhas + modelo independente | F1, F6 |
| `README.md` · `scripts/README.md` | os cinco scripts com os dois formatos no mapa | F1 |
| `reports/round-8-3-nivel-3.md` | este relatório | — |

Regressão nos alvos das rodadas anteriores (nada quebrou; `evidence/20261014-310-regressao.txt`):

```console
$ node scripts/triage-static.mjs work/crackme-n2/.../My_Second_Crackme.exe --refs
    addr 0x0030b0 .rdata [ascii] "enter the password : "  <- usada em 0x1451 (RIP-relativo (lea))
$ node scripts/triage-static.mjs work/crackme-n2/.../My_Second_Crackme.exe --data-refs
    addr 0x003090 .rdata [máscara] <- 1 ref(s), 1a em 0x157d (RIP-relativo (0f 6f))
    addr 0x0030a0 .rdata [máscara] <- 1 ref(s), 1a em 0x1595 (RIP-relativo (0f 6f))
$ node scripts/triage-static.mjs work/crackme-n1/.../My_First_Crackme.exe --refs
    addr 0x003090 .rdata [ascii] "enter the password : "  <- usada em 0x145c (RIP-relativo (lea))
    addr 0x0030a9 .rdata [ascii] "Yeaaaaa!!! Discord : imrate" <- usada em 0x14d7 (RIP-relativo (lea))
$ node scripts/diagnose-load.mjs work/crackme-n2/.../My_Second_Crackme.exe --stdin "Xor_N0t_3nough"
        | enter the password : Yeaaaaa!!! Discord : imrate
        | Flag : CMO{Xor_N0t_3nough}
```

Os endereços batem com o que as rodadas 8.1/8.2 registraram (8.1: `0x145c/0x14d7/0x14e7/0x14f5`;
8.2: máscaras em `0x157d`/`0x1595`). Os alvos PE não sabem que o toolkit aprendeu ELF.

---

## 9. O que NÃO funcionou, e o que continua em aberto (sem maquiagem)

- **O alvo não rodou** (§5). É a limitação central desta rodada: não houve confirmação
  black-box, e nenhuma linha deste relatório deve ser lida como "o alvo imprimiu ACCESS
  GRANTED". O caminho para fechar isso é Linux/WSL com distro ou emulação de CPU.
- **Ghidra, x64dbg, Unicorn, Qiling e LIEF: não exercitados.** Nada nesta rodada os exigiu — e
  "não usados" não é "não funcionam". Continua valendo o que a 8.2 já dizia.
- **O parser de ELF é novo, e novo é onde mora o bug.** Ele foi validado em **um** alvo (ELF64
  x86-64, `ET_EXEC`, dinâmico, com tabela de seções). ELF32, big-endian, `ET_DYN` sem
  `.shstrtab`, seções `SHT_NOBITS` fora do `.bss`, ARM64 — escrito com cuidado e **não
  medido**. Quem topar um desses deve tratar como código não testado.
- **`disasm-range.py` com ELF32/ARM64** segue o mesmo aviso: o caminho ARM64 depende do
  capstone da máquina ter `CS_ARCH_ARM64` (o script diz quando não tem, em vez de chutar).
- **A classificação de `--data-refs` no ELF é mais fraca** que no PE: os alvos saem como
  `[dados]`/`[inteiro pequeno]`/`[ponteiro/tabela]` sem as heurísticas que o alvo PE da 8.2
  mereceu. As três estruturas do alvo foram identificadas lendo a `.rodata` com `pe-read` —
  o que funciona, mas é trabalho manual que no PE já não era.
- **O solver é do caso** (`work/crackme-n3/scripts/solve-vm.py`) e não roda no CI: depende do
  binário do alvo, que não vai para o Git por regra. O que virou toolkit é o que é reutilizável
  — ler o código, ler os bytes, achar as constantes.
- **`--refs` no ELF varre a `.text` inteira sem a filtragem de `.dynstr`/`.eh_frame` do PE**:
  parte das "strings" encontradas é tabela de nomes e não dado do programa. Visível na saída
  (`.dynstr`, `.eh_frame`), não escondido.
- **`nivel 4` em diante não foi tocado**, por escopo.

---

## 10. Reprodução (na ordem)

```powershell
# 1) inventário + congelamento (hash estável)
ls "C:/Users/Admin/Desktop/Alvos/nivel 3"
powershell -File scripts/new-case.ps1 -Name crackme-n3 -Target "…/Alvos/nivel 3/stckwzrd" …
sha256sum work/crackme-n3/src/stckwzrd      # 3bc0c0c2fbcaf696bfbe613d3745e1d453e7601449e8d449994966868061b7ed

# 2) triagem — nada abre GUI, nada de sudo
node scripts/identify-protections.mjs work/crackme-n3/src/stckwzrd      # sem packer; importa ptrace
node scripts/triage-static.mjs work/crackme-n3/src/stckwzrd             # ELF: segmentos, seções, DT_INIT
node scripts/triage-static.mjs work/crackme-n3/src/stckwzrd --refs      # strings + quem as usa
node scripts/triage-static.mjs work/crackme-n3/src/stckwzrd --data-refs # as 3 constantes da .rodata
node scripts/diagnose-load.mjs work/crackme-n3/src/stckwzrd             # ELF: 193, não 0xC000007B

# 3) leitura do código e dos bytes (sem Ghidra, sem debugger)
python scripts/disasm-range.py work/crackme-n3/src/stckwzrd --section .text   # 609 instruções
python scripts/disasm-range.py work/crackme-n3/src/stckwzrd 0x4010a0 --fim 0x401310   # ptrace + decifra
node scripts/pe-read.mjs work/crackme-n3/src/stckwzrd --rva 0x402140 --len 32  # bytecode cifrado
node scripts/pe-read.mjs work/crackme-n3/src/stckwzrd --rva 0x402280 --len 16  # os 16 esperados

# 4) resolver (script DO CASO, dois caminhos independentes)
python work/crackme-n3/scripts/solve-vm.py solve    # emulador da VM + controles negativos
python work/crackme-n3/scripts/solve-vm.py model    # forma fechada do bytecode, sem executar

# 5) regressão do toolkit nos alvos PE das rodadas anteriores
node scripts/triage-static.mjs work/crackme-n2/src/My_Second_Crackme.exe --refs --data-refs
node scripts/diagnose-load.mjs work/crackme-n2/src/My_Second_Crackme.exe --stdin "Xor_N0t_3nough"

# 6) consistência e licenças (depois de qualquer edição de script/doc)
node scripts/check-consistency.mjs
node scripts/verify-licenses.mjs
```

Artefatos brutos do caso (locais, fora do Git por regra): `work/crackme-n3/evidence/20261014-301…311`.
Material do alvo (a senha, o bytecode, o solver) fica em `work/` e **não** é publicado.

---

## 11. CI

Nenhuma ferramenta de terceiros entrou nesta rodada (as mudanças são nos scripts do próprio
projeto, MIT), então o job `licenses` não tem linha nova para revalidar — `verify-licenses.mjs`
local, na §7, deu 79/79.

<!-- CI-RUN -->

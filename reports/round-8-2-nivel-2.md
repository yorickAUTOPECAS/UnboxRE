# Round 8.2 — segundo alvo real (`nivel 2`): resultado técnico + fricção medida do toolkit

Mesmo contrato da rodada anterior: (1) resultado técnico contra o alvo e (2) registro de
fricção, com **cada correção feita agora**. A diferença desta rodada: as três ferramentas que
nasceram no 8.1 (`triage-static.mjs`, `disasm-range.py`, `diagnose-load --stdin`) foram
usadas de ponta a ponta — e o que elas não cobriram apareceu na hora.

Resumo em uma linha: o alvo é da mesma família do `nivel 1` (MinGW x64, console, **sem
proteção de carregamento**), mas a checagem é um **pipeline SSE2** — resolvido sem abrir
Ghidra nem debugger, com senha e flag confirmadas pelo próprio binário, e **dois defeitos
reais corrigidos no toolkit** (um deles na ferramenta criada na rodada anterior).

| Entregável | Estado |
|---|---|
| Resultado técnico (senha + flag, com controles) | ✅ `Xor_N0t_3nough` · `CMO{Xor_N0t_3nough}` |
| É empacotado/protegido? | ❌ não — sem assinatura; loader aceita a imagem |
| Fricções registradas | 5 (comando + saída de cada uma) |
| Corrigidas nesta rodada | 3 (as outras 2 são declaradas como limitação) |
| Ghidra / x64dbg abertos | **zero** |
| Ferramentas do 8.1 usadas | `triage-static --refs`, `disasm-range.py`, `diagnose-load --stdin`/`--stdin-file` |

---

## 1. Passo 1 — Inventário (antes de qualquer ataque)

```console
$ ls -la "C:/Users/Admin/Desktop/Alvos/nivel 2"
-rwxr-xr-x 1 Admin 197121 14336 Oct  8 09:01 My_Second_Crackme.exe
```

Um único arquivo, **14.336 bytes**, sem leia-me/enunciado. Intake pelo caminho canônico
(`new-case.ps1`), com hash conferido de forma independente:

```console
$ powershell -File scripts/new-case.ps1 -Name "crackme-n2" -Target "…/nivel 2/My_Second_Crackme.exe" …
  [OK  ] target:sha256 — 054660AB159328D64E821CCD4988AEDFC4545F973519B04DEBB161ABDBFAB87F
$ sha256sum work/crackme-n2/src/My_Second_Crackme.exe
054660ab159328d64e821ccd4988aedfc4545f973519b04debb161abdbfab87f
```

Ficha: **PE32+ / x64**, ImageBase `0x140000000`, EP `0x13d0`, MinGW-w64
(`api-ms-win-crt-*`), 6 seções, `.tls` com 16 bytes e **2 TLS callbacks** (`rva 0x1700`,
`0x1780` — o loader roda isso antes do entrypoint).

## 2. Passo 2 — Triagem

```console
$ node scripts/identify-protections.mjs <alvo>
  [ok] nenhuma assinatura de packer/protetor conhecida.      Veredito: sem assinatura conhecida

$ node scripts/diagnose-load.mjs <alvo>                       # sem --stdin, o alvo recebe EOF
  [i ] reloc-ok — 38 entradas de relocação, todas em seções com dados
  [i ] run — exit=0x1 (saiu normalmente com status 1 — código do PRÓPRIO programa, não é falha de loader) · stdin: EOF (sem --stdin)
  [i ] saída do alvo (1 linha(s)):
        | enter the password :
  Veredito: sinais de remontagem, sem vício crítico
```

**Sem proteção de carregamento** — mesma categoria do `nivel 1`: o Cenário 1 (packer → dump →
IAT) não se aplica. O alvo é de console; a triagem do 8.1 já entrega o exit code classificado
e a saída do alvo **sem trabalho manual** (foi o que a rodada anterior consertou).

`triage-static --refs` respondeu o resto de uma vez (9 DLLs importadas, 73 strings em seções
de dados, cada uma com a RVA **e a instrução que a usa**):

```console
    rva 0x0030b0 [ascii] "enter the password : "   <- usada em 0x1451 (RIP-relativo (lea))
    rva 0x0030c9 [ascii] "Flag : CMO{%s}"          <- usada em 0x16ce (RIP-relativo (lea))
    rva 0x0030d9 [ascii] "Not today..."           <- usada em 0x16e0 (RIP-relativo (lea))
    rva 0x0030e6 [ascii] "Yeaaaaa!!! Discord : imrate" <- usada em 0x16c2 (RIP-relativo (lea))
```

Note o que **não** aparece: nenhuma string parecida com tabela cifrada (no `nivel 1` havia
`FFEuiXKIAGO` em texto). Aqui a senha não está guardada — é **calculada**.

## 3. O mecanismo (o que o `main` faz)

Desmontagem com `disasm-range.py` (evidência `…-205-disasm-main.txt`), em resumo:

```console
  0x014ae  mov      edi, dword ptr [rip + 0x2b4c]   ; -> rva 0x4000  (SEMENTE)
  0x014bc  cmp      rax, 0xe                        ; strlen(senha) == 14
  0x014c6  imul     eax, edi, 0xc2a29a69            ; 8 pares imul/add…
  0x014cc  add      eax, 0xd3dc167e                 ;   …um por byte do comparador
  0x01573  psrld    xmm2, 0x10                      ; bits 16..23 de cada dword
  0x0157d  movdqa   xmm3, xmmword ptr [rip + 0x1b0b] ; -> rva 0x3090 (MÁSCARA A)
  0x0158d  packuswb xmm2, xmm4
  0x01595  movdqa   xmm3, xmmword ptr [rip + 0x1b03] ; -> rva 0x30a0 (MÁSCARA B)
  0x01603  movabs   rcx, 0x56252cab5d734876          ; o alvo da comparação
  0x0160d  cmp      rax, rcx
  0x01636  cmp      r8b, 0x83                        ; + 6 comparações byte a byte
  0x016c2  lea      rcx, [rip + 0x1a1d]              ; "Yeaaaaa!!! Discord : imrate"
  0x016ce  lea      rcx, [rip + 0x19f4]              ; "Flag : CMO{%s}"  ← a flag é a senha
```

Os três dados que o código lê (semente e as duas máscaras) saíram do próprio toolkit, não de
leitura manual — depois da correção da §5:

```console
$ node scripts/triage-static.mjs <alvo> --data-refs --no-strings
    rva 0x003090 .rdata [máscara] <- 1 ref(s), 1a em 0x157d (RIP-relativo (0f 6f))
    rva 0x0030a0 .rdata [máscara] <- 1 ref(s), 1a em 0x1595 (RIP-relativo (0f 6f))
    rva 0x004000 .data  [inteiro pequeno] <- 1 ref(s), 1a em 0x14ae (RIP-relativo (op 0x8b))

$ node scripts/pe-read.mjs <alvo> --rva 0x4000 --len 8 --as u32
    u32      [2] 4919 (0x00001337), 4294967294 (0xfffffffe)
```

## 4. A resolução (e por que ela é auditável)

**A observação que resolve:** todo o pipeline é **linear sobre GF(2)⁸** — só há `xor`,
seleção por máscara e `shift`. Logo cada byte comparado é "XOR de um subconjunto dos bytes
digitados" ^ uma constante. Isso vira um sistema linear, resolvido por eliminação de Gauss
sobre GF(2) — sem emulador, sem debugger.

O solver do caso (fica em `work/crackme-n2/scripts/solve-n2.py`, porque é *do caso*, não do
toolkit) replica as 30 instruções do pipeline, mede quais bytes da senha entram em cada byte
do comparador e resolve as 14 equações (8 do `movabs` + 6 comparações byte a byte + `strlen`):

```console
$ python scripts/solve-n2.py
semente      : dword rva 0x4000 = 0x00001337 (4919)
constante    : 0x56252cab5d734876
=== pshufhw xmm5, xmm1 (low do SRC) ===
  bytes da senha que entram em cada byte do comparador: {0: [0, 1], 1: [11, 12], 2: [6, 7], 3: [7, 8],
                                                        4: [8, 9], 5: [9, 10], 6: [10, 11], 7: [12, 13]}
  0 bit(s) livre(s)
  senha candidata: 'Xor_N0t_3nough'
```

**A ambiguidade que o alvo resolveu.** Uma única instrução da sequência tem dois registradores
diferentes (`pshufhw xmm5, xmm1, 0xdc`): o quarto baixo do resultado vem do destino ou da
origem? As duas leituras fecham um sistema consistente (14 equações, 14 incógnitas) — a
matemática, sozinha, não decide. O critério foi o alvo, com as duas candidatas:

```console
$ node scripts/diagnose-load.mjs <alvo> --stdin "Xor_N0t_3nough"          # ×3, determinístico
  [i ] run — exit=0x0 (ok) · stdin alimentado (15 bytes)
        | enter the password : Yeaaaaa!!! Discord : imrate
        | Flag : CMO{Xor_N0t_3nough}

$ node scripts/diagnose-load.mjs <alvo> --stdin-file captures/senha-variante-errada.bin
        | enter the password : Not today...        # a leitura ERRADA do pshufhw, descartada pelo alvo

$ node scripts/diagnose-load.mjs <alvo> --stdin "H3llo_Crackme"            # controle: senha do nivel 1
        | enter the password : Not today...
```

**Resultado:** senha `Xor_N0t_3nough`, flag `CMO{Xor_N0t_3nough}`.

---

## 5. Passo 3/4 — Fricção registrada e corrigida

### F1 — Não havia caminho para ler os BYTES de uma RVA (segunda rodada seguida)

**Momento:** o `disasm-range.py` anota `; -> rva 0x4000` e o `triage-static` dá a RVA de cada
string — mas "o que TEM nesse endereço?" não tinha ferramenta. Nas duas rodadas a saída foi um
parser de PE escrito na hora (`work/crackme-n2/scripts/pe-data.py`), e no 8.1 esse script
avulso ainda quebrou sozinho (`Do not know how to serialize a BigInt`).
**Feito agora:** [`scripts/pe-read.mjs`](../scripts/pe-read.mjs) — mapa de seções (RVA ↔ offset
do arquivo), hexdump com gutter ASCII e leitura tipada (`u8..u64`, `float`, `cstring`,
`utf16`), com `--json`. É a ferramenta que eu queria ter tido nas duas rodadas:

```console
$ node scripts/pe-read.mjs <alvo> --rva 0x4000 --len 16
  off 0x003000  rva 0x004000  37 13 00 00 fe ff ff ff e0 35 00 40 01 00 00 00  7........5.@....
  leitura tipada (little-endian):
    u32      [4] 4919 (0x00001337), 4294967294 (0xfffffffe), …
```

Dois defeitos **do próprio script novo** apareceram no teste e foram corrigidos na hora:
(i) `u64` convertido para `Number` antes do `toString(16)` imprimia hexadecimal **errado**
acima de 2^53 (`0xfffffffe00001000` para um valor de 64 bits real); (ii) `--as u9` saía com
exit **0** quando não havia `--rva` (a validação ficava depois do modo mapa, que terminava
antes). Os dois só apareceram porque os exit codes foram medidos caso a caso, sem máscara de
`| tail`.

### F2 — `triage-static` **não encontrava** as constantes do alvo (bug de detecção + falta de relatório)

**Momento:** as duas máscaras (`rva 0x3090`/`0x30a0`) foram achadas lendo o disassembly à mão,
porque a ferramenta do 8.1 não as citava em referência nenhuma. Causa medida: o detector só
pulava REX, então **todo** prefixo `66`/`F2`/`F3` quebrava a leitura — e `0f` estava na lista
de opcodes como se o ModRM viesse no byte seguinte (em opcode de dois bytes ele vem em `p+2`,
logo `(modrm & 0xc7) === 0x05` nunca fechava).

**Feito agora, duas partes:**
1. o detector pula prefixos legados e trata `0f xx` como opcode de dois bytes (lista curada de
   opcodes de memória: `6f/7f` movdqa·movdqu, `10/11`, `28/29`, `6e/7e`, `b6/b7`, `be/bf`…);
2. `--data-refs`: lista as referências a **dados que não são strings**, classificadas
   (`máscara` = só `00`/`ff`, `inteiro pequeno` = semente, `zero (não inicializado)`,
   `ponteiro/tabela` = ruído do CRT) e ordenadas — porque a primeira versão listou 100 alvos
   em ordem de RVA e o sinal se perdeu no meio (11 dos 12 primeiros eram `.data` zerada do CRT).

Resultado, no alvo desta rodada (as três constantes, sem leitura manual):

```console
  0x3090 [máscara]          ref em 0x157d (RIP-relativo (0f 6f))  bytes: ff 00 00 00 ff 00 00 00 …
  0x30a0 [máscara]          ref em 0x1595 (RIP-relativo (0f 6f))  bytes: 00 ff ff ff ff ff ff ff …
  0x4000 [inteiro pequeno]  ref em 0x14ae (RIP-relativo (op 0x8b))  bytes: 37 13 00 00 fe ff ff ff …
```

Regressão e custo, medidos: no alvo do 8.1 as referências de string continuam idênticas
(`0x145c`, `0x14d7`, `0x14e7`, `0x14f5`); num PE de **121 MB**, 3 execuções → 8172 / 8386 /
9429 ms (era 7305 ms) e as referências passaram de 54.133 para **54.821** — a cobertura extra
custa ~15%, e isso está dito aqui, não escondido.

### F3 — A checagem vetorizada não tinha caminho no toolkit (declarado, não escondido)

**Momento:** com o pipeline em SSE2, o caminho que existia era ler 30 instruções à mão e
replicar — e a leitura manual errou uma instrução (o `pshufhw` de dois registradores), o que
só foi descoberto porque o alvo rejeitou a primeira candidata.
**Feito agora (parcial e honesto):** o *princípio* virou documentação, não código —
[docs/06-workflows.md](../docs/06-workflows.md) Cenário 12 ganhou o critério "linear → resolve
por álgebra, **não** precisa de emulador; não linear (hash, S-box, laço com memória) → aí sim
Unicorn/Qiling ou o debugger". O solver em si é **do caso** e vive em
`work/<alvo>/scripts/` (é o contrato de artefatos do 01-arquitetura: código de alvo não vai
para o toolkit). O que o toolkit deve dar — as constantes e o trecho de código — agora dá.

### F4 — Nada a consertar em: `--stdin` e classificação de exit code do `diagnose-load`

Registro de fricção **zero** aqui, de propósito: o que o 8.1 corrigiu foi exatamente o que esta
rodada precisou (rodar o alvo com a candidata e ver a saída). O harness `--stdin` +
`--stdin-file` funcionou de primeira, inclusive com bytes binários.

### F6 — A convenção de encoding do Python não chegava a quem escreve script **do caso**

**Momento:** no fim da rodada, um script avulso do caso (o próprio utilitário de editar a
saída de evidência) morreu com `UnicodeEncodeError: 'charmap' codec can't encode character
'\ufeff'` — o mesmo problema que o 8.1 consertou no script do **toolkit** e documentou em
`scripts/README.md`. Quem escreve script de caso (`work/<alvo>/scripts/`) nunca passa por esse
arquivo: o alerta existia no lugar errado.
**Feito agora:** o template de `notes/intake.md` (criado por `new-case.ps1`) avisa onde o
script do caso mora **e** da armadilha de encoding, apontando para a convenção. Verificado
criando um caso de teste, lendo o intake gerado e removendo o caso.

### F5 — O `--refs` antigo escondia as referências que não são string

Consequência direta do F2: o `refIndex` já continha TODO alvo RIP-relativo do código; o
relatório mostrava apenas os que caíam em string. Ou seja, o dado estava calculado e não era
impresso — a pior forma de lacuna, porque parece que a ferramenta não sabe. Corrigido em F2
(`--data-refs`) e citado na doc.

---

## 6. O que mudou no toolkit nesta rodada

| Arquivo | Mudança | Fricção |
|---|---|---|
| `scripts/pe-read.mjs` | **novo** — leitura de bytes por RVA/offset, hexdump + leitura tipada + JSON; 2 bugs próprios corrigidos no teste (u64 em hex, exit code do `--as` inválido) | F1 |
| `scripts/triage-static.mjs` | detector de referências corrigido (prefixos `66`/`F2`/`F3` e opcode de dois bytes `0f xx`) + `--data-refs` com classificação e ordenação das constantes | F2, F5 |
| `scripts/README.md` · `README.md` | os dois comportamentos novos no mapa de scripts | F1, F2 |
| `docs/06-workflows.md` | Cenário 0: `pe-read.mjs` e `--data-refs` no passo de triagem; Cenário 12: critério **linear vs. não linear** (quando NÃO precisa de emulador) | F3 |
| `scripts/new-case.ps1` | o template de `notes/intake.md` agora diz onde mora o script **do caso** e avisa da armadilha de encoding do `stdout` no Windows | F6 |
| `reports/round-8-2-nivel-2.md` | este relatório | — |

## 7. O que NÃO funcionou, e o que continua em aberto (sem maquiagem)

- **Ghidra e x64dbg seguem não exercitados** por esta linha de alvos: a triagem mostrou que não
  eram necessários. Esta rodada **não** é evidência de que eles funcionam.
- **O `pshufhw` de dois registradores é uma ambiguidade real de leitura, e o toolkit não a
  resolve** — quem resolveu foi o alvo, testando as duas candidatas. Um emulador de instrução
  (Unicorn, catalogado e não usado) daria a resposta de primeira; fica declarado como o
  próximo degrau natural (§F3).
- **O solver é do caso** (`work/crackme-n2/scripts/solve-n2.py`) e não roda no CI, porque
  depende do binário do alvo — que não vai para o Git por regra. A parte reutilizável (achar as
  constantes e ler os bytes) é que virou ferramenta.
- **A remoção de prefixos/opcodes curados é heurística**: `--data-refs` acha candidatos, não
  monta a instrução. Alvo com ofuscação de fluxo vai gerar ruído — e o ruído é visível na
  ferramenta (classificação `ponteiro/tabela`/`dados`), não escondido.
- **Custo maior no alvo grande**: 121 MB agora leva 8,2–9,4 s (era 7,3 s) para achar ~700
  referências a mais. Se virar problema, o caminho é `--no-strings`.
- **Cobertura de licença segue 28/31** (`WSL/Ubuntu`, `sasquatch`, `firmware-mod-kit`): nesta
  rodada não entrou ferramenta nova de terceiros, então nada mudou aí — e nada foi inventado.
- **`nivel 3` em diante não foi tocado**, por escopo.

## 8. Reprodução (na ordem)

```powershell
# 1) inventário + congelamento (hash estável)
ls "C:/Users/Admin/Desktop/Alvos/nivel 2"
powershell -File scripts/new-case.ps1 -Name crackme-n2 -Target "…/My_Second_Crackme.exe" …
sha256sum work/crackme-n2/src/My_Second_Crackme.exe

# 2) triagem — nada abre GUI
node scripts/identify-protections.mjs <alvo>                 # empacotado? não
node scripts/diagnose-load.mjs <alvo>                        # carrega; alvo de console
node scripts/triage-static.mjs <alvo> --refs --min 4         # strings + quem as usa
node scripts/triage-static.mjs <alvo> --data-refs            # as CONSTANTES (máscaras/semente)

# 3) leitura do código e dos dados
python scripts/disasm-range.py <alvo> 0x1440 --fim 0x1700 --strings   # main inteiro
node scripts/pe-read.mjs <alvo> --rva 0x4000 --len 8 --as u32         # semente 0x1337
node scripts/pe-read.mjs <alvo> --rva 0x3090 --len 32                 # as duas máscaras

# 4) resolver (script DO CASO) e confirmar com o alvo
python work/crackme-n2/scripts/solve-n2.py
node scripts/diagnose-load.mjs <alvo> --stdin "Xor_N0t_3nough"        # 3×, determinístico
node scripts/diagnose-load.mjs <alvo> --stdin "H3llo_Crackme"          # controle: falha
```

Artefatos brutos (locais, fora do Git por regra): `work/crackme-n2/evidence/20261014-201…210`.

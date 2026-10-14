# Round 8.1 — primeiro alvo real (`nivel 1`): resultado técnico + fricção medida do toolkit

Esta rodada não foi "resolver o crackme": foi **testar o toolkit contra um alvo que ele nunca
viu**, com dois entregáveis de peso igual — (1) o resultado técnico contra o alvo e (2) o
registro do que **atrapalhou** no caminho. Cada fricção abaixo é um momento real, com o
comando que a expôs, e cada correção foi feita **nesta rodada** (nada de "registra pra
depois"), com a verificação correspondente.

Resumo em uma linha: o alvo **não tem proteção de carregamento** — é lógica pura —, foi
resolvido inteiro **sem abrir Ghidra nem debugger** (senha + flag com controle black-box), e
o caminho que faltava para isso (triagem estática e desmontagem por comando) entrou no
toolkit como `scripts/triage-static.mjs` e `scripts/disasm-range.py`, junto com três bugs
reais que só apareceram porque o toolkit foi usado de verdade.

| Entregável | Estado |
|---|---|
| Resultado técnico (senha + flag, com controle) | ✅ `H3llo_Crackme` · `CMO{H3llo_Crackme}` |
| O alvo é empacotado/protegido? | ❌ não — nenhuma assinatura; sem vício de loader |
| Fricções registradas | 10 (todas com comando + saída) |
| Fricções corrigidas nesta rodada | 8 (as outras 2 são declaradas como limitação) |
| Debugger/Ghidra abertos | **zero** — a triagem disse que não era preciso |

---

## 1. Passo 1 — Inventário (antes de qualquer ataque)

```console
$ ls -la "C:/Users/Admin/Desktop/Alvos/nivel 1"
total 20
drwxr-xr-x 1 Admin 197121     0 Oct 14 11:47 .
drwxr-xr-x 1 Admin 197121     0 Oct 14 12:08 ..
-rwxr-xr-x 1 Admin 197121 13824 Oct  7 14:08 My_First_Crackme.exe
```

Um **único** arquivo. Não veio leia-me, enunciado, `readme.txt` nem pasta com descrição do
desafio — o "enunciado" tem de ser lido do próprio binário (é o que a triagem faz).

Identidade do arquivo, pelo intake canônico (`new-case.ps1`) e pela triagem:

```console
$ node scripts/triage-static.mjs work/crackme-n1/src/My_First_Crackme.exe --no-strings
  13824 bytes · PE32+ · x64 · ImageBase=0x140000000 · EP=0x13d0 · SizeOfImage=0x8000
  DllCharacteristics=0x8160
  seções:
    .text      rva=0x1000  virt=6358     raw=6656     -X entropia=5.82
    .rdata     rva=0x3000  virt=3824     raw=4096     -- entropia=4.18
    .data      rva=0x4000  virt=280      raw=512      W- entropia=0.58
    .pdata     rva=0x5000  virt=288      raw=512      -- entropia=2.37
    .tls       rva=0x6000  virt=16       raw=512      W- entropia=0
    .reloc     rva=0x7000  virt=96       raw=512      -- entropia=1.26
```

Ficha: **PE32+ / x64**, 13.824 bytes, SHA-256
`CAC10BE10CAC29DCB86967DC634AE006B9029B0D85C44037E48407CDBB40E0D9`, toolchain MinGW-w64
(`api-ms-win-crt-*` + a string `Mingw-w64 runtime failure:`), sem `.NET`. `.tls` com 16 bytes
é o primeiro sinal que interessa: **TLS callbacks** (a seção existe; medidos abaixo).

## 2. Passo 2 — Triagem, não ataque direto

As duas perguntas do enunciado, respondidas antes de qualquer ferramenta pesada:

```console
$ node scripts/identify-protections.mjs work/crackme-n1/src/My_First_Crackme.exe
  tamanho: 13824 bytes · arq: x64 · entrypoint: 0x13d0
  [ok] nenhuma assinatura de packer/protetor conhecida.
  Veredito: sem assinatura conhecida

$ node scripts/diagnose-load.mjs work/crackme-n1/src/My_First_Crackme.exe --stdin H3llo_Crackme
  [i ] reloc-ok — 38 entradas de relocação, todas em seções com dados
  [? ] securitycookie-ausente — LOAD_CONFIG não declara SecurityCookie (imagem sem CRT…
  [i ] run — exit=0x0 (ok) · stdin alimentado (14 bytes)
  [i ] saída do alvo (2 linha(s)):
        | enter the password : Yeaaaaa!!! Discord : imrate
        | Flag : CMO{H3llo_Crackme}

  Veredito: sinais de remontagem, sem vício crítico
```

**Resposta honesta: o alvo NÃO é empacotado nem protegido.** Nenhuma assinatura de packer, o
loader aceita a imagem e o processo roda. É a segunda categoria do enunciado — *lógica
ofuscada (na verdade nem ofuscada) sem proteção de carregamento*. O `securitycookie-ausente`
não é vício aqui: este binário é MinGW e simplesmente não tem CRT MSVC (`__security_cookie`
não existe para estar torto).

Consequência direta, e é ela que poupa o trabalho: **o Cenário 1 não se aplica**. Sem packer
não há OEP a achar, dump a fazer nem IAT a reconstruir — logo, nenhum breakpoint, nenhum
`x64dbg`, nenhum `DumpModule`. O alvo se resolve lendo o código.

## 3. O caminho que resolveu (estático, ~100 bytes de código)

O alvo tem duas funções que importam. A primeira é o `main`, a segunda é o **verificador** —
ambas lidas com um comando, sem GUI:

```console
$ python scripts/disasm-range.py work/crackme-n1/src/My_First_Crackme.exe 0x1440 --fim 0x1519 --strings
  0x0145c  lea     rcx, [rip + 0x1c2d]   ; "enter the password : "
  0x014af  lea     rdx, [rip + 0x1bf0]   ; -> rva 0x30a6
  0x014c4  call    0x140001520           ; <-- o verificador
  0x014c9  cmp     eax, 0
  0x014cc  je      0x1400014f5
  0x014d7  lea     rcx, [rip + 0x1bcb]   ; "Yeaaaaa!!! Discord : imrate"
  0x014e7  lea     rcx, [rip + 0x1bd8]   ; "Flag : CMO{%s}"
  0x014f5  lea     rcx, [rip + 0x1bda]   ; "Not today..."

$ python scripts/disasm-range.py work/crackme-n1/src/My_First_Crackme.exe 0x1520 --fim 0x1553 --strings
  0x01529  lea     rcx, [rsp + 0x22]
  0x0152e  call    0x140001560           ; gera a senha esperada
  0x0153d  call    0x140002730           ; strcmp(alvo, digitado)
  0x01545  sete    al

$ python scripts/disasm-range.py work/crackme-n1/src/My_First_Crackme.exe 0x1560 --fim 0x15b4 --strings
  0x01571  cmp     qword ptr [rsp], 0xd       ; 13 bytes
  0x0157c  lea     rax, [rip + 0x1b61]        ; -> rva 0x30e4
  0x01583  movzx   eax, byte ptr [rax + rcx]
  0x01587  xor     eax, 0x2a                 ; <-- XOR 0x2A
  0x01595  mov     byte ptr [rax + rcx], dl
  0x015ab  mov     byte ptr [rax + 0xd], 0     ; NUL final
```

Ou seja: o alvo **gera** a senha esperada (`rva 0x30e4`, 13 bytes, XOR `0x2A`) e compara com o
que foi digitado. Os bytes e o resultado:

```console
$ python -c "
b=[0x62,0x19,0x46,0x46,0x45,0x75,0x69,0x58,0x4b,0x49,0x41,0x47,0x4f]   # rva 0x30e4, 13 bytes
print('bytes :', ' '.join(f'{x:02x}' for x in b))
print('xor2a :', bytes(x^0x2a for x in b).decode())
"
bytes : 62 19 46 46 45 75 69 58 4b 49 41 47 4f
xor2a : H3llo_Crackme
```

## 4. Verificação black-box (a prova de que não é palpite)

Três execuções independentes e dois controles, pelo próprio toolkit (`--stdin` entrou nesta
rodada — ver §5, F3):

```console
$ node scripts/diagnose-load.mjs … --stdin H3llo_Crackme      # ×3, determinístico
        | enter the password : Yeaaaaa!!! Discord : imrate
        | Flag : CMO{H3llo_Crackme}

$ node scripts/diagnose-load.mjs … --stdin senha-errada        # controle
        | enter the password : Not today...

$ node … --stdin FFEuiXKIAGO                                   # controle: os BYTES crus, sem o XOR
        | enter the password : Not today...                    # <- prova que o XOR é obrigatório

$ node … (sem stdin)                                           # controle: EOF
  [i ] run — exit=0x1 (saiu normalmente…)
```

O último controle é o mais informativo: a saída crua da tabela (`FFEuiXKIAGO`) **não** é a
senha; só o XOR de `0x2A` sobre ela é. Um "achado" que tivesse parado na string estaria
errado — foi o teste de controle que mostrou isso.

**Resultado:** senha `H3llo_Crackme`, flag `CMO{H3llo_Crackme}`.

---

## 5. Passo 3/4 — Fricção registrada e corrigida (o segundo entregável)

Tudo abaixo aconteceu **durante** a rodada, e o ganho entrou agora — o próximo nível já usa.

### F1 — Não havia triagem estática: `GetStrings`/`GetImports` exigem o debugger vivo

**Momento:** o primeiro passo natural ("o que este binário importa? o que ele imprime?") não
tinha caminho no toolkit. As ferramentas de leitura do MCP do x64dbg precisam da GUI aberta;
`identify-protections.mjs` responde outra pergunta. Para um alvo de 13 KB isso significava
abrir o debugger só para ler 74 strings.
**Feito agora:** `scripts/triage-static.mjs` — cabeçalho, seções com permissões/entropia,
data directories, **TLS callbacks**, imports por DLL, strings de seções de dados com RVA e,
com `--refs`, onde cada uma é usada no código. Zero dependência externa.

### F2 — A primeira versão do scanner produziu lixo: 164 "strings", quase todas código

**Momento:** a varredura ingênua (arquivo inteiro) devolveu 164 candidatas — `.text`
disfarçado de texto (`"fffff."`, `"AWAVAUATVWUSH"`, nomes de seção) — e a string que
importava ficou diluída.

```console
$ node -e "…varredura ingênua no arquivo inteiro…"
arquivo inteiro: 164 candidatas; exemplos de lixo: [".text","`.rdata","@.data","fffff."]
$ node scripts/triage-static.mjs … --min 4 --json | python -c "…len(d['strings'])…"
triage-static (dados, >=4): 74 strings; TLS callbacks: 2
```

**Feito agora:** string de verdade mora em seção **não executável** — o filtro é obrigatório
e está documentado no cabeçalho do script, junto com o motivo.

E a resposta a "onde essa string é usada?" não pode ser uma varredura por string: isso é
`O(strings × bytes de código)` — invisível num arquivo de 13 KB, inviável num alvo de
verdade. A segunda versão faz **uma** passada no código indexada por destino; medido no lado
oposto do espectro, um PE de **121 MB**:

```console
$ node scripts/triage-static.mjs C:/Windows/System32/amd_comgr_2.dll --refs --json
exit=0  tempo=7305 ms
formato: PE32+ x64 | secoes: 9 | imports DLL: 5 | strings: 327992 | com ref: 54133
exemplo: 'amdgpu::Linker' -> RIP-relativo (lea)
```

327.992 strings e 54.133 com referência em 7,3 s — o número que faltava para saber se a
ferramenta serve para alvo real, não só para o crackme.

### F3 — `diagnose-load.mjs` não alimentava `stdin` (alvo com prompt interativo)

**Momento:** o alvo pede a senha em `stdin`. Sem conseguir alimentá-lo, a única saída era
rodar na mão e comparar visualmente — ou seja, um passo manual que deveria ser automatizado.
**Feito agora:** `--stdin <texto>` / `--stdin-file <arquivo>`, e o script passou a **capturar
a saída do alvo** (antes ele só olhava o exit code). É o que produziu a §4.

### F4 — Saída normal do programa era reportada como "status não catalogado"

**Momento:** o alvo sai com `1` quando o `stdin` fecha (EOF). O script imprimia
`exit=0x1 (status não catalogado)` — veredito que parece defeito de loader e não é.

```console
antes:   [i ] run — exit=0x1 (status não catalogado)
depois:  [i ] run — exit=0x1 (saiu normalmente com status 1 — código do PRÓPRIO programa,
                 não é falha de loader) · stdin: EOF (sem --stdin)
```

**Feito agora:** o script distingue NTSTATUS de loader (a faixa `0xC0000000+`) de código de
saída do programa, e diz em qual dos dois mundos está.

### F5 — Não existia caminho de desmontagem estática (e não havia ferramenta instalada)

**Momento:** para ler o verificador era preciso um desmontador. Medição da máquina:

```console
$ for t in objdump dumpbin r2 rizin rabin2 ndisasm cstool gdb llvm-objdump; do command -v $t; done
objdump (ausente) · dumpbin (ausente) · r2 (ausente) · rizin (ausente) · rabin2 (ausente)
ndisasm (ausente) · cstool (ausente) · gdb (ausente) · llvm-objdump (ausente)
$ python -c "import capstone; print(capstone.__version__)"
5.0.7
```

Existia **só** o Capstone (biblioteca Python), que nenhum script do toolkit usava.
**Feito agora:** `scripts/disasm-range.py` (intervalo de RVA com `--fim`, seção inteira com
`--section`, `--strings` anotando RIP-relativo, `--json`), com a dependência declarada.

### F6 — O Capstone estava catalogado, mas **não era instalado nem sondado** — em nenhum lugar

**Momento:** ao escrever o script acima ficou claro o buraco: a documentação promete capstone
no perfil `static` (README §3, docs/02 §a.3, docs/04), o `bootstrap-windows.ps1` não tinha a
entrada, e nem o bootstrap nem o `health-check` sabiam dizer se o módulo estava instalado —
porque **biblioteca não tem comando no PATH** (`cstool` não vem no pacote do pip).

```console
# antes: nenhuma linha sobre capstone em --Profile static / health-check
# depois, nas duas direções:
$ powershell -File scripts/bootstrap-windows.ps1 -Profile static -DryRun
  [OK  ] Capstone — já instalado (módulo Python 'capstone')
$ PATH=/tmp/fakepy:$PATH powershell -File scripts/bootstrap-windows.ps1 -Profile static -DryRun
── Capstone  [static]
   por quê: disassembler programático — scripts/disasm-range.py depende dele
  [INFO] pip install --user capstone

$ powershell -File scripts/health-check.ps1 -Json | …
[{"Check": "pymod:capstone", "Level": "OK", "Detail": "desmontagem estática — scripts/disasm-range.py"}]
summary: {"ok": 40, "warn": 0, "fail": 0}
```

**Feito agora:** entrada `Capstone` no catálogo do perfil `static` (`Pip = 'capstone'`) mais um
mecanismo novo, `PyModule` + `Test-PythonModule` em `scripts/lib/common.ps1`, para sondar
**módulo Python** (validado por regex — nada de código arbitrário indo para `python -c`).

### F7 — O script Python morria **no meio da saída** com `UnicodeEncodeError` (cp1252)

**Momento:** encontrado ao gravar a própria evidência da rodada — o `stdout` redirecionado
(a forma canônica do toolkit: `> evidence/….txt`) herda cp1252 e o `─` do relatório derruba o
script **depois** de metade da saída já impressa:

```console
$ python -c "print('─'*70)" > /tmp/before.txt
exit=1
UnicodeEncodeError: 'charmap' codec can't encode characters in position 0-69: character maps to <undefined>

$ python scripts/disasm-range.py … --strings > /tmp/after.txt      # com a correção
exit=0   stderr=0 bytes
```

**Feito agora:** `_setup_console()` escolhe pelo destino — redirecionado vira UTF-8 (o arquivo
de evidência fica correto), console vira a code page local com `errors='replace'` (nada
derruba a análise). E a armadilha virou **convenção escrita** em
[scripts/README.md](../scripts/README.md) §Convenções.

### F8 — O teste de consistência não olhava `.py` — e, ao passar a olhar, achou uma doc errada

**Feito agora:** `check-consistency.mjs` varre referências `scripts/*.{ps1,sh,mjs,py}`. Na
primeira execução pegou um erro real de documentação que estava lá havia rodadas:

```console
  [FAIL] (scripts) docs/02-catalogo-ferramentas.md: referencia scripts/patch-entry.py, que não existe
```

`docs/02` §a.2 mandava rodar `python scripts/patch-entry.py` como se o **toolkit** o
distribuísse; o próprio comentário da linha dizia "ver `work/<alvo>/scripts/`". Corrigido na
doc (é script **do caso**, não do toolkit). E a extensão expôs um defeito no próprio checker:
`work/<alvo>/scripts/x.py` era lido como `scripts/x.py` (o prefixo `/` opcional consumia a
barra e a barreira de lookbehind não pegava), então a regra passou a exigir que a referência
**comece** em início de linha ou depois de espaço/aspas/backtick/colchete/`=`/`:`. Verificado
nos dois sentidos: 10 expectativas de regex ✅ e, com uma referência quebrada de verdade
injetada num doc temporário, `exit=1` (depois removido — nada de arquivo de teste sobrando).

### F9 — O workflow documentado não tinha o caminho "sem proteção de carregamento"

**Momento:** o enunciado manda documentar esse caso como resultado honesto, e o
[docs/06-workflows.md](../docs/06-workflows.md) só tinha o Cenário 1 (packer → dump → IAT).
**Feito agora:** o Cenário 0 (preparação, que é obrigatório) ganhou o **passo 3 — triagem
estática sem debugger**, com os quatro comandos e o critério de decisão ("se não há proteção,
não existe dump/OEP/IAT a reconstruir"); [docs/07](../docs/07-operacao-por-ia.md) ganhou a
regra correspondente e um item no checklist de sessão de IA.

### F10 — O custo real do caminho novo (medido, não estimado)

```console
  110 ms  exit=0  node scripts/identify-protections.mjs <alvo>
  110 ms  exit=0  node scripts/triage-static.mjs <alvo> --refs
  204 ms  exit=0  python scripts/disasm-range.py <alvo> 0x1420 --fim 0x1560 --strings
  117 ms  exit=0  node scripts/diagnose-load.mjs <alvo> --stdin H3llo_Crackme
```

Meio segundo para responder "o que é, o que imprime, o que ele compara" — contra o custo de
subir Ghidra/x64dbg para descobrir que não era preciso. É o argumento de F9 em número.

---

## 6. O que mudou no toolkit nesta rodada

| Arquivo | Mudança | Fricção |
|---|---|---|
| `scripts/triage-static.mjs` | **novo** — triagem estática completa, sem dependências | F1, F2 |
| `scripts/disasm-range.py` | **novo** — desmontagem por intervalo de RVA, com strings RIP-relativas | F5, F7 |
| `scripts/lib/common.ps1` | `Test-PythonModule` (sonda de biblioteca Python, validada por regex) | F6 |
| `scripts/bootstrap-windows.ps1` | entrada `Capstone` no perfil `static` + probe por módulo (`PyModule`) | F6 |
| `scripts/health-check.ps1` | seção de bibliotecas Python (`pymod:*`) no relatório do catálogo | F6 |
| `scripts/diagnose-load.mjs` | `--stdin`/`--stdin-file`, captura da saída do alvo, exit code classificado | F3, F4 |
| `scripts/check-consistency.mjs` | cobre `.py` e não confunde caminho de caso com script do toolkit | F8 |
| `scripts/README.md` · `README.md` | os dois scripts novos no mapa + convenção de encoding do Python | F1, F5, F7 |
| `docs/06-workflows.md` · `docs/07-operacao-por-ia.md` · `docs/02-catalogo-ferramentas.md` | triagem estática como passo obrigatório; capstone instalável e sondável | F9, F6, F8 |
| `.github/workflows/ci.yml` | sintaxe de todo `scripts/*.py` (`py_compile`) — o análogo de `node --check`/`bash -n` | F5 |

## 7. O que NÃO funcionou, e o que continua em aberto (sem maquiagem)

- **Ghidra e x64dbg não foram exercitados nesta rodada** — por decisão, não por falha: a
  triagem mostrou que não eram necessários. Isso significa que esta rodada **não** pode ser
  citada como evidência de que eles funcionam; a evidência deles é dos relatórios anteriores.
- **`triage-static --refs` é heurística declarada**: dá candidatos (RIP-relativo por opcode
  típico + ponteiro absoluto de 8 bytes), não monta a instrução. Para ler a instrução exata,
  `disasm-range.py`; para fluxo/xrefs completos, Ghidra.
- **`disasm-range.py` é linear**: não segue fluxo, não resolve chamada indireta, e um `--fim`
  no meio de uma instrução contamina o resto. Não é decompilador.
- **`triage-static --refs` num alvo muito grande custa segundos, não instantâneo**: 121 MB →
  7,3 s e ~330 mil strings na saída JSON (medido). É aceitável para triagem, e é o motivo de
  existir o `--no-strings` e o `--min N`; acima disso, o caminho é filtrar por referência em
  vez de despejar tudo.
- **A codificação do console foi corrigida no script, não imposta a todos**: a convenção está
  escrita e o CI compila os `.py`, mas o CI **não executa** nenhum script Python (não há alvo
  nem Windows no runner). Um `.py` futuro que imprima símbolo sem ajustar o encoding volta a
  quebrar do mesmo jeito — está documentado, não automatizado.
- **Cobertura de licença segue 28/31** do bootstrap (as três sem linha verificada contra a
  fonte primária: `WSL/Ubuntu`, `sasquatch`, `firmware-mod-kit`) — o capstone entrou na
  cobertura por já ter linha no registro; nenhuma linha nova foi inventada nesta rodada.
- **Nada do alvo vai para o Git**: `work/crackme-n1/` inteiro (amostra, scripts do caso,
  evidence) é ignorado; o que é reproduzível ficou neste relatório e nos scripts do toolkit.
- **`nivel 2` em diante não foi tocado** — por escopo explícito.

## 8. Reprodução (na ordem)

```powershell
# 1) inventário + congelamento da entrada
cd work/crackme-n1/src ; sha256sum My_First_Crackme.exe

# 2) triagem — nenhuma destas abre GUI
node scripts/identify-protections.mjs <alvo>          # empacotado? não
node scripts/triage-static.mjs <alvo> --refs          # TLS, imports, 74 strings e onde são usadas
node scripts/diagnose-load.mjs <alvo>                 # carrega normalmente (sem vício de loader)

# 3) leitura do código (alternativa ao Ghidra, para o trecho que importa)
python scripts/disasm-range.py <alvo> 0x1440 --fim 0x1519 --strings   # main
python scripts/disasm-range.py <alvo> 0x1520 --fim 0x1553 --strings   # verificador
python scripts/disasm-range.py <alvo> 0x1560 --fim 0x15b4 --strings   # XOR 0x2A, 13 bytes em rva 0x30e4

# 4) prova black-box (senha calculada + dois controles)
node scripts/diagnose-load.mjs <alvo> --stdin H3llo_Crackme
node scripts/diagnose-load.mjs <alvo> --stdin FFEuiXKIAGO      # controle: os bytes crus NÃO passam
```

Artefatos brutos desta rodada (locais, fora do Git por regra): `work/crackme-n1/evidence/`
(`…-91` a `…-102`), com os comandos e as saídas completas de cada passo.

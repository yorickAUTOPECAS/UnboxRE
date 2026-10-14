# Adendo aos rounds 8.3 e 8.4 — laboratório Linux (WSL) e o fechamento black-box dos dois alvos

Este arquivo é **adendo**, não reescrita: [round-8-3-nivel-3.md](round-8-3-nivel-3.md) e
[round-8-4-nivel-4.md](round-8-4-nivel-4.md) continuam como foram aprovados. Aqui está o que
**mudou no ambiente** e o que a mudança permitiu medir — inclusive onde ela **corrige** uma
conclusão anterior.

Padrão de prova: cada afirmação tem comando + saída; o que não funcionou está na §5, separado.

---

## 1. O ambiente antes e depois

| | Antes (8.3/8.4) | Agora (medido) |
|---|---|---|
| Alvos ELF (`nivel 3`) | binário não rodava: só emulação + modelo fechado | `stckwzrd` roda de verdade; senha confirmada pelo próprio binário |
| Alvos pyzip com runtime `.so` (`nivel 4`) | rodava até `ImportError: DLL load failed … erro 193` | roda inteiro: a runtime ELF carrega e o programa pergunta a senha |
| WSL | ⚠️ binário presente, **nenhuma distro instalada** | **Ubuntu-26.04 em WSL1**, com CPython 3.13 dentro |

Saída real (evidência `work/crackme-n3`/`n4/evidence/20261014-407-wsl-ambiente.txt`):

```console
# lado Windows
Versão do WSL: 2.7.10.0      Versão do kernel: 6.18.33.2-2      Versão do Windows: 10.0.26200.9457
  NAME            STATE           VERSION
* Ubuntu-26.04    Stopped         1

# dentro da distro
Linux 4.4.0-26100-Microsoft x86_64
PRETTY_NAME="Ubuntu 26.04.1 LTS"      VERSION_ID="26.04"
  python3 do sistema : Python 3.14.4
  python3.13 (uv)    : Python 3.13.16
```

Três detalhes que valem registro, porque decidem o que dá e o que não dá:

1. **É WSL1, e por medição — não por escolha.** A conversão para WSL2 falha com
   `HCS_E_HYPERV_NOT_INSTALLED` ("a virtualização não está habilitada"): o firmware desta máquina
   não expõe VT-x. `wsl --set-version Ubuntu-26.04 1` registra a distro **sem Hyper-V**, e é o que
   ficou. Consequência honesta: o kernel é `4.4.0-*` **emulado** — serve para ELF e para CPython,
   mas não é um kernel Linux de verdade (sem namespaces/eBPF/perf completos).
2. **Ubuntu 26.04 não tem `python3.13` no repositório** (o sistema é 3.14.4) e o payload exige
   3.13. Quem resolveu foi o `uv`, baixando um CPython 3.13 *standalone* para linux-x86_64:
   `/root/.local/share/uv/python/cpython-3.13-linux-x86_64-gnu/bin/python3.13`. Nada disso toca o
   Python do host Windows.
3. **Nenhuma elevação foi usada** nesta rodada (nem `sudo`, nem `Start-Process -Verb RunAs`), e
   nada foi instalado no Windows por causa disto: a distro serve **só** ao que é Linux por
   natureza (ELF do 8.3 e a runtime `.so` do 8.4). A triagem de PE continua no host.

---

## 2. `nivel 3` (8.3) — de "modelo concordando" para **black-box**

O 8.3 fechou a senha por emulação + modelo, porque **não havia Linux neste host**. Agora há, e o
binário responde por si (evidência `work/crackme-n3/evidence/20261014-312-wsl-blackbox.txt`):

```console
=== 1) o alvo suporta ptrace aqui? (é o anti-debug do alvo) ===
  ptrace(PTRACE_TRACEME) -> 0  (errno=0)
  0 = suportado (o alvo escolhe a semente 0x5a); -1 = sem suporte (o alvo escolhe 0)

=== 2) o alvo ===
3bc0c0c2fbcaf696bfbe613d3745e1d453e7601449e8d449994966868061b7ed    <- hash do caso congelado

=== 3) senha encontrada no round 8.3 (por emulação + modelo fechado) ===
  stckwzrd :: the stack wizard guards this gate
  serial>   the stack unwinds cleanly. ACCESS GRANTED.
  exit=0

=== 4) controles ===
  St4ckW1z4rd_0x00  ->  the stack overflows with doubt. denied.        exit=0
  senhaerrada       ->  the wizard scoffs. (wrong length)              exit=1
```

Leitura: **a senha está certa** (`ACCESS GRANTED`), os controles recusam, e o caminho de
anti-debug percorrido é o de "sem debugger" — que é o mesmo que um Linux normal daria, já que
`ptrace` está disponível (retorno 0). O que era hipótese sobre o `ptrace` do alvo agora é medida
com o alvo executando.

---

## 3. `nivel 4` (8.4) — a senha e a flag, com o alvo **rodando**

### 3.1 O que roda agora

```console
$ ctypes.CDLL(Y5zl4Kpf/srLX0FXx.so) -> OK (47352 bytes)      # era o que falhava no Windows
$ printf 'teste\n' | python3.13 target.pyz
password: invalid
```

### 3.2 O caminho que destravou: **instrumentar o CPython, não o binário**

O `.so` importa exatamente isto (medido com `nm -D -u`):

```console
U _PyInterpreterState_SetEvalFrameFunc   U _PyInterpreterState_GetEvalFrameFunc
U _PyEval_EvalFrameDefault               U PyUnstable_InterpreterFrame_GetCode
U PyRun_SimpleString                     T PyInit_srLX0FXx       <- único símbolo exportado
```

Ou seja, é um módulo de extensão que **troca o avaliador de frames** e nenhum `memcmp`/`strcmp`:
não há comparação em C para interceptar. Em vez de partir para Ghidra ou debugger nativo, o
instrumento passou a ser o próprio interpretador: um `sitecustomize.py` no `PYTHONPATH` (que o
launcher do alvo repassa ao filho) registra `hashlib`/`base64`, a **pilha de quem chama
`input()`**, as operações feitas sobre a entrada e os `print()`s.

Três medições definiram o que fazer, nesta ordem:

**(a) A pilha mostrou que quem pergunta a senha é o payload em Python** — não o `.so`:

```console
input('password: ') <- pilha:
    /tmp/e01d4c4b…/Y5zl4Kpf/burw392w:44 em <module>
    <member>:132 em <module>
  -> 'teste'
```

**(b) As strings são montadas em runtime a partir de listas de inteiros.** Por isso `password` e
`invalid` não apareciam em nenhum `co_consts` do payload (e a minha varredura estática não os
achava). A própria linha-fonte do helper (`burw392w:44`) mostra a forma:
`''.join(chr((B[i] - c ^ A[i % len(A)]) & 255) …)`. Confirmação de que a forma está certa:
`( [211,222,232,189], [189,173,148,229], 7 )` decodifica para **`exec`**, que é o que aquela
linha chama — ou seja, o `exec` que roda o payload.

**(c) Todas as operações sobre a entrada passaram a ser registradas**, devolvendo-a como uma
subclasse de `str`. O valor esperado se delatou na primeira comparação:

```console
[EspiaStr] __eq__('! ! ! ! ! ! ! !  TREE') -> False   @ burw392w:44 | <member>:132
print('invalid')
```

### 3.3 Confirmação black-box (3× + controles, sem instrumentação nenhuma)

```console
$ python3.13 target.pyz   <  senha           # env sem PYTHONPATH
  candidata, run 1   exit=0  saida='password: CMO{builtins}\n'
  candidata, run 2   exit=0  saida='password: CMO{builtins}\n'
  candidata, run 3   exit=0  saida='password: CMO{builtins}\n'
  entrada errada     exit=0  saida='password: invalid\n'
  entrada errada 2   exit=0  saida='password: invalid\n'
```

| Item | Valor |
|---|---|
| Senha | `! ! ! ! ! ! ! !  TREE` (21 caracteres: `21 20 21 20 21 20 21 20 21 20 21 20 21 20 21 20 20 54 52 45 45`) |
| Flag | `CMO{builtins}` |
| Hash do alvo (caso congelado) | `72eaad9b95c6e9894a20709708f3c35e044bf9910782c353ef54292b4c9ab289` |

A candidata **não foi digitada à mão**: o script lê o log e extrai o literal com
`ast.literal_eval` — os dois espaços entre o último `!` e `TREE` são medição, não transcrição.

### 3.4 De brinde, o que o loader faz: o buffer do `sha512` caracterizado

O alvo manda **1.264.068 bytes** para um `sha512` (capturados em disco pela instrumentação). O que
ele é, medido (`scripts/diff-dump.py`):

```console
  len(dump) == 64 + len(arquivo do zipapp)? True
  bytes coincidentes em dump[64:]: 1263925/1264004
  faixa 0x134933-0x134982 (80 B)
    arquivo : b'$DB393l=WzK|B3<?Ms+h4lV0X?}TbsiH4j%8<`^+4{j_(bZk18!PfhgTqeeDHl|MPXQQzK{4(o=%7a}E'
    hasheado: b'00000000000000000000000000000000000000000000000000000000000000000000000000000000'
  arquivo: marshal OK em offset 0 -> '<module>' consts=233 bytecode=81332
```

Leitura: o buffer é `cabeçalho de 64 B + o payload`, e a **única** alteração é a constante b85 ser
substituída por 80 zeros antes do hash. Ou seja — ao contrário do que o 8.4 supôs — o material que
eu já tinha lido estaticamente **era** o programa real; o que faltava não estava cifrado, estava
**construído em runtime**.

---

## 4. Onde este adendo **corrige** o 8.4

| 8.4 afirmou | Medido agora |
|---|---|
| "Senha/chave **não obtida** … o gate está atrás da runtime nativa" | O gate **não** está atrás da runtime nativa: quem pergunta a senha é o payload em Python (`<member>:132`) e a comparação é uma comparação de `str` em bytecode. O que impedia a leitura estática era a **decodificação de strings em runtime**, não a virtualização |
| "Não aceita substituto: a runtime ELF é obrigatória" | Continua verdade — o payload aborta sem a extensão. Mas "obrigatória" não é "opaca": ela troca o avaliador de frames e, ainda assim, o programa é observável pelo nível Python |
| "payload de 486 code objects / 9.658 instruções no topo" | **Confirmado** pela execução: `marshal` do buffer capturado devolve o mesmo `<module>` (consts=233, bytecode=81.332 B) e 485 code objects aninhados (+1 raiz = 486) |
| "Ghidra, x64dbg, Unicorn e Qiling não exercitados" | **Continua verdade** — e agora está claro que o caminho certo para este alvo é instrumentação no interpretador, não decompilação do `.so` |

---

## 5. O que não funcionou / continua em aberto (sem maquiagem)

- **A varredura estática das strings decodificadas não fechou** (`work/crackme-n4/scripts/decode-strings.py`):
  aplicar as formas observadas a todas as triplas de constantes devolveu **169.548** decodificações
  printáveis — ruído demais para ser conclusão. O que resolveu foi a instrumentação em runtime. Fica
  registrado como tentativa que **não** substitui a medição.
- **WSL1 não é um Linux completo**: kernel `4.4.0-*` emulado. `ptrace` funciona (medido: retorno 0),
  mas namespaces, eBPF, `perf` e o comportamento de anti-debug mais fino não estão garantidos. Para
  os dois alvos desta rodada isso não atrapalhou — e está declarado que é limitação, não equivalência.
- **O harness de instrumentação vive como script do caso** (`work/<alvo>/scripts/sitecustomize.py`
  + `wsl-instrument.sh`), porque é `work/` e `work/` não vai para o Git por regra. Quem quiser repetir
  tem a receita na [docs/06-workflows.md](../docs/06-workflows.md); transformá-la em ferramenta do
  toolkit (um `sitecustomize` + runner reutilizáveis) é **lacuna declarada**, e não foi feita aqui
  para não inflar esta rodada.
- **`nivel 5` e adiante não foram tocados** — escopo.
- **A decisão de tratar o laboratório Linux como parte do ambiente padrão de triagem é sua**, não
  minha: [AGENTS.md](../AGENTS.md) ainda diz que Linux/WSL é roadmap. O que esta rodada prova é que
  ele **funciona para ELF e para alvos Python** nesta máquina — não que ele está suportado.

---

## 6. O que mudou no toolkit nesta rodada

| Arquivo | Mudança | Por quê (medido) |
|---|---|---|
| [scripts/health-check.ps1](../scripts/health-check.ps1) | novo check **`wsl:distro`**: pergunta se existe **distro**, não se o comando existe | `wsl --status` responde numa máquina **sem distro** — foi exatamente o estado que travou os alvos Linux. Com distro: `wsl:distro  OK  Ubuntu-26.04 — alvos ELF/pyzip e pwndbg rodam aqui` |
| [scripts/lib/common.ps1](../scripts/lib/common.ps1) | `Get-CommandVersion` remove NULs da saída | o `wsl.exe` escreve UTF-16LE: capturado como texto, o detalhe saía com um NUL entre cada caractere (`D\u0000i\u0000s\u0000t\u0000r…`). O NUL sai; o **acento não volta** — ver a ressalva abaixo |

Ambos verificados com `health-check.ps1 -Json`: **41 ok / 0 warn / 0 fail**, com o check novo
presente na saída (não é uma afirmação: é o JSON).

```console
  [OK  ] host:wsl — Distribui??o Padr?o: Ubuntu-26.04        # NULs removidos; acentos ainda não
  [OK  ] wsl:distro — Ubuntu-26.04 — alvos ELF/pyzip e pwndbg rodam aqui
```

**Ressalva medida, não maquiada:** o acento mangled **não** é efeito do meu `-replace`. Capturei a
saída crua do `wsl.exe` num arquivo UTF-8 explícito e ela mostra que o dano acontece na *decodificação*:

```console
status=[D\u0000i\u0000s\u0000t\u0000r\u0000i\u0000b\u0000u\u0000i\u0000þ\u0000Ò\u0000o\u0000 …]
status-sem-nul=[DistribuiþÒo PadrÒo: Ubuntu-26.04]
```

Ou seja: o PowerShell 5.1 lê os bytes UTF-16LE do `wsl.exe` como se fossem OEM (CP437), e `ç`/`ã`
chegam como `þ`/`Ò`. Tirar os NULs resolve a ilegibilidade estrutural (o texto vira uma frase
contínua, e o nome da distro — sempre ASCII — sai correto, que é o que o `wsl:distro` imprime);
recuperar o acento exigiria mudar `[Console]::OutputEncoding` em volta da chamada, com efeito
colateral em **todas** as outras capturas nativas do script. Não fiz: o dano é cosmético em 2
detalhes, e está registrado aqui em vez de escondido.

---

## 7. Reprodução (na ordem)

```powershell
# 0) o ambiente existe?
.\scripts\health-check.ps1 -Json                     # procure "wsl:distro"
wsl -l -v                                            # VERSION 1 = WSL1 (sem Hyper-V)

# 1) nivel 3: o ELF roda e a senha do 8.3 é aceita pelo binário
wsl -d Ubuntu-26.04 -u root -- bash work/crackme-n3/scripts/wsl-blackbox.sh
#    -> "the stack unwinds cleanly. ACCESS GRANTED."

# 2) nivel 4: CPython 3.13 dentro do WSL (uma vez)
wsl -d Ubuntu-26.04 -u root -- bash work/crackme-n4/scripts/wsl-setup.sh

# 3) nivel 4: o alvo rodando + instrumentacao do CPython
wsl -d Ubuntu-26.04 -u root -- bash work/crackme-n4/scripts/wsl-instrument.sh "teste"
#    -> no log: a pilha de input(), o dump de 1.264.068 B e o literal comparado

# 4) niv4: extrai a candidata do log e roda o alvo LIMPO (3x + controles)
wsl -d Ubuntu-26.04 -u root -- /root/.local/share/uv/python/cpython-3.13-linux-x86_64-gnu/bin/python3.13 `
    work/crackme-n4/scripts/extract-eq-and-run.py
#    -> 'password: CMO{builtins}'

# 5) evidencia (gera/atualiza os arquivos 312/407/408/409 do caso)
wsl -d Ubuntu-26.04 -u root -- bash work/crackme-n4/scripts/wsl-evidence.sh
```

Evidência bruta (local, fora do Git por regra): `work/crackme-n3/evidence/20261014-312-*`,
`work/crackme-n4/evidence/20261014-407-*`, `…-408-*`, `…-409-*`.

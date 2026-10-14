# Round 8.4 — quarto alvo real (`nivel 4`): resultado técnico + fricção medida do toolkit

Alvo: `C:\Users\Admin\Desktop\Alvos\nivel 4` — **um zipapp do Python 3.13 protegido**, com
uma **runtime nativa ELF** dentro. Nas quatro rodadas o alvo mudou de formato três vezes
(PE → ELF → zipapp), e o aviso valeu: aqui não era nem PE, nem ELF, e **era** protegido.

| | |
|---|---|
| Formato | **zipapp**: `#!/usr/bin/env python3` + ZIP (preâmbulo de 23 bytes, 6 membros) |
| Empacotado/protegido? | **Sim** — protetor de Python com runtime nativa (`rt_p2.c`, ELF64) que troca o executor de frames do CPython; topo do programa **aplanado** (dispatcher de 127 rótulos) |
| Plataforma | **Linux** — a runtime é `.so` ELF e o payload **recusa** rodar sem ela |
| Interpretador | **CPython 3.13** (evidência: `/usr/local/include/python3.13/object.h` dentro do `.so`) |
| Lógica | Não-linear e anti-análise (VM nativa + fluxo aplanado) → Cenário 12 manda para emulação/debugger |
| O alvo foi executado? | **Não até o fim** — com 3.13 roda e morre em `ImportError ... %1 não é um aplicativo Win32 válido` (erro 193); com 3.11/3.12 (as versões que a máquina tinha) **não dá erro: dá access violation** |
| Senha/chave | **Não obtida**, declarado na §5 — o gate está atrás da runtime nativa |
| Ferramentas do toolkit | **1 script novo** (`triage-archive.mjs`) + 4 docs; zero Ghidra, zero x64dbg |

---

## 1. Passo 1 — Inventário (antes de qualquer ataque)

```console
$ ls -la "/c/Users/Admin/Desktop/Alvos/nivel 4"
-rwxr-xr-x 1 Admin 197121 1339787 Oct 12 06:53 target.pyz      # um arquivo, SEM leia-me

$ file target.pyz
Zip archive data, made by v2.0 UNIX, extract using at least v2.0, ... method=store

$ head -c 32 target.pyz | xxd
00000000: 2321 2f75 7372 2f62 696e 2f65 6e76 2070  #!/usr/bin/env p
00000010: 7974 686f 6e33 0a50 4b03 0414 0000 0000  ython3.PK.......

$ sha256sum target.pyz
72eaad9b95c6e9894a20709708f3c35e044bf9910782c353ef54292b4c9ab289
```

Seis membros, cada um de um tipo diferente (`evidence/20261014-402`):

| Membro | Tamanho | É |
|---|---|---|
| `__main__.py` | 13.821 | launcher em fonte Python **ofuscado** |
| `Y5zl4Kpf/burw392w` | 13.885 | o **loader** (fonte ofuscado, sem extensão) |
| `Y5zl4Kpf/f2mlPAeX.bin` | 26 | **manifest** (marshal de dict) |
| `Y5zl4Kpf/T2hRITch.bin` | 1.264.004 | **code object** marshalled do programa |
| `Y5zl4Kpf/srLX0FXx.so` | 47.352 | **runtime nativa** — ELF64 x86-64 |
| `Y5zl4Kpf/` | — | diretório |

Caso criado com `scripts/new-case.ps1` (intake + hash em `work/crackme-n4/evidence/20261014-intake-001.json`).

---

## 2. Passo 2 — Triagem: os cinco comandos do Cenário 0 recusaram o alvo (**F1**)

Saída real (`evidence/20261014-401`):

```console
$ node scripts/identify-protections.mjs work/crackme-n4/src/target.pyz   ; exit=2
work/crackme-n4/src/target.pyz: nem assinatura "MZ" (PE) nem "\x7fELF" — formato não reconhecido
$ node scripts/triage-static.mjs work/crackme-n4/src/target.pyz --refs --data-refs   ; exit=2
[!!] work/crackme-n4/src/target.pyz: nem assinatura "MZ" (PE) nem "\x7fELF" — formato não reconhecido
$ node scripts/diagnose-load.mjs work/crackme-n4/src/target.pyz          ; exit=2
work/crackme-n4/src/target.pyz: nem assinatura "MZ" (PE) nem "\x7fELF" — formato não reconhecido
$ python scripts/disasm-range.py work/crackme-n4/src/target.pyz 0x1000  ; exit=2
[!!] work/crackme-n4/src/target.pyz: nem assinatura "MZ" (PE) nem "\x7fELF" — formato não reconhecido
$ node scripts/pe-read.mjs work/crackme-n4/src/target.pyz --rva 0x1000   ; exit=2
[!!] work/crackme-n4/src/target.pyz: nem assinatura "MZ" (PE) nem "\x7fELF" — formato não reconhecido
```

Os cinco **recusam** — e desta vez por um motivo novo: o alvo não é imagem, é **container**.
Sem conserto nesta rodada a análise morria aqui (na prática andou com `unzip` na mão). Isto é **F1**
e foi corrigido: novo [`scripts/triage-archive.mjs`](../scripts/triage-archive.mjs) (§6).

Depois da correção, a triagem responde tudo de uma vez (`evidence/20261014-404`):

```console
$ node scripts/triage-archive.mjs work/crackme-n4/src/target.pyz
  1339787 bytes · zipapp (shebang + ZIP)
  preâmbulo (shebang): #!/usr/bin/env python3
  entradas: 6 · preâmbulo de 23 bytes antes do primeiro PK

  membros:
    Y5zl4Kpf/T2hRITch.bin            1264004 B  - store  marshal:code (code object — SEM cabeçalho de versão)
    Y5zl4Kpf/burw392w                  13885 B  - store  texto:Python
    Y5zl4Kpf/f2mlPAeX.bin                 26 B  - store  pickle/marshal:dict (manifest ({...}))
    Y5zl4Kpf/srLX0FXx.so               47352 B  - store  ELF (ELF64 x64)  abi=python3.13,PyInit_srLX0FXx
    __main__.py                        13821 B  - store  texto:Python

  o que isso decide:
    * marshal NAO tem cabecalho de versao: carregar com o interpretador errado nao da erro ...
    * membro nativo ELF: ... extensao do CPython compilada para Linux. O Windows nao carrega ELF
      como modulo (o erro e 193, ERROR_BAD_EXE_FORMAT); rodar exige Linux/WSL.
    * srLX0FXx.so: dica de ABI -> python3.13, PyInit_srLX0FXx
```

**Resposta à pergunta do Passo 2:** é **empacotado e protegido**, é **Linux**, e a lógica é
**anti-análise** (não-linear): o critério do Cenário 12 mandaria para emulação/debugger, mas o que
falta antes disso é **host**: o alvo depende de uma extensão ELF.

---

## 3. O mecanismo (o que o alvo faz, camada por camada)

Leitura 100% estática (nenhum debugger aberto): `work/crackme-n4/scripts/deob.py` (o mesmo
princípio do `__main__.py` do round anterior — literal por lambda → literal) e
`work/crackme-n4/scripts/payload-dis.py` (desmonta o payload marshalled, com travessia que
sobrevive a grafo com ciclo). Evidência `-405`.

```python
# __main__.py de-ofuscado (20 linhas — 62 literais resolvidos)
N56XCTRl['dir'] = tempfile.mkdtemp(prefix=base64.b85decode('...').decode())
with zipfile.ZipFile(os.path.abspath(sys.argv[0])) as ztXUJopk:
    ztXUJopk.extractall(N56XCTRl['dir'])
N56XCTRl['pay'] = os.path.join(N56XCTRl['dir'], 'Y5zl4Kpf')
N56XCTRl['env']['PYTHONPATH'] = N56XCTRl['pay'] + (os.pathsep + PUOyEq1z if PUOyEq1z else '')
...  # tratamento de Termux (LD_LIBRARY_PATH)
N56XCTRl['rc'] = subprocess.run([sys.executable,
    os.path.join(N56XCTRl['pay'], 'burw392w'), N56XCTRl['pay'], 'file', '__main__',
    os.path.join(N56XCTRl['pay'], 'f2mlPAeX.bin')], cwd=N56XCTRl['pay'], env=N56XCTRl['env']).returncode
raise SystemExit(N56XCTRl['rc'])
```

O `burw392w` (de-ofuscado, 41 linhas) é um **loader**: `marshal.loads` do manifest, um
`MetaPathFinder` que serve módulos a partir de arquivos marshal, e `exec` do code object do
`__main__` com `{'__name__': '__main__'}`.

O payload (`T2hRITch.bin`) é um code object de **Python 3.13** com **486 code objects** e 9.658
instruções só no topo. O que ele é, pela evidência:

- importa `hashlib` e `base64` e traz as constantes de **Curve25519/Ed25519** —
  `27742317777372353535851937790883648493` (ordem L do grupo), `-121665`, `121666` → checagem de
  chave/assinatura, não uma senha comparada a um literal;
- o topo está **aplanado**: um dispatcher com `qpiToeiN` comparado a rótulos grandes
  (`598421066810`, `596746089217`, …) e `JUMP_FORWARD`/`EXTENDED_ARG` de volta a `L118`;
- a **runtime** (`srLX0FXx.so`): ELF64 estático (só `libc.so.6`), exporta `PyInit_srLX0FXx` e
  importa `_PyInterpreterState_SetEvalFrameFunc`, `_PyEval_EvalFrameDefault`,
  `PyUnstable_InterpreterFrame_GetCode`, `PyRun_SimpleString`, `dladdr`/`dlsym` — ou seja, ela
  **troca o executor de frames** do CPython por um VM próprio. As assertivas do binário mostram a
  forma do VM: `vm->names`, `consts`, `eht`, `pending`, `mta`, `pn`, `kn`, `pos` (pilha de
  operandos, tabela de exceções, nomes, constantes).

**Onde ficou o gate:** não no Python visível. O payload importa a runtime e **recusa seguir sem
ela** (§5). As duas coisas que fecharam o diagnóstico, ambas medidas:

```console
# a versão importa MAIS que o formato: o MESMO arquivo marshal, três interpretadores
$ python 3.11  -> marshal.loads OK · dis: IndexError · exec: exit=139 (access violation, sem mensagem)
$ python 3.12  -> marshal.loads OK · dis: IndexError · exec: exit=139
$ python 3.13  -> marshal.loads OK · dis: 9658 instruções · exec: chega ao import da runtime

# e o alvo RODA com 3.13 — até a extensão:
$ python3.13 target.pyz
  File "<member>", line 132, in <module>
ImportError: DLL load failed while importing srLX0FXx: %1 não é um aplicativo Win32 válido.
```

---

## 4. Black-box: até onde foi possível ir

O contrato da rodada diz que executar de fato é preferível a emular. Tentado, na ordem
(`evidence/20261014-406`):

| Ambiente | Resultado |
|---|---|
| Python 3.11.15 (o `python` da máquina) | **exit 127**, nenhuma mensagem; o loader direto morre com **exit 139** (access violation) |
| Python 3.12.9 (o `py -3.12` da máquina) | idem: `dis` falha, `exec` estoura |
| Python **3.13.14** (instalado nesta rodada com `uv python install 3.13`, escopo do usuário, sem elevação) | **roda**: extrai, monta o `PYTHONPATH`, carrega o payload e morre no `import srLX0FXx` com `ImportError: DLL load failed ... %1 não é um aplicativo Win32 válido` (o erro 193) |
| runtime **stubada** (ambiente **modificado e declarado**: `work/crackme-n4/stub/srLX0FXx.py` no lugar do `.so`) | o payload recusa substituto: `ImportError: native runtime srLX0FXx not found; searched 9 sys.path entries` |

Ou seja: **não existe caminho só-Python** para este alvo — a runtime ELF é obrigatória, e o
Windows não carrega ELF como módulo (`%1 não é um aplicativo Win32 válido` = 193
`ERROR_BAD_EXE_FORMAT`, o mesmo tema do `0xC000007B` das rodadas 1–2, agora num import do CPython).

---

## 5. Limitação declarada (sem maquiagem)

- **O alvo não foi executado até a checagem.** O que existe é o alvo rodando até a extensão nativa
  e morrendo — não é "não carrega porque está quebrado", é "não carrega porque o host é o errado".
- **A senha/chave não foi obtida.** O caminho estático chegou ao code object desmontado, à
  identificação do esquema (Curve25519 + `hashlib`/`base64` + aplanamento + VM nativa) e à recusa
  explícita do payload a rodar sem a runtime. De-*aplanar* um topo de 9.658 instruções com 127
  rótulos de estado é o próximo trabalho, e é outro trabalho — não se resolve "com mais um comando".
- **Fechar isso exige Linux + CPython 3.13** (WSL com distro; `wsl --install -d Ubuntu` pede
  elevação e rede, e a regra 2 do projeto proíbe elevação por conta própria). O `.so` é ELF
  x86-64, então o mesmo 3.13 *dentro* do WSL com certeza carrega a extensão.
- **Ghidra, x64dbg, Unicorn e Qiling seguem não exercitados** — e aqui não é por não precisar:
  é por não haver o que eles resolvem melhor neste host (a barreira é de ambiente, não de análise).

---

## 6. Passo 3/4 — Fricção registrada em tempo real e corrigida AGORA

### F1 — Os cinco comandos do Cenário 0 recusavam **container** (a recusa vinha do round 8.3 já melhorada: "não é MZ nem ELF", e nem por isso útil)

**Momento:** §2. Em quatro rodadas o alvo mudou de PE → ELF → zipapp; o toolkit já tinha aprendido
ELF no round 8.3, mas "container" não é um formato de imagem: não há seção, não há RVA. A saída era
`unzip` na mão, e a informação que decidiu a rodada (a **dica de ABI** dentro do `.so`) não aparecia
em lugar nenhum.

**Feito agora:** [`scripts/triage-archive.mjs`](../scripts/triage-archive.mjs) — triagem de
container/empacotamento, sem dependência (Node puro):

- reconhece **ZIP** e **zipapp** pelo **diretório central** (não pela assinatura no byte 0 — o
  zipapp tem 23 bytes de shebang antes do primeiro `PK\x03\x04`), `.pyc` (magic + CRLF + flags) e
  payload **marshal** de code object;
- lista os membros com tamanho, método (store/deflate — descomprime membros deflate), CRC,
  entropia e **o formato de cada um** por assinatura: PE, ELF, ZIP aninhado, fonte Python, marshal,
  manifest;
- reporta a **dica de ABI** (`python3.13`, `PyInit_*`, `cp313-*`) achada dentro dos membros
  nativos — o dado que fixou a versão do interpretador nesta rodada;
- **avisa sobre o marshal**: sem cabeçalho de versão, carregar com o interpretador errado não dá
  erro, dá access violation (com o número medido);
- e quando o arquivo **não** é container, manda para o leitor certo (`triage-static.mjs`) em vez de
  recusar (exit 2).

Testado em quatro casos (evidência `-404`): o zipapp do alvo; um ZIP misto criado aqui com PE + ELF
+ manifest em **deflate**; um `.pyc` gerado pelo 3.13 (magic `0xdf3`); e um PE solto → exit 2 com o
redirecionamento.

### F2 — `marshal` sem cabeçalho de versão: o erro não é erro, é *access violation*

**Momento:** a primeira leitura do payload. `marshal.loads()` "funciona" nas três versões; o que
quebra é o `dis` (`IndexError: tuple index out of range`) e, ao **executar**, o processo morre com
**exit 139 sem uma linha de mensagem**. Num alvo que fosse analisado sem essa informação, a
conclusão errada ("o binário é anti-debug / está corrompido de propósito") seria natural — e a certa
é "é bytecode de outra versão".

**Feito agora:** o aviso está **na ferramenta** (F1) e no [docs/06-workflows.md](../docs/06-workflows.md),
com a tabela medida; e o script do caso
(`work/crackme-n4/scripts/payload-dis.py`) imprime a versão do interpretador que carregou e diz
explicitamente quando o `dis` falha por isso, em vez de engolir a exceção. A dica de ABI é o que
resolve o impasse — sem ela você não sabe **qual** interpretador tentar.

### F3 — Um `.so` **dentro** de um pacote Python: o leitor certo é o de ELF (e o veredito é de plataforma)

**Momento:** o membro `srLX0FXx.so` precisava de duas respostas: "o que é" e "de qual
interpretador". O toolkit já responde a primeira desde o round 8.3 (`identify-protections`,
`triage-static`) — e a segunda **não existia**: foi preciso `grep` de strings no `.so` para achar
`/usr/local/include/python3.13/object.h`.

**Feito agora:** a dica de ABI virou recurso do F1, e a nota de plataforma é explícita ("o Windows
não carrega ELF como módulo — erro 193; rodar exige Linux/WSL"). Regressão: os dois leitores de
imagem continuam respondendo sobre ELF sem alteração (medido no `.so`: 3.520 bytes de `.text`
listados, 36 símbolos indefinidos com `PyInit_srLX0FXx` entre eles).

### F4 — O harness de execução (`diagnose-load.mjs`) é para **imagem** — e isso está certo (lacuna declarada, não fabricada)

**Momento:** rodar o alvo com entrada e capturar a saída é o gesto que o `diagnose-load.mjs` faz
para PE/ELF (`--stdin`). Num zipapp ele não se aplica por desenho: quem executa é `python <arquivo>`,
e o "loader" é o interpretador.

**Não corrigido aqui, declarado:** estender o harness para alvos Python (escolher o interpretador,
alimentar stdin, capturar exit code e output) é trabalho real e **não** foi feito nesta rodada — o
que fiz foi o ajuste mínimo: `triage-archive.mjs` manda o analista para o comando certo
(`python <arquivo>`, com a dica de ABI dizendo qual `python`), e o relatório registra a lacuna em
vez de escondê-la atrás de "o alvo não roda". Fica como o próximo passo natural do toolkit.

---

## 7. O que mudou no toolkit nesta rodada

| Arquivo | Mudança | Fricção |
|---|---|---|
| `scripts/triage-archive.mjs` | **novo** — triagem de container (ZIP/zipapp pelo diretório central, `.pyc`, marshal), formato de cada membro por assinatura, entropia/CRC, **dica de ABI** e o aviso do marshal; redireciona para `triage-static` quando não é container | F1, F2, F3 |
| `docs/02-catalogo-ferramentas.md` | **novo d.10** "Python empacotado (zipapp · `.pyc` · marshal)" — o que faz / quando usar / como usar / integração / por quê, com a medição da versão | F1 |
| `docs/06-workflows.md` | subseção **"Alvo que não é imagem (container, `.pyc`, marshal)"** no Cenário 0, com o comando novo e o aviso do marshal | F1, F2 |
| `README.md` · `scripts/README.md` | `triage-archive.mjs` no mapa de scripts | F1 |
| `reports/round-8-4-nivel-4.md` | este relatório | — |

Regressão e consistência, re-rodadas depois de todas as edições:

```console
$ node scripts/check-consistency.mjs
  núcleo: 4 · catálogo: 31 · perfis: 13 · flags MCP: 9
  licenças com linha verificada: 28/31 do bootstrap · registradas: 79
  [OK] nenhuma divergência encontrada (197 verificações).                 ; exit=0
```

Os alvos das rodadas anteriores continuam passando pelos mesmos caminhos (o ZIP misto de teste
leva um PE do round 8.2 como membro deflate e o `triage-archive` o reconhece como PE sem tocar no
`triage-static`).

---

## 8. O que NÃO funcionou, e o que continua em aberto (sem maquiagem)

- **A senha/chave não foi obtida** (§5). Este round entrega o **diagnóstico completo do
  empacotamento/proteção** e o caminho estático até o bytecode do programa — não a resposta do gate.
- **O programa está aplanado e a runtime é uma VM nativa**: de-*aplanar* (ou reimplementar o
  dispatch) é o próximo trabalho; ele é grande e não foi tentado pela metade.
- **A extensão `.so` é ELF e é obrigatória**: sem Linux (WSL com distro) + CPython 3.13 não há
  black-box. Instalar distro exige elevação — o projeto proíbe que eu eleve por conta própria.
- **`diagnose-load.mjs` não roda alvo Python** (F4): declarado, não corrigido; o caminho correto
  hoje é `python <arquivo>` com o interpretador da dica de ABI.
- **O instalador de 3.13 mudou o host**: `uv python install 3.13` baixou o CPython 3.13.14 para
  `%APPDATA%\uv\python` (escopo do usuário, sem elevação, reversível com `uv python uninstall 3.13`).
  Fica registrado porque análise que muda o ambiente tem que dizer que mudou.
- **Uma cópia de trabalho do alvo foi modificada e restaurada** no experimento do stub (F3): o
  `srLX0FXx.so` e o `src/target.pyz` foram conferidos por hash depois (evidência `-406`).
- **`nivel 5` e `nivel 6.5` não foram tocados**, por escopo.

---

## 9. Reprodução (na ordem)

```powershell
# 1) inventário + congelamento
ls "C:/Users/Admin/Desktop/Alvos/nivel 4"
node scripts/triage-archive.mjs "C:/Users/Admin/Desktop/Alvos/nivel 4/target.pyz"   # zipapp + membros + ABI
powershell -File scripts/new-case.ps1 -Name crackme-n4 -Target "…\nivel 4\target.pyz" …
sha256sum work/crackme-n4/src/target.pyz     # 72eaad9b95c6e9894a20709708f3c35e044bf9910782c353ef54292b4c9ab289

# 2) desempacotamento e leitura da camada de empacotamento (script DO CASO)
cd work/crackme-n4 && unzip -o src/target.pyz -d unpacked
python scripts/deob.py unpacked/__main__.py --stats -o unpacked/__main__.deob.py    # 62 literais
python scripts/deob.py unpacked/Y5zl4Kpf/burw392w --stats -o unpacked/payload.deob.py  # 55 literais

# 3) o integrador tem a versao? (dica de ABI: python3.13)
uv python install 3.13
PY313="%APPDATA%\uv\python\cpython-3.13.14-windows-x86_64-none\python.exe"
"$PY313" -c "import marshal; print(marshal.loads(open(r'unpacked/Y5zl4Kpf/f2mlPAeX.bin','rb').read()))"

# 4) black-box (executar de fato) — morre na extensao ELF, e isso e o resultado
"$PY313" src/target.pyz          # ImportError: DLL load failed ... erro 193

# 5) desmontar o payload (script DO CASO) e ler as constantes
"$PY313" scripts/payload-dis.py unpacked/Y5zl4Kpf/T2hRITch.bin --out unpacked/payload.dis.txt

# 6) o .so pelos leitores de imagem do toolkit
node scripts/triage-static.mjs unpacked/Y5zl4Kpf/srLX0FXx.so --refs
node scripts/identify-protections.mjs unpacked/Y5zl4Kpf/srLX0FXx.so

# 7) consistência (depois de qualquer edição de script/doc)
node scripts/check-consistency.mjs
```

Artefatos brutos do caso (locais, fora do Git por regra): `work/crackme-n4/evidence/20261014-401…406`.
Material do alvo e scripts do caso ficam em `work/` e **não** são publicados.

---

## 10. CI

Commit desta rodada: `1c6109c`. Run
[38624848912](https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38624848912) — **verde**,
4/4 jobs (medido com `gh run watch --exit-status`, exit 0):

```console
✓ Documentação e estrutura in 16s
✓ Scan de segredos e binários in 7s
✓ Licenças contra a fonte primária in 31s
✓ Ponte MCP do REA sobe e responde in 17s
```

`verify-licenses.mjs` local, re-rodado depois das edições: `[OK] 79 licenças declaradas batem com
a fonte primária` (exit 0) — nenhuma ferramenta de terceiros entrou nesta rodada (o script novo é
Node puro, sem dependência).

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

```bash
# 3) Triagem ESTÁTICA — nenhum destes abre GUI, debugger ou Ghidra
cd ../..   # raiz do toolkit
node scripts/triage-archive.mjs work/acme-app-2.1/unpacked/acme.work.pkg        # é CONTAINER (zip/pyz/whl)? o que tem dentro?
node scripts/identify-protections.mjs work/acme-app-2.1/unpacked/acme.work.exe   # está empacotado? com o quê?
node scripts/triage-static.mjs work/acme-app-2.1/unpacked/acme.work.exe --refs   # o que ele é: TLS, imports, strings e onde são usadas
node scripts/diagnose-load.mjs work/acme-app-2.1/unpacked/acme.work.exe          # ele carrega? (0xC000007B)
python scripts/disasm-range.py work/acme-app-2.1/unpacked/acme.work.exe 0x1520 --fim 0x15b4 --strings   # ~100 bytes de código
node scripts/pe-read.mjs work/acme-app-2.1/unpacked/acme.work.exe --rva 0x4000 --len 16               # e o que TEM nesse endereço?
node scripts/triage-static.mjs work/acme-app-2.1/unpacked/acme.work.exe --data-refs                  # que CONSTANTES o código lê?
```

`--data-refs` responde a pergunta que vem antes de ler o código linha a linha: a checagem
compara com o quê? Ele lista os alvos de dados (que não são string) referenciados pelo código,
com o tipo heurístico de cada um — `máscara` (só `00`/`ff`, o `movdqa` típico), `inteiro
pequeno` (semente/contador em `.data`), `ponteiro/tabela` (a do CRT, ruído) — e os bytes de
cada alvo. Medido no round 8.2: as duas máscaras do pipeline SSE e a semente `0x1337`
apareceram **sem** ler o disassembly à mão.

O último comando fecha o ciclo que o `disasm-range.py` abre: ele termina as linhas com
`; -> rva 0x4000` ou `"texto"`, e `pe-read.mjs` mostra **o conteúdo** daquele RVA (hexdump +
leitura tipada: a semente `u32` que o `imul` multiplica, a máscara de 16 bytes que o
`movdqa` carrega, os 8 bytes que o `movabs` compara). Sem ele o caminho era escrever um
parser de PE na hora — foi o que aconteceu nas rodadas 8.1 e 8.2, com bug próprio na
primeira vez. Confirmação black-box da resposta, quando o alvo é de console:
`node scripts/diagnose-load.mjs <alvo> --stdin '<candidata>'`.

### Alvo Linux (ELF) na triagem

Os cinco comandos acima leem **PE e ELF** desde a rodada 8.3 (o alvo Linux recusava em todos
eles com a mesma mensagem, "sem assinatura MZ"). O que muda no ELF:

- o endereço que aparece na saída é o **vaddr de link** (absoluto, como no readelf/objdump),
  não um RVA — é ele que você passa para `--rva`/`--section`/`--fim`;
- o "código que roda antes do main" é `DT_INIT`/`DT_INIT_ARRAY` (o equivalente do TLS
  callback do PE) e os imports são `DT_NEEDED` + os símbolos **indefinidos** do `.dynsym`;
- **executar** o alvo no Windows não é possível: o loader aceita só PE e o erro dele é 193
  (`ERROR_BAD_EXE_FORMAT`), **não** `0xC000007B` — `diagnose-load` diz isso e mostra o status
  real. Sem distro instalada (`wsl -l -v` vazio), o caminho é estático (triagem + `disasm-range`
  + `pe-read`) e, para o que for não-linear, emulação (item 7 do Cenário 12).
- **com distro, execute — é o que separa "emulação concordando" de black-box.** Copie o alvo
  para dentro da VM (o `src/` do caso nunca é executado no lugar) e rode com a candidata:

```bash
$ wsl -d Ubuntu -u root -- bash -lc 'cp /mnt/c/…/work/<alvo>/src/<alvo> /tmp/x && chmod +x /tmp/x && printf "%s\n" "$SENHA" | /tmp/x; echo "exit=$?"'
```

  Antes disso, meça o que o alvo faz **antes** da validação: anticheat/anti-debug que decide
  caminho por `ptrace` (o `ptrace(PTRACE_TRACEME)` responde 0 num Linux normal e o alvo escolhe
  a semente "sem debugger") muda a resposta esperada. Medido no round 8.3: `ACCESS GRANTED` com
  o `ptrace` disponível e controles recusando. Duas ressalvas declaradas: **WSL1 não é um Linux
  completo** (kernel `4.4.0-*` emulado — sem namespaces/eBPF/perf, e anti-debug fino pode
  divergir), e se o firmware não expõe VT-x o WSL2 não sobe (`HCS_E_HYPERV_NOT_INSTALLED`).

### Alvo que não é imagem (container, `.pyc`, marshal)

Os cinco comandos acima leem **formatos de imagem**. Se o alvo for um **container** — zipapp,
`.whl`, `.jar`, `.nupkg` —, quem responde primeiro é
`node scripts/triage-archive.mjs <alvo>`: ele reconhece ZIP e zipapp (preâmbulo de shebang), `.pyc`
e payload **marshal** de code object, lista os membros com o **formato de cada um** por assinatura
e traz a **dica de ABI** (`python3.13`, `PyInit_*`) do interior dos membros nativos.

Essa dica é o que decide a rodada quando o programa vem em **marshal**: marshal não tem cabeçalho de
versão, então `marshal.loads()` com o interpretador errado **não dá erro** — devolve code object
corrompido e o processo morre com *access violation*. Medido no round 8.4 (o mesmo payload: 3.11 e
3.12 → exit 139 sem mensagem; 3.13 → desmonta). Escolha o interpretador pela dica **antes** de tentar
carregar. Os membros ELF/PE que saírem do container entram direto nos leitores de imagem
(`triage-static`, `disasm-range`, `pe-read`); um membro ELF de extensão do CPython, porém, **não
carrega no Windows** (erro 193) — rodar exige Linux/WSL.

### Alvo Python que RODA: instrumente o interpretador, não o binário

Quando o alvo é um zipapp/programa Python e a leitura não fecha — topo aplanado, strings
construídas em runtime, extensão nativa que importa `_PyInterpreterState_SetEvalFrameFunc`
(isto é: troca o avaliador de frames do CPython) —, o caminho curto **não** é Ghidra nem
debugger nativo: é fazer o próprio CPython contar o que o alvo faz. Quem entrega o arquivo é o
import automático de `sitecustomize` a partir do `PYTHONPATH` (e os launchers de zipapp
costumam **repassar** o `PYTHONPATH` ao processo filho):

```bash
$ PYTHONPATH=$DEST/instr python3.13 alvo.pyz      # com $DEST/instr/sitecustomize.py
```

Quatro ganchos, em objetos **compartilhados** (o alvo faz `__import__('hashlib')` e recebe a
versão já instrumentada, sem você reimplementar o loader dele):

| Gancho | O que ele responde | Medido no round 8.4 |
|---|---|---|
| `hashlib`/`base64` + **dump** dos buffers >64 KiB | o que entra e o que sai de cada hash | `sha512` sobre 1.264.068 B (o buffer é cabeçalho de 64 B + o payload; o loader troca uma constante b85 por 80 zeros **antes** de hashear) |
| pilha de quem chama `input()` | a pergunta é feita pelo alvo em Python ou por código nativo? | `<member>:132` → o payload, não o `.so` |
| devolver a entrada como **subclasse de `str`** que registra `__eq__`/`encode`/… | o **valor esperado**, sem desofuscar nada | `__eq__('! ! ! ! ! ! ! !  TREE')` → senha, e a flag `CMO{builtins}` |
| `print` com pilha | onde o "invalid/denied" é emitido | `print('invalid')` logo após a comparação |

A subclasse de `str` é o detalhe que faz a diferença: por ser subclasse, ela tem **prioridade no
`__eq__` refletido** — a comparação é capturada nas duas direções (`senha == X` e `X == senha`).

Por que grep **não** acha essas strings: elas são montadas em runtime a partir de listas de
inteiros do próprio marshal, na forma
`''.join(chr((B[i] - c ^ A[i % len(A)]) & 255) …)`. Dá para decodificar estaticamente (e há
validação barata: a tripla `([211,222,232,189], [189,173,148,229], 7)` tem de dar `exec`), mas a
varredura por tentativa gera ruído demais — medido: 169.548 "decodificações printáveis" numa
única passada. **Instrumentar em runtime é o método; a decodificação estática é conferência.**

Limite declarado: isso só vê o que passa pelo nível Python. Checagem fechada dentro de código
nativo não aparece aqui — para ela, o caminho é debugger/emulação (Cenário 12). E este harness
ainda **não é ferramenta do toolkit**: vive como script do caso (`work/<alvo>/scripts/`), que não
vai para o Git por regra.

### Alvo que calcula rápido demais para observar (park + patch + leitura)

Alguns alvos fazem o trabalho **depois** do input e terminam em menos de 1 ms — medido nesta série:
`NtSuspendProcess` devolve `0xC000010A` (`STATUS_PROCESS_IS_TERMINATING`) até com atraso 0. Para
esses, o caminho que funciona é instrumentar **antes** de alimentar a entrada:

```powershell
# 1) parkeia no prompt, patcha em MEMÓRIA (nunca no arquivo), alimenta e congela para ler depois
powershell -File scripts/park-patch-run.ps1 -Target work/acme/src/acme.exe -Entrada 'ABC' `
    -HookPos '0x4695' -FreezeIat 'exit=0x46644'
# 2) o que o alvo prepara a partir da entrada (função de trim/decodificação antes do cálculo)
powershell -File scripts/park-patch-run.ps1 -Target work/acme/src/acme.exe -Entrada 'ABC' `
    -HookCall '0x4659=0x1000' -SeguirRetorno -FreezeIat 'exit=0x46644'
# 3) stub próprio: grava rsp (para ler o frame da função) ou vários registradores
powershell -File scripts/park-patch-run.ps1 -Target work/acme/src/acme.exe -Entrada 'ABC' `
    -HookStub '0x8333=49BB{scratch}498923{orig}C3' -FreezeIat 'exit=0x46644'
```

As cinco armadilhas medidas (estão no cabeçalho do script e no relatório da rodada 8.5):
`call stub` tem de reconstruir **`rsp` do call** (não só o alinhamento de 16 — se a função recebe 5º
argumento na pilha, `rsp` errado = `0xC0000005`); store absoluto de 64 bits só via `movabs` (use
`r11` quando o retorno usa `rax`/`rdx`); stub montado à mão erra encoding — **valide com
`python scripts/disasm-range.py`** numa cópia do alvo; cada modo de hook precisa de área própria; e
**rejeição pode ser transporte, não senha** (entrada binária que a função de preparação zera vira
digest de entrada vazia — instrumente o call de preparação antes de concluir que a senha está
errada).

**Por quê antes de qualquer ferramenta pesada:** a resposta que decide o resto do
plano é "este binário está empacotado/protegido ou é só lógica?". Se **não** houver
proteção de carregamento, não existe dump, OEP nem IAT a reconstruir — o Cenário 1
inteiro (e o debugger) é desnecessário, e o alvo se resolve lendo o código. Se houver,
é o Cenário 1 com breakpoint de hardware. As três ferramentas acima se dividem o
trabalho: assinatura de packer (`identify-protections`), estrutura e o que o programa
*imprime* (`triage-static`) e a decisão do loader (`diagnose-load`). Medido no round
8.1: um alvo de 13 KB **sem** proteção de carga foi resolvido por esse caminho, com o
debugger aberto **zero** vezes — e sem Ghidra, porque `disasm-range.py` lê o trecho
que importa. Isso não é atalho: é a triagem dizendo o que o alvo pede.

---

## Cenário 1 — PE x64 protegido por packer simples (UPX)

**Objetivo:** recuperar o binário desempacotado (OEP + dump + IAT).

```powershell
PS> upx -t .\acme.exe                 # confirma UPX e a variante
PS> upx -d .\acme.exe -o .\unpacked\acme.unpacked.exe
```

Se não for UPX puro (stub modificado), vá pelo debugger. **A regra que decide a qualidade do
dump está no passo 4** — leia o quadro logo abaixo antes de armar qualquer breakpoint:

```
1. Abra no x64dbg:  LoadBinary work/acme-app-2.1/src/acme.exe
2. Vá até o entry point:  RunToAddress <EP>   → depois StepOver até o salto final
3. Use DetectOEP  → o plugin devolve o OEP real
4. Pare no OEP com breakpoint de HARDWARE:  SetHardwareBreakpoint <OEP>
   → run → pausa no código original
5. Confira os MÓDULOS no ponto de parada:  ListModules
   (quem carrega as DLLs do alvo é o stub: medido no caso iat-hardcase, no EP a lista tinha 4
   módulos e a reconstrução saiu com 126 slots resolvidos em 53 blocos; no ponto de parada são
   18 módulos, 315 slots em 70 blocos — a lista curta dá uma tabela de imports errada)
6. DumpModule (dump completo com IAT)  ou  DumpMemory na região
7. AnalyzeModule no dump → reconstrói imports
8. Salve em unpacked/ e registre o comando em evidence/
```

**Breakpoint: hardware por padrão enquanto a seção pode mudar.** Um breakpoint de
**software** grava `int3` (`0xCC`) **na memória** do alvo; se o stub do packer ainda vai
decriptar/escrever naquela seção, o debugger guarda o byte que estava lá *naquele momento*
(o cifrado) e, ao parar, "restaura" o byte **pré-decriptação** — o dump sai com **uma
instrução trocada**, o loader aceita o arquivo e o programa morre depois, dentro do CRT.
O breakpoint de **hardware** (`SetHardwareBreakpoint`, DR0-DR3) não escreve nada na memória,
então não há o que restaurar errado: é o caminho padrão do passo 4 e de qualquer parada em
código que o packer ainda pode reescrever.

| | Quando usar | Custo/limite real (medido) |
|---|---|---|
| **Hardware** (`SetHardwareBreakpoint`) | **padrão** para parar em código que o stub ainda pode escrever (o OEP típico) | DR0-DR3 = **4** por thread. O 5º **não** arma: o x64dbg responde `Hardware breakpoint set.` e descarta o endereço em silêncio — por isso `x64dbg-drive.mjs --hw-break` confere o `ListBreakpoints` e **falha (exit 1)** se o endereço não entrou |
| **Software** (`SetBreakpoint`) | só **depois** que a seção está no estado final (ex.: parar dentro do código já decifrado) | sem limite de quantidade; deixa `0xCC` na memória |
| `RunToAddress` (`--run-to`) | ir a um ponto cujo código já está no estado final | é um breakpoint **temporário de software** por baixo — vale a mesma restrição; entra no log como `sw-temp` |

**Sessão limpa não é o que parece.** O x64dbg persiste breakpoints **por módulo** em
`x64dbg/release/x64/db/<módulo>.dd64`, e eles **voltam armados na carga seguinte** (os de
software *e* os de hardware: medido — depois de reiniciar o x64dbg, a lista continuava com os
4 anteriores). Um breakpoint de uma rodada anterior pode, portanto, contaminar a captura de
hoje. A receita de captura confiável, medida:

```powershell
# 1. feche o debugger
.\scripts\start-x64dbg.ps1 -Stop
# 2. apague o banco do MÓDULO-alvo (não o dos módulos de sistema)
Remove-Item .\x64dbg\release\x64\db\acme.exe.dd64, .\x64dbg\release\x64\db\acme.exe.dd64.cmdline
# 3. reabra e confirme ANTES de capturar: tem de dizer "No breakpoints set."
.\scripts\start-x64dbg.ps1
node scripts/x64dbg-drive.mjs --list-breaks
```

A mesma captura pela ponte MCP (o `--bp-log` é o que o passo 12 consome; sem ele, o modo sem
original não sabe onde procurar):

```bash
node scripts/x64dbg-drive.mjs --load work/acme/src/acme.exe \
     --run-to "<EP>" --modules --state \
     --hw-break "<OEP>" --bp-log evidence/bps.jsonl \
     --modules --dump-module acme unpacked/acme-dump.exe
#                             ^ o 1º --modules é no EP (lista curta, só para ter o mapa);
#                               o 2º é no ponto de parada — é ESSA lista que o rebuild-iat quer
```

**Ordem obrigatória:** OEP → dump → **reparo de IAT** → **estado de carga**. Dump sem IAT
reparada abre no Ghidra com imports lixo e a análise estática vira ruído.

Um dump **de memória** (passo 6) carrega o estado da execução que o gerou, e o loader do
Windows exige imagem em estado de carga **limpo** — por isso o arquivo pode ser recusado
antes de qualquer código rodar (`0xC000007B` e afins). Não é o fim e nem sempre é a IAT:

```
9. O Windows recusou o dump reconstruído? Meça o motivo em vez de adivinhar:
     node scripts/diagnose-load.mjs unpacked/acme-unpacked.exe
10. Se o diagnóstico acusar estado de carga (o `__security_cookie` já randomizado pela
   execução anterior), reponha o sentinela — o script escreve no endereço que o próprio
   LOAD_CONFIG do alvo declara:
     node scripts/reset-load-state.mjs --dump unpacked/acme-unpacked.exe        # dry-run
     node scripts/reset-load-state.mjs --dump unpacked/acme-unpacked.exe \
          --out unpacked/acme-unpacked-loadstate.exe
11. Tem o original EM CLARO (a mesma build obtida por outro caminho)? Então compare — é o
    teste mais forte que existe e o único que denuncia byte escrito por engano no dump:
      node scripts/verify-dump.mjs --dump unpacked/acme-unpacked.exe --original acme.exe
    Ele reloca o original para a base do dump e classifica CADA byte diferente: IAT (o
    loader preenche), LOAD_CONFIG/TLS, estado de carga (cookie) — e o que sobra vai para
    `CODIGO` (seção executável) ou `dados`. `CODIGO` é defeito: instrução que o original não
    tem, com o endereço exato para investigar. Além de achar o problema, ele também
    confirma o que **não** é problema: `.text` idêntico ao original é a prova de que o
    unpack saiu limpo.
12. NÃO tem original (crackme, alvo comercial: é a regra no round 8 em diante)? Então o
    passo 11 é impossível e o veredito passa a ser MODO FRACO. Passe o que foi carregado no
    debugger e o log de breakpoints da captura:
      node scripts/verify-dump.mjs --dump unpacked/acme-unpacked.exe \
           --packed src/acme.exe --bp-log evidence/bps.jsonl
    Três marcas, e o que cada uma vale: (1) resíduo de `0xCC` em seção executável —
    **indício**, o padding do MSVC também é `0xCC`; vira **forte** se o endereço está no log
    da captura; (2) **byte parado no tempo** — nos endereços do log, o byte do dump ainda é
    o do arquivo EMPACOTADO com a seção reescrita: é o defeito desta rodada, exatamente;
    (3) faixa de 8+ bytes ainda cifrada dentro de uma seção reescrita. Ele **não vê** byte
    trocado por valor plausível em endereço sem breakpoint — **este modo não prova que o
    dump está limpo**, só pega as marcas conhecidas. `--original` continua sendo o teste
    forte; este é o substituto quando não existe.
```

O mecanismo (qual checagem do `ntdll` reprova, com registrador e valor medidos) está em
[../reports/root-cause-0xc000007b.md](../reports/root-cause-0xc000007b.md) §8 — leia antes
de procurar defeito na IAT que você acabou de reconstruir.

**Armadilha medida — e tratada por padrão (custou uma rodada inteira do caso iat-hardcase).**
O defeito era um breakpoint de **software** em `.text` **antes** de o stub decriptar a seção:
o debugger gravou o `int3` no byte, o stub decriptou por cima e, ao parar, o debugger
"restaurou" o byte *pré-decriptação* — o dump saiu com **uma instrução trocada** (`0x48` →
`0x51`, medido em RVA `0x1f98`), o loader **aceitou** o arquivo e o programa morreu depois,
dentro do CRT. O que mudou para não repetir:

* o passo 4 passou a ser **breakpoint de hardware por padrão** (não escreve na memória, logo
  não tem byte a restaurar errado) — e a limitação real (4 slots DR0-DR3, o 5º descartado em
  silêncio) está no quadro acima, conferida pelo próprio driver, não só documentada;
* a captura passou a **gravar o log dos breakpoints** (`--bp-log`), que é o que dá dentes ao
  passo 12 quando não existe original;
* o passo 12 **detecta** o bug sem original em claro: nos endereços do log, byte igual ao
  arquivo empacotado dentro de uma seção reescrita = byte parado no tempo;
* e a persistência do banco `.dd64` (breakpoint de rodada anterior voltando armado) virou
  parte do procedimento, com a checagem `--list-breaks` antes de capturar.

Provas de 2026-10-14 (comando + saída): reprodução do bug com breakpoint de software, a mesma
captura com hardware saindo correta sem patch manual, e o modo fraco pegando o mesmo byte —
em [../reports/verification-2026-10-14.md](../reports/verification-2026-10-14.md) §9.

**Critério de pronto:** o dump abre no Ghidra, tem `GetProcAddress`/imports plausíveis,
uma das strings originais aparece em `strings`/`GetStrings` e — quando ele veio de memória,
passos 6–12 — o **loader do Windows o aceita** e o alvo **roda até o fim como o original**
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
6. Checagem LINEAR (XOR/shift/máscara byte a byte)? NÃO precisa de emulador nem debugger:
   leia as constantes (disasm-range.py + pe-read.mjs + triage-static --data-refs) e monte o
   sistema em Python — cada byte de saída é "XOR de um subconjunto dos bytes digitados" ^
   constante, e isso se resolve por eliminação sobre GF(2). Confirme com o alvo
   (diagnose-load.mjs --stdin). Caso medido: crackme-n2 (round 8.2) — 14 bytes, semente em
   .data, duas máscaras vectorizadas, senha e flag obtidas sem abrir GUI.
7. NÃO linear (hash, S-box, laço que lê memória)? Aí o caminho é emulação (Unicorn/Qiling)
   ou o debugger — e o registro que importa é o do valor que o alvo calcula, não o número
   de tentativas. **Antes de instalar emulador, veja se o não-linear está isolado**: se o
   alvo tem um interpretador próprio (VM de bytecode, laço de máquina de pilha) e o
   conjunto de operações dele é pequeno, transcrever os handlers dá um emulador de ~100
   linhas que roda offline, com controle negativo. Caso medido: crackme-n3 (round 8.3) —
   ELF64 com a senha cifrada em `.rodata` e um interpretador de 22 opcodes; os handlers
   saíram do disassembly e o oráculo em Python resolveu. O que **não** se dispensa nesse
   caminho: o modelo independente (forma fechada do bytecode) conferindo o mesmo resultado,
   e o controle negativo recusando entrada errada.
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

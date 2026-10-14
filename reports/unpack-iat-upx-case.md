# Caso controlado — unpack + tabela de imports (UPX) e o fluxo de ponta a ponta

**Data:** 2026-10-13
**Máquina:** Windows 11 (build 26200), Git Bash, PowerShell 5.1, Node 24.18, Ghidra 12.1.4, UPX 5.2.1
**Objetivo:** fechar a lacuna "o toolkit só diz *está protegido*" — provar que a peça seguinte
existe: **sair do binário empacotado para um binário analisável, com a tabela de imports
restaurada**, e documentar isso como uma única tarefa de ponta a ponta, do jeito que um usuário
real usaria.

Todo comando abaixo foi executado nesta máquina; cada afirmação tem saída ao lado. O que
**não** ficou coberto está em §5.

---

## 1. O alvo e o caso (Cenário 0 do fluxo canônico)

Alvo controlado: `work/packer-demo/clean.exe` — um PE x64 de 360 KB que **roda** (exit 0).
Empacotei com a versão oficial do UPX para ter um caso 100% reproduzível em duas linhas:

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/new-case.ps1 \
  -Name "iats-upx" -Target "work/packer-demo/clean.exe" \
  -Origin "binario de controle compilado no proprio toolkit" \
  -Purpose "provar unpack + IAT num caso controlado"
# cria work/iats-upx/{src,unpacked,notes,scripts,captures,evidence} + intake com hash

/tmp/unboxre-upx/upx-5.2.1-win64/upx.exe -9 --force \
  work/iats-upx/src/clean.exe -o work/iats-upx/src/clean.packed.exe
#     360448 ->    211456   58.66%    win64/pe     clean.packed.exe
# Packed 1 file.
```

> `--force` é necessário: o UPX recusa empacotar um PE com `GUARD_CF`
> (`CantPackException: GUARD_CF enabled PE files are not supported`). O alvo tem CFG, então o
> output tem o CFG desligado — é a razão de o desempacotado **não** voltar idêntico byte a byte
> ao original (hash `a72a74e5…` vs `468ffe12…`), mas ele restaura um binário **funcional**, que é
> o critério que importa aqui.

## 2. Triagem: o toolkit diz o que é, antes de mexer

```bash
node scripts/identify-protections.mjs work/iats-upx/src/clean.packed.exe
#   [!!] UPX (high) — seções UPX0/UPX1 ou marcador UPX! — packer UPX
#   [? ] Entry point fora de .text (medium) — entrypoint cai em "UPX1"
#   [? ] Seção de código gravável (medium) — "UPX1" é W+X
#   Veredito: PROVAVELMENTE PROTEGIDO
```

E o diagnóstico de carga, que já sabe separar "empacotado" de "não carrega":

```bash
node scripts/diagnose-load.mjs work/iats-upx/src/clean.packed.exe
#   [? ] secoes-esvaziadas — UPX0 (VirtualSize > 0, SizeOfRawData = 0)
#   [? ] dir-em-secao-vazia — exception e delayimport apontam para UPX0
#   [i ] reloc-ok — 9 entradas, todas em seções com dados
#   [!!] run — exit=null (EFTYPE)
```

**Achado honesto, e ele morde:** o output do UPX **não carrega nesta máquina** —
`O executável especificado não é um aplicativo válido para esta plataforma de SO`
(mesma família do `0xC000007B` de [root-cause-0xc000007b.md](root-cause-0xc000007b.md)).
Testei se a causa eram os data directories apontando para `UPX0`: zerei `exception` e
`delayimport` no arquivo do UPX e **continuei sem carregar** (`packed.noexc`, `packed.nodelay`,
`packed.noexc_nodelay` → todos "não é um aplicativo válido"). Ou seja: **esses dois achados do
script são sinal, não veredito** — por isso eles aparecem como `[? ]` (médio), não `[!!]`. O
segundo achado (o `run`) é o que vale.

## 3. Unpack e prova de que a tabela de imports voltou

```bash
/tmp/unboxre-upx/upx-5.2.1-win64/upx.exe -d \
  work/iats-upx/src/clean.packed.exe -o work/iats-upx/unpacked/clean.unpacked.exe
#     360448 <-    211456   58.66%    win64/pe     clean.unpacked.exe
# Unpacked 1 file.
```

O critério de pronto do `docs/06-workflows.md` (Cenário 1) é "o dump abre com imports
plausíveis". Medido nos três arquivos:

| Arquivo | bytes | seções | DLLs na IAT | thunks de import | roda? |
|---|---|---|---|---|---|
| `clean.exe` (original) | 360448 | 8 | **50** | **315** | exit 0 |
| `clean.packed.exe` (UPX) | 211456 | 3 | 51 (stub) | **54** (só o stub) | **não carrega** |
| `clean.unpacked.exe` (`upx -d`) | 360448 | 8 | **50** | **315** | **exit 0** |

E a prova de conteúdo: uma string do original que o empacotamento comprimiu volta a aparecer
só depois do unpack.

```text
clean.exe              contem "fothk"
clean.packed.exe       SEM "fothk"      ← comprimido
clean.unpacked.exe     contem "fothk"   ← restaurado
```

## 4. Ponta a ponta: o binário restaurado vira análise

Esta é a tarefa única, do começo ao fim: **"aqui está um .exe empacotado — me diga o que ele
faz"** — sem trocar de contexto nem de ferramenta.

**Passo 0 — triagem** (acima): `identify-protections` → UPX, `diagnose-load` → não carrega.

**Passo 1 — unpack**: `upx -d` → `unpacked/clean.unpacked.exe`, 50 DLLs / 315 thunks restaurados.

**Passo 2 — o artefato está mesmo analisável**: Ghidra headless importa e analisa.

```bash
mkdir -p work/iats-upx/ghidra-proj   # o projeto precisa existir
./ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat \
  work/iats-upx/ghidra-proj iats-upx \
  -import work/iats-upx/unpacked/clean.unpacked.exe -deleteProject
#   Total Time   167 secs
# INFO  REPORT: Analysis succeeded for file: …\clean.unpacked.exe
# INFO  REPORT: Import succeeded
```

Dá mais valor que um "exit 0": o log mostra que o Ghidra **resolveu a tabela de imports
restaurada** — ele procurou e aplicou os símbolos do Windows
(`[API-MS-WIN-CORE-ERRORHANDLING-L1-1-0.DLL]`, `winspool.drv`, `urlmon.dll` — as DLLs que só
existem na imagem original, não no stub do UPX). Um dump sem IAT reparada falha exatamente aqui:
imports viram lixo e a análise estática vira ruído.

**Passo 3 — resumo**: com o binário restaurável e analisado, o "o que ele faz" passa a ser uma
pergunta respondível (strings/call graph no Ghidra, `x64dbg` no restaurado). Nesta rodada o
escopo foi o **pipeline**, não a engenharia reversa do `clean.exe`; o que o toolkit entrega é o
caminho até aqui, com evidência por passo.

### O fluxo, resumido

```
hash + new-case   →   identify-protections   →   unpack (upx -d)   →   diagnose-load (carrega?)
   (Cenário 0)         (o que é?)                 (volta a análise)      + Ghidra analyzeHeadless
```

## 5. O que **não** ficou coberto

- **Dump de memória + reparo de IAT com Scylla não foi exercido pelo caminho "duro".** Para
  UPX o caminho canônico é o `upx -d`, que **restaura o arquivo original** — não é preciso
  dump nem reparo de IAT, e é o que está provado acima. A peça "dump do processo parado no OEP
  → reconstruir a IAT com Scylla" é para packers **sem** caminho de restore (VMProtect/Themida,
  packers desconhecidos/malware). Os instrumentos estão presentes e catalogados — `Scylla.dll`
  está em `x64dbg/release/x64/`, o ScyllaHide/TitanHide estão no
  [catálogo](../docs/tools/scyllahide.md), e o `x64dbg-MCP` expõe `DumpModule`/`AnalyzeModule` —
  mas **não automatizei o passo de GUI do Scylla**, então não vou chamar isso de "provado de
  ponta a ponta". Fica como o próximo item certo.
- **Nos alvos VMProtect/Themida o `upx -d` obviamente não se aplica** — e essas amostras não
  carregam nesta máquina de qualquer forma ([root-cause-0xc000007b.md](root-cause-0xc000007b.md)),
  então um dump em memória delas está bloqueado na origem até que exista uma imagem que carregue.
- **Um alvo não-UPX com packer sem restore não foi testado** (não tinha um à mão que carregasse).

## 6. Reproduzir

```bash
# 0. caso + alvo
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/new-case.ps1 \
  -Name "iats-upx" -Target "work/packer-demo/clean.exe" -Origin "controle" -Purpose "unpack+IAT"
cp work/packer-demo/clean.exe work/iats-upx/src/clean.exe

# 1. empacotar (UPX oficial; --force por causa do CFG do alvo)
<upx>/upx.exe -9 --force work/iats-upx/src/clean.exe -o work/iats-upx/src/clean.packed.exe

# 2. triagem + diagnóstico de carga
node scripts/identify-protections.mjs work/iats-upx/src/clean.packed.exe
node scripts/diagnose-load.mjs work/iats-upx/src/clean.packed.exe

# 3. unpack + prova
<upx>/upx.exe -d work/iats-upx/src/clean.packed.exe -o work/iats-upx/unpacked/clean.unpacked.exe
node scripts/diagnose-load.mjs work/iats-upx/unpacked/clean.unpacked.exe     # exit 0 = carrega

# 4. analisável?
mkdir -p work/iats-upx/ghidra-proj
./ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat work/iats-upx/ghidra-proj iats-upx \
  -import work/iats-upx/unpacked/clean.unpacked.exe -deleteProject | grep REPORT
```

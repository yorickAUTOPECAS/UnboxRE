# 03 — Licenças, compatibilidade MIT e regras de publicação

Você pediu ferramentas **MIT-compatíveis** e um toolkit publicável no GitHub. Este
documento responde a três perguntas práticas:

1. **Posso usar** a ferramenta no meu fluxo? (quase sempre sim)
2. **Posso redistribuir** a ferramenta no meu repo? (quase sempre não)
3. **Posso publicar** o que produzi com ela? (depende do que você produz)

---

## 1. A distinção que resolve 90% das dúvidas

```
   USAR  ≠  LINKAR  ≠  REDISTRIBUIR  ≠  PUBLICAR SAÍDA
```

| Ação | O que significa | Regra prática |
|---|---|---|
| **Usar** | rodar a ferramenta como processo separado (CLI, GUI) | livre, para qualquer licença |
| **Linkar** | incluir a *biblioteca* dentro do seu binário | LGPL ok (dinâmico); GPL contamina; permissiva ok |
| **Redistribuir** | colocar o binário/código dela no seu repo | só se a licença permitir e você cumprir os termos |
| **Publicar saída** | publicar o *resultado* (relatório, pseudocódigo, spec) | regido pela licença do **alvo**, não da ferramenta |

**O ponto crítico:** chamar o Ghidra (Apache-2.0) via `analyzeHeadless` é *usar*. O
pseudocódigo que sai **não** é obra derivada do Ghidra — é análise do seu alvo. Você
pode publicá-lo se tiver direito sobre o alvo. Mas se você *copiar código-fonte do
Ghidra* para o seu script, aí é linkagem e a Apache-2.0 se aplica (permissiva, mas
exige atribuição).

---

## 2. Matriz de licenças — tudo que o toolkit usa

### 2.1 Permissivas (MIT-compatíveis — sem atrito)

| Ferramenta | Licença | Redistribuível no seu repo MIT? |
|---|---|---|
| Ghidra | Apache-2.0 | sim, com `NOTICE`/atribuição e mantendo a licença |
| REA (`rea-agents`) | MIT | sim |
| x64dbg-MCP Server | MIT | sim |
| LIEF | Apache-2.0 | sim, com atribuição |
| Capstone / Keystone | BSD-3 | sim |
| YARA | BSD-3 | sim |
| YARA-X | Apache-2.0 | sim |
| capa (Mandiant FLARE) | Apache-2.0 | sim, com atribuição |
| Detect It Easy (DIE) | MIT | sim |
| ghidriff | Apache-2.0 | sim |
| angr | BSD-2 | sim |
| Triton | Apache-2.0 | sim |
| msynth | BSD-3 | sim |
| VTIL | BSD-3 | sim |
| RetDec | MIT | sim |
| Unicorn | GPL-2.0 | **não** (ver §2.2) |
| dnlib | MIT | sim |
| de4dot-cex | MIT | sim |
| ILSpy | MIT | sim |
| apktool | Apache-2.0 | sim |
| jadx | Apache-2.0 | sim |
| wabt | Apache-2.0 | sim |
| binaryen | Apache-2.0 | sim |
| binwalk | MIT | sim |
| unblob | MIT | sim |
| UEFITool | BSD-2 | sim |
| pyelftools | Unlicense (domínio público) | sim |
| pefile | MIT | sim |
| Kaitai Struct | MIT | sim |
| mitmproxy | MIT | sim |
| PE-sieve / HollowsHunter | BSD-2 | sim, mantendo o aviso de copyright |
| GoReSym / redress | MIT | sim |
| ImHex | GPL-2.0 | **não** |
| Frida (core) | `wxWindows`/LGPL-like | sim, com termos (biblioteca) |
| Frida (bindings Python/Node) | MIT | sim |
| objection | MIT | sim |
| Redress, GoReSym | MIT | sim |

### 2.2 Copyleft — usar sim, redistribuir com cuidado

| Ferramenta | Licença | Pode usar? | Pode redistribuir? |
|---|---|---|---|
| x64dbg | GPL-3.0 | sim (CLI/GUI separado) | não no repo MIT |
| radare2 / rizin | LGPL-3.0 | sim | só como lib separada, com fonte |
| GDB | GPL-3.0 | sim | não |
| binutils (readelf/objdump) | GPL-3.0 | sim | não |
| DynamoRIO | BSD-3 | sim | sim |
| Qiling | GPL-2.0 | sim | não |
| Unicorn | GPL-2.0 | sim (lib) | não; cuidado com *linkar* |
| Scapy | GPL-2.0 | sim | não |
| boofuzz | GPL-2.0 | sim | não |
| ScyllaHide / TitanHide | GPL-3.0 | sim | não |
| D-810 / NETReactorSlayer | MIT / GPL-3.0 | sim | ver licença individual |
| de4dot | GPL-3.0 (versão antiga) | sim | não; use `de4dot-cex` (MIT) |
| dnSpyEx | GPL-3.0 | sim | não |
| MobSF | GPL-3.0 | sim | não |
| AFL++ | Apache-2.0 | sim | sim |
| Diaphora | GPL-3.0 | sim | não |
| Fluxzy (Core) | GPL-3.0 (dupla: GPL-3.0 ou comercial) | sim | não no repo MIT |
| Moneta | GPL-3.0 | sim (binário do upstream) | não no repo MIT |

> **Regra do toolkit:** o repositório publica **apenas o seu código (MIT) e a sua
> documentação**. Ferramentas GPL são *instaladas localmente* pelo bootstrap, nunca
> commitadas. O `.gitignore` já bloqueia `ghidra/`, `x64dbg/`, `tools/`, binários.

### 2.3 Comerciais / freemium — marcar claramente

| Ferramenta | Modelo | Nota |
|---|---|---|
| IDA Pro / Hex-Rays | `[COMERCIAL]` | descompilador de referência; Ghidra cobre o caso geral |
| Hopper | `[COMERCIAL]` | descompilador macOS/iOS |
| JEB | `[COMERCIAL]` | Android/DEX avançado |
| BinDiff | `[COMERCIAL]` (grátis p/ uso) | Diaphora/ghidriff cobrem |
| Burp Suite | `[FREEMIUM]` | mitmproxy cobre o essencial |
| WinDbg | `[COMERCIAL]` (grátis) | EULA Microsoft; redistribuição via winget |
| pestudio | `[FREEMIUM]` | PE triagem |
| MobSF | `[FREEMIUM]` | Android |
| rev.ng | `[FREEMIUM]` | recompilação |
| HTTP Toolkit | `[FREEMIUM]` | interceptação |
| VMware / Genymotion | `[COMERCIAL]` | VirtualBox/Hyper-V são alternativas |
| Sysinternals | `[COMERCIAL]` (grátis) | EULA Microsoft |
| Xcode Command Line Tools (`otool`, `codesign`, `atos`) | `[COMERCIAL]` (grátis) | EULA Apple; só no host macOS |

Nenhum item comercial é **requisito** do toolkit — todos têm caminho aberto no §2.1.

---

## 3. O que o toolkit pode publicar (regra de ouro)

| Publicar | Pode? | Por quê |
|---|---|---|
| Scripts próprios (Ghidra/x64dbg/Python) | ✅ | obra sua, MIT |
| Documentação e metodologia | ✅ | obra sua |
| Templates de config MCP | ✅ | obra sua |
| Regras YARA próprias | ✅ | obra sua |
| Padrões Kaitai (`.ksy`) do *formato* | ✅ | descrição de formato, não código do alvo |
| Especificação comportamental (spec) | ⚠️ | depende da licença do alvo — veja §4 |
| Pseudocódigo extraído do alvo | ⚠️ | pode ser obra derivada do alvo |
| Strings/assets do alvo | ❌ | reprodução de conteúdo do alvo |
| Binários de terceiros (Ghidra, x64dbg…) | ❌ | licença + tamanho |
| Amostras de alvos de terceiros | ❌ | material de terceiro: a licença do alvo não permite redistribuir |
| Tokens, chaves, licenças | ❌ | segurança |

---

## 4. Alvo de terceiros: o que não entra no Git

A regra dos §2–§3 vale igualmente para o **alvo**: o que é obra sua (metodologia,
script, spec de formato) pode ser publicado; o que é material do alvo (código,
pseudocódigo, strings, assets) não é seu para republicar.

| Situação | Analisar | Publicar o método | Republicar material do alvo |
|---|---|---|---|
| Ferramenta que você instalou, para interoperar | sim | sim | depende da licença do alvo |
| Pesquisa de segurança, resposta a incidente | sim | sim | não — é material do alvo |
| Alvo com proteção/licença de terceiros | sim | sim | não — é material de terceiro |

- **Analisar** o alvo é trabalho seu.
- **Documentar** o método (como se faz) é texto técnico seu.
- **Republicar** trechos do alvo é publicar material de terceiro: a licença dele
  passa a valer, como em qualquer outro item da matriz.

**Prática do toolkit:** achados ficam em `work/<alvo>/notes/` (**fora do Git**). O que
vai para `reports/` é *metodologia genérica* e *spec de comportamento* — nunca material
do alvo. Ao publicar um caso de estudo, o alvo entra como não redistribuível.

---

## 5. Compatibilidade de licença na prática — os 3 casos que importam

### Caso A — você chama a ferramenta como processo (o normal)

```
seu script (MIT)  ──exec──▶  x64dbg (GPL)  ──▶  relatório
```
Nenhuma contaminação. É uso, não linkagem. **É assim que este toolkit opera.**

### Caso B — você importa a biblioteca no seu código

```python
import lief          # Apache-2.0  → ok, atribua no NOTICE
from unicorn import Uc  # GPL-2.0   → seu script vira GPL se distribuído
```

Para GPL: mantenha o script *separado* (subprocesso) ou aceite licenciar seu script
como GPL. O toolkit escolhe **subprocesso** sempre que possível.

### Caso C — você redistribui o binário da ferramenta

Não faça. Aponte para o upstream e deixe o bootstrap instalar. Reduz o repo, evita
atualizar versões velhas e elimina o problema de licença.

---

## 6. Arquivos de licença no repositório

| Arquivo | Cobre |
|---|---|
| [LICENSE](../LICENSE) | o código e a documentação **próprios** (MIT), © UnboxRE contributors |
| [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) | **atribuição de todas as ferramentas de terceiros** referenciadas (autor, licença e upstream) |
| `NOTICE` (opcional) | só se você algum dia **redistribuir** um componente Apache-2.0 |

O [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) é a peça que deixa explícito que
este repositório **não se apropria** de trabalho alheio: cada projeto listado traz o
autor, a licença e o link do upstream. Ele é obrigatório — o CI falha se o arquivo
sumir.

O `NOTICE` separado só passa a ser necessário se você deixar de instalar localmente e
passar a **redistribuir** algum componente Apache-2.0 (ex.: empacotar o Ghidra no
release). Enquanto o bootstrap instalar localmente, o THIRD_PARTY_NOTICES.md cobre a
atribuição.

---

## 7. Verificação

```powershell
# 1) Confirme que nenhum binário de terceiro está prestes a ser commitado
git status --short | Select-String -Pattern 'ghidra/|x64dbg/|tools/|\.exe$|\.dll$'

# 2) Liste as licenças dos pacotes Python que você efetivamente importa
uv pip list --format=json | ConvertFrom-Json | Select-Object name,version

# 3) Confira que o .gitignore cobre os diretórios de terceiros
git check-ignore -v ghidra x64dbg tools rea-main x64dbg-mcp-server-main
```

Se o passo 1 não retornar nada e o passo 3 listar os cinco diretórios, a publicação
está limpa do ponto de vista de licença.

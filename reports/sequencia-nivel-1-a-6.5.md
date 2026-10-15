# A sequência de seis alvos (nivel 1 → 6.5) — o que cada um exigiu e o que ficou no toolkit

Uma página para quem não vai ler os seis relatórios inteiros. Ela responde três perguntas por
alvo: **o que ele era**, **o que exigiu do toolkit** e **o que entrou nele por causa disso** — e,
na última coluna, **o que continua aberto** (sem maquiagem; cada linha aponta o relatório onde a
medição completa está).

Como o projeto foi conduzido: cada rodada tinha **dois entregáveis de peso igual** — resolver o
alvo, e corrigir **naquela rodada** a fricção que o alvo expôs. Nenhuma correção foi adiada
("registra pra depois"), e é por isso que a coluna do meio é a mais densa das três.

---

## 1. A tabela

| Alvo | O que era | O que exigiu | O que entrou no toolkit | O que ficou aberto |
|---|---|---|---|---|
| **nivel 1** ([8.1](round-8-1-nivel-1.md)) | PE32+ x64 de **13 KB** (MinGW), **sem packer** — lógica pura | responder "é protegido?" e ler ~100 bytes de código **sem abrir Ghidra nem debugger** | `scripts/triage-static.mjs` (cabeçalho, TLS callbacks, imports, strings com endereço), `scripts/disasm-range.py`; `diagnose-load --stdin` (F3); capstone sondado/instalado de verdade (F6) | Ghidra/x64dbg **não exercitados** (decisão, não falha); `--refs` é heurística declarada; `disasm-range` é linear (não segue fluxo) |
| **nivel 2** ([8.2](round-8-2-nivel-2.md)) | PE32+ x64 (MinGW), sem packer; checagem é um **pipeline SSE2** | ler **os bytes** que o disassembly cita (semente, máscaras) e localizar constantes que não são string | `scripts/pe-read.mjs` (mapa de seções + hexdump + leitura tipada); `--data-refs` no `triage-static` (o `--refs` antigo escondia as não-strings) | ambiguidade de leitura do `pshufhw` de dois registradores (um emulador resolveria); solver do caso não roda no CI |
| **nivel 3** ([8.3](round-8-3-nivel-3.md)) | **ELF64 Linux** com VM de bytecode própria (22 opcodes, 288 B cifrados) | o Cenário 0 **inteiro** recusou o formato (cinco comandos, mesma mensagem) | leitura de ELF em `triage-static`, `disasm-range.py`, `pe-read.mjs` e `identify-protections.mjs`; `diagnose-load` ensinou a diferença (ELF no Windows = 193, **não** 0xC000007B) | na rodada o alvo não rodou; o adendo de 2026-10-14 fechou black-box no WSL (o próprio binário imprimiu `ACCESS GRANTED`, 3 controles recusando) |
| **nivel 4** ([8.4](round-8-4-nivel-4.md)) | **zipapp Python 3.13 protegido** com runtime nativa ELF; topo do programa aplanado (dispatcher de 127 rótulos) | "container não é imagem": nem seção, nem RVA — e a **dica de ABI** (a versão do CPython) não aparecia em lugar nenhum | `scripts/triage-archive.mjs` (ZIP/zipapp pelo diretório central, `.pyc`, marshal, formato de cada membro + dica de ABI) | fechado depois, black-box (senha `! ! ! ! ! ! ! !  TREE`, flag `CMO{builtins}`); de-*aplanar* não foi tentado pela metade; `diagnose-load` não roda alvo Python |
| **nivel 5** ([8.5](round-8-5-nivel-5.md)) | PE32+ x64 (Rust), **sem packer**, com **VM própria**; cálculo termina em <1 ms | instrumentar **antes** de alimentar a entrada: gravar registradores e despejar frame dentro do processo vivo | `scripts/park-patch-run.ps1` — 4 modos de hook (`-Patch`, `-FreezeIat`, `-HookCall`, `-HookPos`, `-HookStub`, `-HookSeed`) com **7 armadilhas medidas** embutidas | senha "padrão-ouro" não fechou: o obstáculo é **transporte** (o alvo exige entrada que decodifique para 32 B binários), não o modelo — que passou a reproduzir os dois digests medidos no alvo |
| **nivel 6.5** ([8.6](round-8-6-nivel-6.5.md)) | **JAR** (Forge 1.8.9) + **DLL nativa de 31 MB** (trava anti-leak: 32 classes, 100 nativos) | recompilar sem a trava; e, antes disso, **ler bytecode** — nenhum leitor do toolkit sabia | `scripts/triage-java.mjs` (class file, nativos, loader JNI por `System.load`+extração, binários embutidos, colisões de maiúscula); correção do **falso-positivo de UPX** (nome de seção ≠ marcador) | os **68 nativos reais** não foram reconstruídos (o corpo vive só na DLL, empacotada); 38 fontes do build original perdidos na colisão de maiúscula do NTFS |

---

## 2. O que o toolkit aprendeu, por tema

**Triagem (a mesma pergunta mudou de forma quatro vezes).** "Está protegido, e com o quê?" começou
como leitura de PE (8.1), virou leitura de **ELF** (8.3), depois de **container/zipapp** (8.4) e
finalmente de **JVM/bytecode** (8.6). Em todas as quatro, a primeira resposta do toolkit foi
*recusa* — e em todas as quatro a recusa virou leitura. A lição está escrita em três relatórios
com a mesma frase: **recusar não é triagem**.

**Instrumentação.** A rodada 8.5 é a que mais mudou o ferramental: o alvo decidia em menos de 1 ms
depois da entrada, e o único caminho era instrumentar **antes** de alimentar. O
`park-patch-run.ps1` nasceu aí, com sete armadilhas medidas (entre elas: `call stub` precisa
reconstruir o `rsp` do call; e o instrumento **também** precisa ser medido — dois defeitos dele só
apareceram no smoke, não na leitura do código).

**Verificação.** `verify-dump.mjs` (dump contra o original em claro), o **modo fraco** declarado
quando não há original, `check-consistency.mjs` (docs ↔ código ↔ licenças, 198 verificações hoje) e
`verify-licenses.mjs` (79 licenças contra a fonte primária). Regra da casa, respeitada nas seis
rodadas: **toda afirmação reportada vem com comando e saída reais** — e o que não funcionou fica
numa seção própria.

**Licenças.** Nenhuma ferramenta de terceiro é redistribuída: o toolkit baixa do upstream,
declara cada licença em `config/` e tem um job de CI que reprova quem divergir da fonte primária.

---

## 3. O que continua aberto (agregado)

| Aberto | Onde | Por quê |
|---|---|---|
| Corpo dos 68 nativos do nivel 6.5 | [8.6 §6](round-8-6-nivel-6.5.md) | vive só na DLL empacotada; o `JNI_OnLoad` não retorna (4 execuções medidas) |
| Build do nivel 6.5 de ponta a ponta | [8.6 §3](round-8-6-nivel-6.5.md) | 38 fontes perdidos na colisão de maiúscula do NTFS |
| Senha "padrão-ouro" do nivel 5 | [8.5 §4](round-8-5-nivel-5.md) | obstáculo é transporte (entrada binária), não o modelo |
| Ghidra, x64dbg, Unicorn, Qiling, LIEF não exercitados nas rodadas 8.1–8.4 | 8.1–8.4 §"em aberto" | nenhuma delas foi **necessária** ali; "não usadas" ≠ "não funcionam" — a evidência delas é dos relatórios anteriores e do CI |
| `--refs` heurístico; `disasm-range.py` linear; parser ELF validado em um alvo | 8.1/8.3 | limitações declaradas das ferramentas, não defeitos escondidos |

---

## 4. Como citar isto

Cada linha da tabela aponta o relatório da rodada, e cada relatório tem a seção
**"O que NÃO funcionou, e o que continua em aberto (sem maquiagem)"** — leia-a antes de repetir
qualquer número daqui: é lá que o limite da evidência está escrito, e não nesta página de resumo.

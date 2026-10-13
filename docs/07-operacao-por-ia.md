# 07 — Operação por IA

O pressuposto do projeto é que **a LLM é o operador primário**. Isso muda o design:
documentação é interface, artefatos são memória, e o maior risco não é a ferramenta
falhar — é a IA **inventar** um resultado plausível. Este documento é sobre como evitar
isso.

---

## 1. Os três modos de falha que importam

| Modo | Como aparece | Antídoto |
|---|---|---|
| **Alucinação de artefato** | "o binário usa RSA-2048" sem nenhum arquivo de evidência | todo achado tem que citar um arquivo em `evidence/` |
| **Perda de contexto** | sessão nova re-analisa o que já foi analisado, ou contradiz | `notes/findings.md` é o estado; a IA lê antes de agir |
| **Ação destrutiva silenciosa** | patch aplicado no `src/`, alvo corrompido | `src/` é imutável; todo patch em `unpacked/` |

**Por quê documentar isso em primeiro lugar:** um toolkit de RE operado por IA que não
resolve esses três é pior que nenhum toolkit — ele produz confiança infundada.

---

## 2. O contrato de evidência

Todo achado no `notes/findings.md` segue este formato:

```markdown
### F-007 — A validação de licença usa HMAC-SHA256 com chave embutida
- **Confiança:** observado | inferido | hipótese
- **Evidência:** evidence/12-key-schedule.txt (dump de memória em 0x7FF...A320)
- **Comando:** ReadMemory 0x7FF...A320 64  →  anexo
- **Reprodução:** LoadBinary + SetBreakpoint 0x401A20 + run
- **Consequência:** reimplementar como HMAC; a chave muda por versão
```

As três palavras de confiança não são decorativas:

- **observado** — vi os bytes/comportamento. Um comando reproduz.
- **inferido** — deduzi de padrões (ex.: constantes de inicialização SHA → "é SHA-256").
- **hipótese** — plausível, não verificado. **Precisa de teste antes de virar decisão.**

**Regra para a IA:** nunca promova uma hipótese a fato sem um comando que a teste.
Se o teste não for possível agora, escreva `TODO: verificar`.

---

## 3. Prompting por fase

Cada fase tem um pedido diferente. Pedir "faça engenharia reversa deste binário" produz
resposta genérica; pedir a fase produz trabalho verificável.

### Fase recon

> "Liste as seções, imports, exports e as 30 strings mais informativas de
> `work/<alvo>/src/<bin>`. Não interprete — só reporte, com o comando usado."

*Por quê:* você quer matéria-prima sem interpretação antecipada. Interpretação na fase
de recon contamina tudo depois.

### Fase triage

> "Dado `evidence/01-strings.txt` e `evidence/02-imports.txt`, produza 5 hipóteses
> sobre a arquitetura do programa, cada uma com a evidência que a sustenta e o teste
> que a refutaria."

*Por quê:* força hipóteses **falseáveis**. "Provavelmente é C++" não é falseável;
"usa Qt porque importa `QMetaObject`" é.

### Fase deep

> "Decompile a função em `0x401A20` no Ghidra e produza pseudo-C anotado. Marque cada
> variável com o tipo inferido e diga qual evidência suporta o tipo."

*Por quê:* nomes e tipos são onde a IA mais alucina. Exigir justificativa por tipo
expõe as inferências frágeis.

### Fase síntese

> "Escreva `notes/protocol.md` a partir APENAS dos artefatos em `captures/` e
> `evidence/`. Se algo não estiver coberto, escreva `NÃO OBSERVADO`."

*Por quê:* "NÃO OBSERVADO" é a saída mais valiosa de um relatório de RE. Ela define o
próximo experimento.

---

## 4. Ordem de operação recomendada

```
   ┌─ 1. health-check        (o ambiente está são?)
   │
   ├─ 2. new-case            (congela entrada + hash)
   │
   ├─ 3. recon               (matéria-prima, sem interpretação)
   │
   ├─ 4. triage              (hipóteses falseáveis)
   │
   ├─ 5. deep                (estático + dinâmico, com evidência)
   │
   ├─ 6. síntese             (findings.md + protocol.md)
   │
   └─ 7. publish-safe        (o que pode ir pro GitHub?)
```

**Por quê health-check primeiro:** metade dos "o REA não funciona" é `JAVA_HOME` errado.
Diagnóstico de 10 segundos antes de 2 horas de depuração.

---

## 5. Padrões de MCP que funcionam bem

**Use o x64dbg-MCP para:** inspeção (read memory, registers, stack, disassemble),
breakpoints, dumps. Ele é excelente nisso e a IA é boa em formular essas consultas.

**Use com cuidado:** `WriteMemToAddress`, `Assemble`, patch de bytes, `RestorePatches`.
Aqui a IA pode corromper o estado do alvo. Regra: **patch só em `dumps/`, e sempre
depois de gravar o estado original** (o plugin tem `RestorePatches` — use-o).

**Use o REA para:** pipelines que cruzam domínios (firmware → Ghidra, rede → parser),
e para o contrato de evidência.

**Não use IA para:** decidir se algo é legal publicar. Isso é seu.

---

## 6. Higiene de sessão

Sessões longas de RE degradam: o contexto enche, o modelo começa a repetir hipóteses
antigas. Sinais e correção:

| Sinal | Correção |
|---|---|
| o modelo "relembra" um endereço que nunca apareceu | pare; reescreva `findings.md`; nova sessão |
| conclusões contradizem sessão anterior | `findings.md` é a fonte; reconcilie explicitamente |
| respostas ficam genéricas | o contexto está saturado — divida por fase |
| o modelo para de citar arquivos | exija citação ou descarte a resposta |

**Regra prática:** uma sessão por fase do §4. Ao trocar de fase, escreva um resumo de
5 linhas em `notes/` e comece nova sessão. Custa menos que lutar contra contexto sujo.

---

## 7. Automação de pipeline (quando já existe estabilidade)

Só automatize o que você já fez à mão duas vezes. O padrão:

```bash
node scripts/pipeline.mjs --case acme-app-2.1 --stage recon
```

O pipeline lê `work/<alvo>/case.json`, executa a fase, grava em `evidence/` e anexa em
`findings.md`. **Não** deixe o pipeline decidir interpretação — ele coleta e registra;
a IA interpreta a partir do que foi coletado.

---

## 8. Checklist de uma sessão de IA bem-sucedida

- [ ] `health-check` passou (ou as falhas estão registradas)
- [ ] o alvo tem hash e o `original/` está intacto
- [ ] todo achado em `findings.md` cita um arquivo de evidência
- [ ] todo achado tem nível de confiança
- [ ] hipóteses têm teste associado ou `TODO: verificar`
- [ ] o que não foi observado está escrito como não observado
- [ ] nenhum token/segredo entrou em arquivo versionado

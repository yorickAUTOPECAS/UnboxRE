# 08 — Higiene e segurança

Este toolkit manipula **código hostil por definição**. Amostras podem ser maliciosas,
podem detectar sua máquina, podem tentar escapar do sandbox. Este documento é curto de
propósito: são as regras que evitam perder a máquina ou o repositório.

---

## 1. Isolamento de amostras

**Nunca analise dinamicamente na máquina de trabalho.** O `x64dbg` é um debugger de
usermode rodando no seu Windows real — ele não é sandbox.

| Camada | Quando | Como |
|---|---|---|
| VM descartável | amostra desconhecida / suspeita | Hyper-V/VMware/VirtualBox, snapshot antes |
| Snapshot restore | sempre, antes de rodar | reverta após a sessão, não "limpe" |
| Rede host-only | amostras que falam com a rede | sem bridge, sem NAT para a LAN |
| Conta de usuário não-admin | sempre | debugger não precisa de admin para usermode |
| Máquina separada | kernel debugging | o host fica limpo; o alvo é o descartável |

**Por quê snapshot e não "limpeza":** malware moderno persiste em múltiplos lugares
(registry, tasks, WMI, bootkit). Restaurar snapshot é determinístico; limpar não é.

---

## 2. Kernel debugging

Kernel debugging exige duas máquinas: **host** (WinDbg, limpo) e **target** (kernel com
debug habilitado, descartável), conectadas por serial nomeado ou rede com chave.
O target **nunca** é sua máquina de trabalho, e o par host/target **nunca** compartilha
disco.

```powershell
# no TARGET (uma vez, e é uma alteração irreversível sem snapshot):
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.56.1 port:50000 key:1.2.3.4
```

Se você não tem uma VM descartável, **não faça kernel debugging**. Marque como gap.

---

## 3. Segredos e tokens

O `x64dbg-MCP` gera um token em `x64dbg/mcp_config.json`. Ele dá controle total do
debugger — é uma credencial de administrador.

- [x] `mcp_config.json` está no `.gitignore`
- [x] `config/env/*.env` (exceto `.example`) está no `.gitignore`
- [x] `work/**/captures/*.keys` (SSLKEYLOGFILE) está no `.gitignore`
- [x] `*.pcapng` com tráfego autenticado **não** vai para o repo

**Antes de qualquer `git add`, rode:**

```bash
node scripts/scan-secrets.mjs        # procura tokens/chaves nos arquivos staged
```

**Rotacione o token** depois de qualquer sessão em que ele apareceu em print, log ou
transcrição de chat.

---

## 4. O que pode ser publicado no GitHub

O toolkit é publicável. As **amostras** e os **artefatos de análise** normalmente não.
A regra:

| Item | Publicar? | Por quê |
|---|---|---|
| Scripts, docs, config templates | ✅ sim | é o produto |
| Binários de terceiros | ❌ não | redistribuição não autorizada |
| Dumps/pseudocódigo de terceiros | ❌ não | obra derivada |
| Chaves, tokens, certificados | ❌ nunca | segurança |
| PoC de bypass de proteção | ⚠️ caso a caso | contém material do alvo: não redistribuível |
| Metodologia, catálogo, workflows | ✅ sim | conhecimento |
| Hash e metadados do alvo | ✅ geralmente | fato, não obra |

**Por quê a distinção importa:** descrever *como* analisar é livre. Redistribuir o
resultado da análise de software de terceiros não é. Publique o **método**; mantenha o
**artefato** local. Veja [03-licencas.md](03-licencas.md) §4.

---

## 5. Licenças do próprio toolkit

O repo é **MIT**. Isso exige cuidado com o que você *copia para dentro dele*:

- ✅ Ferramentas MIT/BSD/Apache-2.0 → podem ser referenciadas livremente.
- ⚠️ Ferramentas **GPL** (Ghidra é Apache-2.0, ok; **radare2 é LGPL-3**) → você pode
  *usar* e *chamar via CLI*, mas não pode *linkar* e distribuir sem abrir seu código.
  Chamar por subprocesso é a separação que mantém o MIT.
- ❌ Ferramentas proprietárias → não podem ser redistribuídas, só documentadas como
  `[COMERCIAL]`.

O detalhamento está em [03-licencas.md](03-licencas.md).

---

## 6. Rede e interceptação

- Interceptar tráfego **seu** ou de dispositivo **seu**: ok.
- Interceptar tráfego de terceiros sem autorização: crime em praticamente toda
  jurisdição.
- `SSLKEYLOGFILE` só funciona em aplicações que respeitam a variável (Chromium, Firefox,
  curl, algumas apps Electron). App com TLS próprio exige hooking — e isso só no seu
  alvo.
- **Não** deixe o `mitmproxy` com CA instalada de forma permanente na máquina de
  trabalho.

---

## 7. Fuzzing

- Só contra alvo próprio, ou com autorização escrita.
- Fuzzing gera tráfego anômalo e pode derrubar serviços — nunca contra produção de
  terceiros.
- Rode em rede isolada; limite taxa; monitore.

---

## 8. Checklist antes de fechar uma sessão

- [ ] snapshot da VM revertido (ou programado para reverter)
- [ ] `work/` contém apenas o que você quer manter
- [ ] nenhum segredo em arquivo versionado (`scan-secrets.mjs`)
- [ ] patches registrados em `notes/`, alvo original intacto
- [ ] artefatos de terceiros marcados como não-publicáveis
- [ ] token do MCP rotacionado, se exposto

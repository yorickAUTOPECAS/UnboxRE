# Auditoria de licenças de terceiros — fonte primária

**Data:** 2026-10-13
**Escopo:** linhas da matriz de licenças que estavam divergentes do que o upstream
declara, mais os dois projetos citados no catálogo sem entrada na matriz
(`capa` e `Fluxzy`).
**Método:** abrir o `LICENSE`/`LICENSE.md` do repositório de origem (raw) ou a API
de licença do GitHub — nunca a memória, nunca o `winget`/`pip`. Citação literal do
cabeçalho encontrado registrada abaixo, para que a auditoria seja refazível sem
depender deste relatório.

---

## 1. Resultado

| Projeto | Documentação dizia | Upstream diz | Situação |
|---|---|---|---|
| PE-sieve | BSD-2 | BSD-2 | já correto (commit `c48782d`) |
| HollowsHunter | BSD-2 | BSD-2 | já correto (commit `c48782d`) |
| capa (Mandiant FLARE) | ausente da matriz | Apache-2.0 | corrigido (`777f1cb`) |
| Fluxzy (Core) | `MIT` (catálogo do bootstrap) | GPL-3.0 (dupla: GPL-3.0 ou comercial) | corrigido (`777f1cb`) |
| Moneta | "freeware sem licença declarada", autor hasherezade | GPL-3.0, Forrest Orr | corrigido (`777f1cb`) |

Commits associados (verificáveis com `git show --stat`):

```
777f1cb  Corrige a matriz de licenças (capa, Fluxzy, Moneta) e reduz o §4 a fato técnico
c48782d  Corrige licenças de terceiros na fonte e tira o tom de escopo da documentação
```

---

## 2. Evidência por projeto

### PE-sieve — BSD-2 (confirmado)

`https://raw.githubusercontent.com/hasherezade/pe-sieve/master/LICENSE`

```
BSD 2-Clause License

Copyright (c) 2017-2026, @hasherezade
All rights reserved.
```

### HollowsHunter — BSD-2 (confirmado)

`https://raw.githubusercontent.com/hasherezade/hollows_hunter/master/README.md`
traz o selo que aponta para o `LICENSE` do próprio repositório:

```
[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](...)
```

### capa — Apache-2.0 (corrigido)

`https://raw.githubusercontent.com/mandiant/capa/master/LICENSE.txt`

```
                                 Apache License
                           Version 2.0, January 2004
```

Estava atribuído corretamente no `THIRD_PARTY_NOTICES.md`, mas **faltava na matriz**
`docs/03-licencas.md`. Consequência prática: a ferramenta de triagem estática mais
usada do perfil `static` ficava fora da regra de "pode redistribuir?", que é
exatamente onde a resposta (sim, com atribuição) importa. Entrou em §2.1.
Ressalva de nome: o pacote `capa` no PyPI de outro autor não é este projeto — o
alvo é `mandiant/capa`, distribuído como `flare-capa`.

### Fluxzy — GPL-3.0 (corrigido)

`https://raw.githubusercontent.com/haga-rak/fluxzy.core/main/LICENSE.md`

```
- **Fluxzy.Core**: [GPLv3 or other](src/Fluxzy.Core/LICENSE.md)
...
Commercial licensing is available upon request. Please contact project@fluxzy.io
```

O catálogo do bootstrap (`scripts/bootstrap-windows.ps1`, perfil `net`) declarava
`License = 'MIT'`. Não é um typo inofensivo: o rótulo é lido por quem decide o que
pode ser empacotado, e "MIT" num copyleft convida a redistribuir sem cumprir a
licença. Passou a `GPL-3.0` no catálogo e entrou em §2.2 (copyleft) da matriz.

### Moneta — GPL-3.0, Forrest Orr (corrigido, com troca de atribuição)

`https://api.github.com/repos/forrest-orr/moneta` → `license.spdx_id = GPL-3.0`
(o `LICENSE` do repositório é o texto da GNU GPL v3, 29 June 2007).

A documentação anterior apontava `hasherezade / https://hasherezade.net` como
origem do Moneta. Esse ponteiro não se sustenta:

- `https://hasherezade.net/moneta/` não existe mais — redireciona para a lista de
  projetos do autor, e Moneta **não está** nessa lista;
- `https://api.github.com/repos/hasherezade/moneta` → `404`, e
  `?q=moneta+user:hasherezade` → `total_count: 0`;
- `http://web.archive.org/cdx/search/cdx?url=hasherezade.net/moneta` → `[]`,
  ou seja, não há nem captura histórica dessa página.

O Moneta vivo hoje é `forrest-orr/moneta` ("a live usermode memory analysis tool for
Windows with the capability to detect malware IOCs"), GPL-3.0. A linha saiu de §2.3
(comerciais/freemium) — onde estava como "sem licença declarada, trate como todos os
direitos reservados" — e foi para §2.2 (copyleft), com autor e upstream corrigidos no
`THIRD_PARTY_NOTICES.md` e em `docs/02`.

**Limitação registrada:** não foi possível recuperar o `LICENSE` do Moneta de
hasherezade porque o projeto saiu do ar. Se a intenção original era aquele binário
aposentado, não existe evidência de licença a citar — e nesse caso a única afirmação
defensável é a do Moneta atual, que é a que ficou no repositório.

---

## 3. Documentação afetada por escopo (não por licença)

Além da matriz, o §4 de `docs/03-licencas.md` ("Análise de proteção, DRM e
licenciamento") perdeu a linguagem de finalidade lícita/DRM/risco jurídico e passou a
tratar só do critério técnico que decide a publicação: **obra própria versus material
do alvo**. `docs/08-higiene-e-seguranca.md` acompanhou (linha do PoC de bypass e a
referência à antiga seção "Escopo legal", que não existia com esse nome).

O `README.md` §6 já estava limpo desde `c48782d`; nada a fazer lá.

---

## 4. O que continua fora desta auditoria

Esta foi uma auditoria **dirigida**: as quatro linhas sinalizadas mais os dois projetos
sem entrada na matriz. As demais linhas de `docs/03-licencas.md` (~90) carregam a
mesma classe de risco de erro e **não** foram reconferidas contra o upstream nesta
leva. Uma passada completa precisa de código, não de olho: o formato da tabela
(`| Ferramenta | Licença | ... |`) é regular o bastante para um verificador que
consulte a API de licença do GitHub por linha e reporte divergência.

O que já existe hoje:

- `scripts/scan-secrets.ps1` (sem rede) — pega o que **não** pode ser versionado;
- CI: confirma que nenhum binário de terceiro foi rastreado e que arquivos de docs
  obrigatórios existem.

Nada disso valida licença contra o upstream, que é o buraco que este relatório expõe.
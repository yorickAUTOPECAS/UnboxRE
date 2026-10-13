# Toolchain WebAssembly (wabt, wasm-decompile, wakaru)
**Licença:** Apache-2.0 (wabt) / Apache-2.0 (Binaryen) / MIT (wakaru) ·
**Status:** a instalar · **Camada:** formatos

Caminho após bootstrap: `tools/wabt/`, `tools/binaryen/`, `tools/wakaru/`

## O que faz

| Ferramenta | Conversão | Uso |
|---|---|---|
| **wasm2wat** (wabt) | WASM → WAT (texto canônico) | leitura fiel do módulo |
| **wasm-decompile** (Binaryen) | WASM → pseudo-C | leitura rápida da lógica |
| **wasm-objdump** (wabt) | metadados, seções, imports | mapa do módulo |
| **wakaru** | JS bundlado/minificado → legível | reverter o JS que gera/chama o WASM |
| **wasm2c** (wabt) | WASM → C | recompilar/instrumentar |

## Quando usar

- App web/Electron cuja lógica pesada está em WASM (jogos, CAD, codecs, crypto).
- Módulo WASM gerado por Emscripten (C/C++) — o pseudo-C do Binaryen fica próximo do
  original.
- Quando você precisa **reconstruir** o fluxo: `wasm2c` gera C que você compila com
  instrumentação.
- Reverter o JS companheiro com **wakaru** — quase sempre é mais produtivo que atacar o
  WASM direto, porque os nomes de funções exportadas estão no JS.

## Quando NÃO usar

- **Esperando nomes.** WASM compilado perde nomes. Se houver "name section" você tem
  sorte; senão, tudo é `func_17`.
- **Quando a lógica está no JS.** Muitos apps usam WASM só para uma rotina de crypto; o
  resto é JS. Comece pelo JS (wakaru), não pelo WASM.
- **WASM ofuscado/protegido.** Existem ofuscadores de WASM; aí a leitura canônica não
  ajuda muito e você vai para instrumentação.

## Instalação

```bash
$ npm i -g wabt binaryen                 # ou baixe os releases
$ npx wakaru app.js -o work/acme-wasm/debundled/
```

## Uso — receitas curtas

```bash
# Mapa do módulo
$ wasm-objdump -x app.wasm | head -60

# Texto canônico (fiel)
$ wasm2wat app.wasm -o work/acme-wasm/app.wat

# Pseudo-C (legível)
$ wasm-decompile app.wasm -o work/acme-wasm/app.dcmp

# Voltar para C compilável (instrumentar)
$ wasm2c app.wasm -o work/acme-wasm/app.c

# Reverter o JS que acompanha
$ wakaru app.js -o work/acme-wasm/debundled/
```

**Ordem que funciona:** objdump (mapa) → wakaru no JS (nomes) → wasm-decompile (lógica)
→ Ghidra se você precisar de grafo e tipos.

## Integração com o resto do setup

- **REA** tem bridge WASM (`wabt`/`wakaru`) — é o caminho mais direto para lote.
- **Ghidra** não descompila WASM nativamente, mas o C gerado pelo `wasm2c` **compila** e
  aí você tem um binário analisável com todas as ferramentas de ELF.
- **YARA/capa** podem rodar no C gerado.
- Artefatos em `work/<alvo>-wasm/`.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| atacar WASM antes do JS | perde os nomes | wakaru primeiro |
| esperar nomes de variáveis | tudo `func_N` | aceite e renomeie conforme entende |
| `wasm2c` sem os headers do runtime | não compila | inclua o `wasm-rt.h` do wabt |
| ignorar a name section | perde nomes disponíveis | `wasm-objdump -x` mostra se existe |
| WASM ofuscado | leitura canônica inútil | instrumente em runtime |

## Referências

- `docs/06-workflows.md` Cenário 7 (WASM)
- `docs/02-catalogo-ferramentas.md` §5 (d.7)

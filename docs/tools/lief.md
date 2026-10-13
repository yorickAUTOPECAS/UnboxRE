# LIEF (Library to Instrument Executable Formats)
**Licença:** Apache-2.0 · **Status:** a instalar · **Camada:** análise estática

Caminho após bootstrap: `tools/lief/` (ou via `pip install lief`)

## O que faz

Biblioteca (Python/C++/Rust) para **ler e escrever** PE, ELF, Mach-O, DEX e OAT. Lê
headers, seções, imports/exports, relocations, TLS, recursos. E — o que a distingue de
todas as outras — **reescreve** o binário: adicionar seção, alterar entry point, mudar
imports, injetar payload, rebuild de imports.

## Quando usar

- **Automação de PE.** Extrair imports de 500 binários em segundos, sem abrir GUI.
- **Verificação de patch.** Aplicar um patch programaticamente e validar.
- **Instrumentação.** Adicionar seção, mudar EP — base para injetar um hook estático.
- **Normalizar firmware.** Rebuild de binários extraídos que ficaram com headers
  estranhos.
- **CI.** Validar propriedades de um binário (assinatura, seções, entitlements).

## Quando NÃO usar

- **Análise semântica.** LIEF te dá a **estrutura do container**, não o que o código
  faz. Para isso: Ghidra.
- **Editar um binário protegido.** Reescrever um PE com checksum/integrity check embutido
  invalida a assinatura e o alvo morre. Repare a assinatura depois ou não edite.
- **Como substituto do dump de memória.** LIEF edita arquivo em disco; para código
  desempacotado você precisa de **dump** (x64dbg) + reparo de IAT.

## Instalação

```bash
$ pip install lief                       # Python (mais simples)
# ou
$ cargo add lief                         # Rust
```

## Uso — receitas curtas

**Inspecionar um PE:**

```python
import lief
b = lief.parse("work/acme/src/target.exe")
print("EP:", hex(b.entrypoint))
print("seções:", [(s.name, hex(s.virtual_address), s.size) for s in b.sections])
print("imports:", [(e.name, len(e.entries)) for e in b.imports])
print("assinado:", b.has_signatures)
```

**Lote — triagem de imports (o caso de uso do domínio f):**

```python
import lief, json, pathlib
out = []
for p in pathlib.Path("tools-out/firmware").rglob("*.so"):
    b = lief.parse(str(p))
    if b is None: continue
    out.append({"path": str(p), "imports": [e.name for e in b.imports]})
json.dump(out, open("evidence/lief-imports.json", "w"), indent=2)
```

**Reescrever (com cuidado):**

```python
b = lief.parse("unpacked/target.exe")
b.entrypoint = 0x401000          # ex.: apontar para o código original
b.write("unpacked/target.patched.exe")
```

## Integração com o resto do setup

- **Alimenta o Ghidra:** um binário com headers normalizados pela LIEF importa melhor.
- **Complementa o x64dbg:** LIEF diz o que **deveria** estar na memória; o x64dbg mostra
  o que **está** (útil para detectar hooking/patches em runtime).
- **PE-sieve** usa a mesma ideia no sentido inverso (compara disco × memória).
- Saída JSON entra direto em `evidence/`.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| editar binário assinado | assinatura inválida | não edite, ou re-assine |
| editar binário com integrity check | alvo morre | repare o check antes (Cenário 2) |
| `lief.parse` em binário truncado | retorna `None` silenciosamente | sempre cheque `None` |
| esperar semântica | você só tem o container | use Ghidra para o código |
| rebuild de imports mal feito | binário não carrega | valide abrindo no x64dbg/PE-bear |

## Referências

- `docs/02-catalogo-ferramentas.md` §2 (a.2)
- LIEF docs: API Python espelha a C++

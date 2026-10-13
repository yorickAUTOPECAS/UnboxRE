# Detect It Easy (DIE) + `diec`
**Licença:** MIT · **Status:** a instalar · **Camada:** análise estática

Caminho após bootstrap: `tools/die/`

## O que faz

Identifica **o que construiu o binário e o que o protege**: compilador, linker,
linguagem, packer, protetor, instalador. Usa assinaturas + heurística (entropia por
seção, EP fora da primeira seção, imports mínimos, seções com nomes atípicos).

`diec` é o CLI — o que torna o DIE utilizável por IA e pipeline.

## Quando usar

- **Primeiro comando em qualquer alvo novo.** Custa 1 segundo e define toda a
  estratégia: se é UPX, você desempacota antes; se é .NET, você vai por de4dot; se é
  VMProtect, você muda de abordagem (Cenário 2).
- Triagem em lote de firmware/malware.
- Detectar protetor **antes** de perder horas analisando um stub.

## Quando NÃO usar

- **Como verdade absoluta.** O DIE erra em protetores modificados/custom. Um resultado
  "unknown" não significa "não protegido" — significa "assinatura não bateu".
- **Para decidir sozinho.** Ele diz "VMProtect"; ele não diz *o que* está virtualizado
  nem *como* lidar. A decisão é sua (Cenário 2).
- **Em binário já desempacotado.** Aí o resultado é o compilador, que você já sabe.

## Instalação

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile static
# ou baixe o release do DIE e extraia em tools/die/
```

## Uso — receitas curtas

```bash
# Relatório completo
$ tools/die/diec work/acme/src/target.exe

# Formato curto, ideal para log/pipeline
$ tools/die/diec -r -j work/acme/src/target.exe | tee evidence/$(date +%Y%m%d)-die-001.json
```

```bash
# Lote: quais dos 200 binários extraídos estão empacotados?
$ find tools-out/firmware -type f -executable -print0 \
  | xargs -0 -n1 -I{} sh -c 'printf "%s\t" "{}"; tools/die/diec -r "{}" | head -1'
```

**Leitura do resultado — o que importa:**

| Sinal no DIE | O que significa | Próximo passo |
|---|---|---|
| `UPX` | packer simples | Cenário 1: `upx -d` |
| `VMProtect` / `Themida` / `Enigma` | virtualização | Cenário 2: medir, não devirtualizar às cegas |
| `.NET` / `ConfuserEx` | IL ofuscado | Cenário 3: de4dot |
| `PyInstaller` / `Nuitka` | Python empacotado | extrair o `pyc` e usar decompilador Python |
| `AutoIt` / `NSIS` / `InnoSetup` | instalador | extrair payload primeiro |
| entropia ~8 em seção grande | comprimido/criptografado | suspeita de packer mesmo sem assinatura |

## Integração com o resto do setup

- **Antes do Ghidra** e **antes do x64dbg** — define a estratégia de ambos.
- **Depois do unblob/binwalk** em firmware: identifique cada ELF extraído.
- Alimenta `notes/triage.md` e vira o campo `protection` do `case.json`.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| confiar em "unknown" | você acha que não há proteção | confirme por entropia e por comportamento |
| usar só a GUI | não automatiza | use `diec` |
| não registrar o resultado | a estratégia fica sem justificativa | grave em `evidence/` |

## Referências

- `docs/06-workflows.md` Cenários 1–3 (uso do resultado do DIE)
- `docs/02-catalogo-ferramentas.md` §2 (a.5)

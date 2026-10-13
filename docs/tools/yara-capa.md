# YARA / yara-x + capa
**Licença:** BSD-3 (YARA) / Apache-2.0 (yara-x) / Apache-2.0 (capa) ·
**Status:** a instalar · **Camada:** análise estática

Caminhos após bootstrap: `tools/yara/`, `tools/capa/`

## O que faz

- **YARA** casa **padrões** (bytes, strings, expressões) contra arquivos. É o motor de
  assinaturas de facto para malware e para triagem em massa.
- **capa** identifica **capacidades** a partir de regras: "cria processo", "persiste via
  registry", "criptografa com AES", "faz requisição HTTP". Responde *o que o binário
  pode fazer*, não *o que ele é*.

## Quando usar

- **Triagem em massa:** 2000 amostras, quais merecem atenção? YARA filtra.
- **Capacidades:** antes de reverter, descubra o que o binário faz por categoria.
- **Firmware:** YARA encontra chaves privadas, URLs, credenciais embutidas, com regras
  próprias.
- **Verificação de patch:** escreva uma regra que casa com o binário **original** e não
  com o patchado — prova objetiva de que o patch pegou.

## Quando NÃO usar

- **Como substituto de análise.** YARA casa texto; não entende fluxo de controle. Uma
  regra que não casa não significa "não faz".
- **Contra alvo empacotado.** O conteúdo está comprimido; nenhuma regra casa. Desempacote
  primeiro.
- **capa em binário empacotado/protegido** — mesmo problema, e capa avisa pouco sobre isso.
- **Confundir com AV.** Você não está escrevendo detecção para produção; está fazendo
  triagem para análise.

## Instalação

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile static
# yara-x é a reimplementação em Rust (mais rápida, mesma sintaxe)
PS> winget install VirusTotal.YARA-X       # ou baixe o release
```

```bash
$ pip install capa                        # ou baixe o binário standalone
```

## Uso — receitas curtas

**Regra própria (o caso de uso mais útil):**

```yara
// work/acme/scripts/find_key.yar
rule acme_embedded_key : acme
{
    meta:
        author = "UnboxRE"
        evidence = "procura material de chave embutido"
    strings:
        $rsa = { 30 82 ?? ?? 02 01 00 02 82 }   // DER de RSAPublicKey
        $pem = "-----BEGIN " ascii
        $lic = "activation" ascii nocase
    condition:
        any of them
}
```

```bash
$ tools/yara/yara -r work/acme/scripts/find_key.yar work/acme/unpacked/
$ tools/yara/yara -r rules/ -s work/acme/unpacked/ | tee evidence/yara-hits.txt
```

**capa:**

```bash
$ tools/capa/capa -v work/acme/src/target.exe | tee evidence/capa-capabilities.txt
$ tools/capa/capa -j work/acme/src/target.exe > evidence/capa.json   # para pipeline
```

## Integração com o resto do setup

- **Depois do unpack** (x64dbg) e **depois do unblob** (firmware) — nunca antes.
- **Alimenta o Ghidra:** um hit do capa ("usa RC4") diz onde procurar no descompilador.
- **Regras próprias** são a forma de codificar um achado da análise para reuso em lote —
  você transforma "achei a chave" em "encontro a chave em qualquer versão futura".
- `evidence/*.json` do capa entra no pipeline.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| rodar em binário empacotado | zero hits, falso "limpo" | desempacote primeiro |
| regra muito específica | não casa na próxima versão | use expressões, não bytes exatos |
| regra muito genérica | falso positivo em massa | teste contra um corpus negativo |
| confundir capa com análise | conclusão superficial | capa é mapa, não destino |
| sintaxe yara-x vs yara | regra não compila | yara-x é compatível, mas valide |

## Referências

- `docs/06-workflows.md` Cenário 5 (uso em firmware)
- `docs/02-catalogo-ferramentas.md` §2 (a.4)

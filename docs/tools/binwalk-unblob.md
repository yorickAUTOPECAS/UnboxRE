# binwalk (+ unblob)
**Licença:** MIT (binwalk v3, em Rust) / MIT (unblob) ·
**Status:** a instalar · **Camada:** formatos (firmware)

Caminhos após bootstrap: `tools/binwalk/`, `tools/unblob/`

## O que faz

- **binwalk:** varre um arquivo e identifica assinaturas de arquivos embutidos
  (filesystems, kernels, compressão, headers). Faz **recon** muito bem.
- **unblob:** extração robusta de firmware. Lida com **containers aninhados**
  (squashfs dentro de gzip dentro de header proprietário), usa extractores dedicados e
  produz um **relatório** de o que extraiu. É o sucessor espiritual do `binwalk -e`.

## Quando usar

- **binwalk para recon** (o que tem aqui dentro?) — é rápido e legível.
- **unblob para extração** — quando você quer os arquivos de verdade.
- **Ordem recomendada:** `binwalk` para o mapa, `unblob` para extrair.
- Firmware de roteador, câmera, IoT, BIOS, imagem de disco, e **qualquer arquivo que
  contenha outro arquivo** (que é quase tudo).

## Quando NÃO usar

- **`binwalk -e` para firmware complexo.** Erra em containers aninhados e produz
  extração parcial sem te avisar direito. É o erro clássico: você analisa um filesystem
  incompleto e conclui coisas erradas.
- **Esperando entender o binário.** Extrair é o começo, não o fim. Os ELFs extraídos vão
  para o Ghidra.
- **Em arquivo com criptografia.** Se o container está cifrado, nada extrai — e o
  problema é outro (chave no bootloader, por exemplo).
- **Redistribuir firmware de terceiros.** Ver [08-higiene-e-seguranca.md](../08-higiene-e-seguranca.md).

## Instalação

```bash
$ pip install binwalk                    # v3 (Rust) via pacote; ou baixe o binário
$ pip install unblob                     # requer extractores do sistema:
$ sudo apt install squashfs-tools lz4 zstd p7zip-full cabextract e2fsprogs
```

O unblob precisa dos extractores nativos; sem eles, ele reporta "extractor not found" e
**pula** o container silenciosamente. Instale todos.

## Uso — receitas curtas

```bash
# Recon: o que tem aqui?
$ binwalk firmware.bin

# Extração robusta (com relatório)
$ unblob -e work/acme-fw/extracted/ -d work/acme-fw/reports/ firmware.bin

# Achou o filesystem raiz? Procure o que importa:
$ find work/acme-fw/extracted -type f -name '*passwd*' -o -name '*.pem' -o -name '*.key'
$ find work/acme-fw/extracted -type f -executable -exec file {} \; | grep ELF
```

**Roteiro de firmware (ordem que evita retrabalho):**

```
1. binwalk → mapa
2. unblob → extração + relatório
3. identifique a arquitetura dos ELFs (readelf -h → Machine)
4. strings nos binários de serviço (httpd, telnetd, upnpd)
5. Ghidra com o -processor correto (MIPS/ARM, nunca x86 por padrão)
6. procure: credenciais, chaves, URLs de update, comandos de debug
```

## Integração com o resto do setup

- **DIE** em cada ELF extraído (arquitetura, compilador, se está empacotado).
- **Ghidra** para análise estática com o processor correto.
- **Qiling** para rodar os binários sem o hardware.
- **YARA** para achar chaves/credenciais em massa.
- **REA** tem bridge de firmware que automatiza parte desse fluxo.

## Limites e armadilhas

| Armazilha | Efeito | Correção |
|---|---|---|
| extractor ausente | unblob pula em silêncio | instale squashfs/lz4/zstd/7z/cabextract |
| `binwalk -e` em container aninhado | extração parcial | use unblob |
| Ghidra em x86 por padrão | descompilação sem sentido | `readelf -h` → `-processor` explícito |
| analisar só o primeiro filesystem | conclusão incompleta | procure múltiplos rootfs |
| firmware redistribuído no repo | material de terceiro no Git | `work/` fica fora do Git |

## Referências

- `docs/06-workflows.md` Cenário 5 (firmware passo a passo)
- `docs/02-catalogo-ferramentas.md` §5 (d.5)

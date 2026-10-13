# mitmproxy (+ Wireshark/tshark, dumpcap)
**Licença:** MIT (mitmproxy) / GPL-2.0 (Wireshark) ·
**Status:** a instalar · **Camada:** rede e protocolo

Caminhos após bootstrap: `tools/mitmproxy/` (pip), Wireshark instalado pelo sistema

## O que faz

- **mitmproxy:** proxy HTTP/HTTPS interativo. Fica no meio, decripta (com sua CA), mostra
  request/response, permite modificar em trânsito e salvar tudo. É **a** ferramenta para
  reverter protocolo de aplicação.
- **Wireshark/tshark:** captura de pacotes em todos os níveis. Necessário quando o
  protocolo **não é HTTP** (binário sobre TCP/UDP).
- **dumpcap:** captura sem interface (para scripts).
- **`SSLKEYLOGFILE`:** faz aplicações que respeitam a variável (Chromium, Firefox, curl,
  Electron) escreverem as chaves TLS — o Wireshark então decripta a captura sem MITM.

## Quando usar

- **mitmproxy** quando é HTTP(S): APIs REST, GraphQL, telemetria, licenciamento online.
- **Wireshark + SSLKEYLOGFILE** quando você quer decriptar sem intermediar (menos
  invasivo, menos detectável) e a app respeita a variável.
- **Wireshark puro** para protocolo binário próprio (Cenário 6).
- **mitmproxy em modo reverse/transparent** para app que não aceita proxy explícito.

## Quando NÃO usar

- **Esperando ver tudo.** App com **certificate pinning** rejeita a CA do mitmproxy. Sem
  bypass de pinning (Frida), você não vê nada. O erro clássico é concluir "não usa rede"
  quando na verdade usa TLS pinado.
- **Contra tráfego de terceiros.** Ver [08-higiene-e-seguranca.md](../08-higiene-e-seguranca.md) §6.
- **Quando o protocolo é QUIC/HTTP3.** mitmproxy não intercepta QUIC de forma confiável;
  force HTTP/2 ou use Wireshark.
- **Deixando a CA instalada permanentemente.** Instale, analise, remova.

## Instalação

```bash
$ pip install mitmproxy                  # fornece mitmproxy, mitmweb, mitmdump
```

```powershell
PS> winget install WiresharkFoundation.Wireshark
```

## Uso — receitas curtas

**Proxy interativo (web UI):**

```bash
$ mitmweb --listen-port 8080 --save-stream-file work/acme/captures/flows.mitm
# configure o cliente para usar 127.0.0.1:8080 e confie na CA (http://mitm.it)
```

**Modo dump (scriptável):**

```bash
$ mitmdump -w work/acme/captures/flows.mitm -s work/acme/scripts/rewrite.py
```

**Decriptar sem MITM (SSLKEYLOGFILE):**

```bash
$ export SSLKEYLOGFILE="$UNBOXRE_WORK/acme/captures/tls.keys"
$ ./target.exe                            # rode o alvo com a var setada
$ dumpcap -i 1 -w work/acme/captures/traffic.pcapng
# Wireshark: Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
```

**Extrair framing de protocolo binário:**

```bash
$ tshark -r work/acme/captures/traffic.pcapng -T fields -e data | head -20
```

## Roteiro de reversão de protocolo

```
1. Capture (mitmproxy para HTTP, dumpcap para binário)
2. Identifique o FRAMING: magic, length, tipo, checksum
3. Escreva notes/protocol.md com o framing ANTES de escrever parser
4. Valide o framing contra 20+ mensagens, não 3
5. Só então escreva o parser
```

**Por quê nessa ordem:** pular para o parser produz um parser que funciona nos três
pacotes que você olhou e quebra no quarto.

## Integração com o resto do setup

- **Frida** para bypass de pinning (Cenário 4 + 6 combinados).
- **pwntools** quando o protocolo é binário e você quer automatizar a conversa.
- **REA** tem bridge de mitmproxy e de capturas de rede web.
- Capturas ficam em `work/<alvo>/captures/` — **fora do Git** (contêm credenciais).

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| certificate pinning | você não vê tráfego | bypass via Frida |
| CA esquecida instalada | risco permanente | remova ao fim da sessão |
| QUIC/HTTP3 | interceptação falha | force HTTP/2 |
| pcap com credenciais no Git | vazamento | `.gitignore` cobre `work/` |
| parser antes do framing | parser frágil | documente o framing primeiro |

## Referências

- `docs/06-workflows.md` Cenário 6 (protocolo passo a passo)
- `docs/02-catalogo-ferramentas.md` §8 (domínio g)

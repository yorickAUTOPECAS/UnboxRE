# pwndbg / gef / pwntools
**Licença:** GPL-3.0 (pwndbg, gef) / MIT (pwntools) ·
**Status:** a instalar (via WSL) · **Camada:** análise dinâmica

## O que faz

- **pwndbg / gef:** extensões de GDB que transformam o debugger em algo usável — mostra
  registradores, stack, heap, disassembly, contexto a cada parada.
- **pwntools:** biblioteca Python para interagir com processos e rede: `tube`,
  `ROP`, `ELF`, `checksec`, `cyclic`, `shellcraft`. É a linguagem franca do
  binary exploitation e uma excelente ferramenta de **automação de protocolo**.

## Quando usar

- **ELF Linux** (nativo, WSL, ou extraído de firmware que roda em Linux).
- **CTF / vulnerabilidade:** análise de heap, ROP, format string.
- **pwntools para automatizar protocolo:** `remote()` + `sendline`/`recvuntil` é a forma
  mais rápida de falar com um serviço proprietário e mapear o comportamento.
- **`checksec`** como primeiro comando em qualquer ELF.

## Quando NÃO usar

- **Windows PE.** Use x64dbg/WinDbg. GDB no Windows é sofrível.
- **Android/iOS.** Frida.
- **Ghidra para estrutura** — GDB não te dá call graph nem tipos.
- **Exploit em alvo de terceiros.** Ver [08-higiene-e-seguranca.md](../08-higiene-e-seguranca.md).

## Instalação (WSL)

```bash
$ sudo apt update && sudo apt install -y gdb python3-pip
$ git clone https://github.com/pwndbg/pwndbg ~/pwndbg && cd ~/pwndbg && ./setup.sh
$ pip install pwntools
```

O `setup.sh` escreve no `~/.gdbinit` — o `gdb` passa a carregar o pwndbg automaticamente.

## Uso — receitas curtas

```bash
$ checksec --file=./target              # RELRO, canary, NX, PIE
$ gdb ./target
pwndbg> start
pwndbg> vmmap                            # mapa de memória com permissões
pwndbg> telescope $rsp 20                # stack legível
pwndbg> heap                             # estado do heap
pwndbg> got                              # tabela GOT
```

**pwntools — automatizar um protocolo (o uso mais subestimado):**

```python
from pwn import *
context.log_level = "debug"

io = remote("127.0.0.1", 4444)           # alvo SEU
io.recvuntil(b"HELLO")
io.sendline(b"VERSION")
print(io.recvline())
# a partir daqui: brute-force de campos, teste de limites, mapa do protocolo
```

**Falando com um binário local:**

```python
io = process("./target")
io.sendline(b"admin\x00")
print(io.recvall())
```

## Integração com o resto do setup

- **WSL** é o ambiente: ELF Linux, GDB, pwntools. O Windows fica para PE.
- **Com o Ghidra:** GDB mostra valores reais; Ghidra mostra a estrutura. Endereços batem
  se você desativar ASLR (`set disable-randomization on`, padrão no gdb).
- **Com o mitmproxy:** pwntools para o protocolo binário, mitmproxy para o HTTP.
- **Com o REA:** o REA tem bridge de pwndbg/pwntools.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| GDB no Windows | experiência ruim | use WSL |
| ASLR ligado | endereços mudam entre runs | `set disable-randomization on` |
| pwndbg e gef no mesmo gdbinit | conflito | escolha um |
| `pwntools` contra alvo de terceiros | dados de terceiro no relatório | só alvo próprio/autorizado |
| GPL-3.0 dentro do repo MIT | conflito | chame por processo |

## Referências

- `docs/06-workflows.md` Cenário 10 (ELF/ARM)
- `docs/04-instalacao.md` (provisionamento do WSL)

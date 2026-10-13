# Unicorn + Qiling + Speakeasy
**Licença:** GPL-2.0 (Unicorn, Qiling) / Apache-2.0 (Speakeasy) ·
**Status:** a instalar · **Camada:** análise dinâmica

Caminhos após bootstrap: `tools/unicorn/`, `tools/qiling/`, `tools/speakeasy/`

## O que faz

Três níveis de emulação, do mais baixo ao mais alto:

| Ferramenta | Nível | O que emula |
|---|---|---|
| **Unicorn** | CPU | instruções de x86/ARM/MIPS/etc., memória e registradores. Nada de SO |
| **Qiling** | sistema | Unicorn + SO: syscalls, filesystem virtual, registry virtual |
| **Speakeasy** | aplicação | Windows API (kernel32/ntdll/user32) sobre emulação, foco em malware |

## Quando usar

- **Qiling para firmware/ELF de outra arquitetura.** Você emula um MIPS sem ter um
  roteador, e roda a função que interessa com entrada controlada.
- **Unicorn para uma função específica.** "O que esta rotina de decriptação retorna para
  esta entrada?" — emula 200 instruções em milissegundos, sem executar o binário.
- **Speakeasy para triagem de malware Windows.** Roda a amostra sem executá-la de
  verdade, com API virtualizada; excelente para ver comportamento sem risco.
- **Ambiente sem VM.** Emular é mais seguro que executar.

## Quando NÃO usar

- **Como substituto de execução real.** Emulação **não é** execução: código que depende
  de timing, hardware, GPU, TLS real, ou de comportamento não emulado simplesmente não
  funciona. Metade das falhas de emulação é isso, não bug do seu script.
- **Antes de saber o que emular.** Emular o binário inteiro do entry point raramente
  funciona. Emule **a função**, com estado preparado.
- **Quando você tem VM.** Se pode executar com segurança em snapshot, executar é mais
  rápido e mais verdadeiro.
- **Unicorn como debugger.** Não tem UI; é uma lib para script.

## Instalação

```bash
$ pip install unicorn qiling speakeasy-emulator
```

## Uso — receitas curtas

**Unicorn — emular uma função (esqueleto):**

```python
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RAX

BASE = 0x400000
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(BASE, 0x10000)
mu.mem_write(BASE + 0x1000, open("unpacked/func.bin","rb").read())
mu.mem_write(BASE + 0x2000, b"TESTE-LICENSE-0001\x00")
mu.reg_write(UC_X86_REG_RDI, BASE + 0x2000)     # 1º argumento
mu.emu_start(BASE + 0x1000, BASE + 0x1000 + 0x200)
print("retorno:", hex(mu.reg_read(UC_X86_REG_RAX)))
```

**Qiling — rodar um ELF de firmware:**

```python
from qiling import Qiling
ql = Qiling(["tools-out/firmware/bin/httpd"],
            rootfs="tools-out/firmware/squashfs-root")
ql.run()
```

**Speakeasy:**

```bash
$ speakeasy -t work/acme/src/target.exe -o evidence/speakeasy.json
```

## Integração com o resto do setup

- **Com o Ghidra:** extraia a função alvo (bytes + endereço) e emule com o Unicorn para
  obter o valor de retorno — isso responde em segundos o que levaria uma sessão de debug.
- **Com o unblob:** firmware extraído → Qiling roda os binários MIPS/ARM sem hardware.
- **Com o REA:** o REA tem bridge de emulação; a integração evita escrever o boilerplate.
- GPL-2.0 → **chame por processo** (script separado), não importe no seu código MIT
  ([03-licencas.md](../03-licencas.md)).

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| emular do entry point | trava em código não emulado | emule a função, com estado pronto |
| esperar fidelidade total | resultados errados silenciosos | valide contra execução real quando possível |
| mapear memória errada | segfault na emulação | confira o `ImageBase` real |
| importar Unicorn/Qiling no código MIT | conflito GPL | subprocesso |
| Qiling sem rootfs completo | syscalls falham | aponte o rootfs extraído inteiro |

## Referências

- `docs/06-workflows.md` Cenário 5 (firmware)
- `docs/02-catalogo-ferramentas.md` §3 (b.4)

# WinDbg + Time Travel Debugging (TTD)
**Licença:** [COMERCIAL] — grátis para uso, EULA Microsoft (não redistribuir) ·
**Status:** a instalar · **Camada:** análise dinâmica

## O que faz

O debugger oficial da Microsoft. Cobre o que o x64dbg não cobre:

- **Kernel debugging** (driver, boot, hipervisor) — com duas máquinas.
- **Time Travel Debugging (TTD):** grava a execução inteira do processo e permite
  **voltar no tempo**. Você roda uma vez, grava, e depois navega para frente e para trás
  no trace. É a ferramenta mais poderosa para entender um bug ou um fluxo complexo.
- Análise de **crash dump** (`.dmp`), `!analyze -v`.
- Extensões ricas: `!heap`, `!peb`, `!teb`, `!address`, `!dh`.

## Quando usar

- **TTD quando o problema é "como chegou aqui?".** Em vez de re-executar 40 vezes com
  breakpoints diferentes, grave uma vez e investigue para trás.
- **Kernel.** Não há alternativa de qualidade.
- **Crash dumps** de produção.
- Quando o alvo é instável sob debug — o TTD grava sem breakpoints, o que muda o
  comportamento muito menos que o x64dbg.

## Quando NÃO usar

- **Usermode rápido do dia a dia.** O x64dbg é mais leve e melhor integrado ao MCP.
- **macOS/Linux.** Fora de escopo.
- **Sem duas máquinas para kernel.** Não improvise; marque como gap.
- **TTD em processo enorme e longo.** O trace fica gigabyte. Use filtros e limite a
  gravação.

## Instalação

```powershell
PS> winget install Microsoft.WinDbg
# TTD: o pacote TTD (ttd.exe) vem com o WinDbg moderno; confirme com:
PS> ttd.exe --help
```

**Kernel — preparação do TARGET (só em VM descartável):**

```powershell
PS> bcdedit /debug on
PS> bcdedit /dbgsettings net hostip:<ip-do-host> port:50000 key:1.2.3.4
# reinicie o target; anote a key — ela vai no host
```

No host: `File → Attach to Kernel → Net`, mesma porta e key.

## Uso — receitas curtas

**Gravar um trace e reexecutar para trás:**

```bash
$ ttd.exe -out work/acme/traces -launch target.exe
# depois, no WinDbg: File → Open Trace File → work/acme/traces/*.run
```

```text
0:000> !tt 0                 // volta para o início do trace
0:000> g                     // avança; pode voltar com !tt <posição>
0:000> !tt 5:0               // salta para 50% do trace
0:000> dx @$curprocess.TTD   // objetos do TTD (chamadas, exceções)
```

**Comando mais valioso do TTD:** `!tt` combinado com breakpoint reverso — você pausa em
um ponto conhecido e **volta** para ver como chegou ali.

**Analisar crash dump:**

```text
0:000> !analyze -v
0:000> ~*k            // todos os threads, call stacks
0:000> !peb           // ambiente do processo
```

## Integração com o resto do setup

- **Complementa o x64dbg:** use TTD quando precisar de história; x64dbg quando precisar
  de interação rápida.
- **Kernel → o alvo é a VM**; o host é o WinDbg. Nunca a máquina de trabalho.
- Os traces alimentam `work/<alvo>/traces/` (fora do Git; são grandes).

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| kernel debugging sem VM descartável | risco alto | não faça |
| TTD em processo longo | trace de GBs | limite a gravação |
| esperar redistribuir | EULA proíbe | documente como `[COMERCIAL]` |
| usar no lugar do x64dbg | fluxo mais lento | escolha por pergunta, não por hábito |
| `bcdedit /debug on` na máquina de trabalho | alteração persistente | só em VM com snapshot |

## Referências

- `docs/02-catalogo-ferramentas.md` §3 (b.1)
- `docs/08-higiene-e-seguranca.md` §2 (kernel debugging)

# Frida
**Licença:** wxWindows Library Licence (LGPL-like, permissiva) · **Status:** a instalar ·
**Camada:** análise dinâmica

Caminho após bootstrap: `tools/frida/` (ou `pip install frida-tools`)

## O que faz

Instrumentação dinâmica **multi-plataforma** (Windows, macOS, Linux, Android, iOS):
injeta um runtime JavaScript no processo alvo e permite **hookar** funções, ler/escrever
memória, interceptar chamadas, substituir retornos — sem recompilar nada.

`frida-trace` gera os stubs automaticamente a partir dos imports. É a ferramenta que
transforma "vou ter que depurar isso" em "vou escrever 10 linhas de JS".

## Quando usar

- **Android/iOS.** É *a* ferramenta. O x64dbg não cobre mobile.
- **Hooking em app que reage mal a debugger.** Frida não é um debugger — não há
  breakpoint de hardware, então muitos anti-debug não disparam.
- **API tracing em alto nível:** "quais arquivos este processo abre?", "que URLs ele
  chama?", "o que retorna da função de validação?".
- **Bypass de root/jailbreak detection** em app que você tem direito de analisar.
- **Alterar retorno de uma função** para testar uma hipótese: `return true` no
  `isLicensed()`.

## Quando NÃO usar

- **Stepping fino.** Frida é hooking, não single-step. Para instrução por instrução, use
  x64dbg/WinDbg.
- **Código protegido com anti-Frida.** Apps modernos detectam o `frida-server` (nome do
  processo, portas, strings). Renomeie o server, use gadget mode — e espere detectar
  ainda assim.
- **Windows usermode profundo.** O x64dbg é melhor em contexto e integração.
- **Como primeira ferramenta.** Faça estático antes; hook sem mapa de classes é chute.

## Instalação

```bash
$ pip install frida-tools                # CLI (frida, frida-trace, frida-ps)
$ pip install frida                      # bindings Python
```

Android/root: suba o `frida-server` **da mesma versão** do client, com nome renomeado se
possível.

## Uso — receitas curtas

**Descobrir e anexar:**

```bash
$ frida-ps -U | grep acme                # processos no device USB
$ frida -U -f com.acme.app -l hook.js --no-pause
```

**Hook (receita: interceptar validação de licença em Android):**

```javascript
// work/acme-android/scripts/hook.js
Java.perform(function () {
  const L = Java.use('com.acme.license.LicenseManager');
  L.isValid.implementation = function (key) {
    const real = this.isValid(key);
    console.log('[+] isValid("' + key + '") -> ' + real);
    // return true;   // ⚠️ só em VM descartável e só para testar hipótese
    return real;
  };
});
```

**Hook nativo (biblioteca .so / DLL):**

```javascript
const f = Module.findExportByName('libacme.so', 'check_serial');
Interceptor.attach(f, {
  onEnter(args) { console.log('[+] arg:', args[0].readUtf8String()); },
  onLeave(ret) { console.log('[+] ret:', ret); }
});
```

**Trace automático de APIs:**

```bash
$ frida-trace -U -f com.acme.app -i "open*" -i "*connect*"
```

## Integração com o resto do setup

- **Depois do jadx** (Cenário 4): o estático dá o mapa de classes; o Frida confirma em
  runtime.
- **Com mitmproxy** (Cenário 6): pinning bypass no Frida + proxy MITM = tráfego em claro.
- **Com Ghidra:** Frida dá os valores reais; Ghidra dá a estrutura.
- `hook.js` por alvo vive em `work/<alvo>/scripts/` — é evidência reproduzível.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| versão client ≠ server | "unable to connect" | alinhe as versões |
| app detecta Frida | crash ou comportamento falso | renomeie o server, use gadget |
| SSL pinning | proxy MITM não vê nada | bypass de pinning + mitmproxy |
| hookar sem mapa estático | tentativa e erro infinito | faça jadx/Ghidra antes |
| deixar `return true` no script | você "prova" algo que não é verdade | comentar e registrar como hipótese |

## Referências

- `docs/06-workflows.md` Cenário 4 (Android)
- `docs/02-catalogo-ferramentas.md` §3 (b.2)

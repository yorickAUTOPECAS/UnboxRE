# jadx (+ apktool, baksmali, frida)
**Licença:** Apache-2.0 (jadx, apktool) · **Status:** a instalar ·
**Camada:** formatos (Android)

Caminho após bootstrap: `tools/jadx/`, `tools/apktool/`

## O que faz

**jadx** converte DEX/APK → **Java legível**, com navegação, busca e grafo de
referências. É o passo que transforma bytecode Android em algo que você (e uma IA) pode
ler.

Toolchain ao redor:

| Ferramenta | Papel | Quando |
|---|---|---|
| **jadx / jadx-gui** | DEX → Java | primeira coisa em qualquer APK |
| **apktool** | desmonta recursos, manifest, smali | quando o problema é layout/manifest/smali |
| **baksmali/smali** | monta/desmonta smali | patching de bytecode |
| **frida** | hook em runtime | confirmar o que o estático sugere |

## Quando usar

- **Sempre** como primeiro passo em APK (Cenário 4).
- `apktool` quando você precisa do `AndroidManifest.xml` **legível**, dos recursos, ou
  quer reconstruir o APK depois de patchar smali.
- **Frida depois** — nunca antes. Hook sem mapa de classes é tentativa e erro.

## Quando NÃO usar

- **Como fonte da verdade sobre comportamento.** O decompilador Java é **aproximado**:
  pode gerar código que compila mas não é exatamente o que a DEX faz (especialmente com
  `try/finally` complexo, lambdas, inline). Confirme o crítico em runtime.
- **Quando a lógica está em native libs.** `lib/arm64-v8a/*.so` não aparece no jadx —
  extraia e use o Ghidra (ARM64).
- **App com anti-tamper/integrity check.** Repackar com apktool quebra a assinatura e o
  app detecta. Aí é Frida, não repack.
- **Esperando código Kotlin limpo.** A decompilação de Kotlin é pior (coroutines, inline
  classes).

## Instalação

```powershell
PS> .\scripts\bootstrap-windows.ps1 -Profile mobile
# jadx: baixe o release (zip com jadx-gui.bat) para tools/jadx/
# apktool: baixe o jar + wrapper para tools/apktool/
```

Requer **Java** — o mesmo JDK do Ghidra serve.

## Uso — receitas curtas

```bash
# Java legível (o comando principal)
$ tools/jadx/bin/jadx -d work/acme-android/jadx/ app.apk

# Só o manifest, sem decompilar tudo (rápido)
$ tools/jadx/bin/jadx --no-src --single-class AndroidManifest app.apk

# Só recursos
$ tools/jadx/bin/jadx --no-res -d work/acme-android/jadx/ app.apk
```

```bash
# apktool: estrutura + smali (para repack)
$ tools/apktool/apktool.bat d -f app.apk -o work/acme-android/apktool/
$ tools/apktool/apktool.bat b work/acme-android/apktool/ -o work/acme-android/repacked.apk
```

**Onde procurar primeiro** (roteiro que economiza horas):

1. `AndroidManifest.xml` → permissões, `exported` components, services com `BOOT_COMPLETED`.
2. Pacotes com nome suspeito: `license`, `auth`, `billing`, `crypto`, `net`.
3. `BuildConfig` e constantes — chaves de API costumam estar embutidas.
4. Chamadas a `native` (`System.loadLibrary`) → sinaliza que a lógica está no `.so`.
5. `WebView` + `addJavascriptInterface` → superfície interessante.

## Integração com o resto do setup

- **Frida** confirma o que o jadx sugere ([frida.md](frida.md)).
- **mitmproxy** para o tráfego (Cenário 6), com bypass de SSL pinning via Frida.
- **Ghidra** para as `.so` nativas (ARM64 funciona bem).
- **REA** tem provider JEB e bridge Android — alternativa/complemento ao jadx.

## Limites e armadilhas

| Armadilha | Efeito | Correção |
|---|---|---|
| confiar 100% na decompilação | conclusão sutilmente errada | valide o crítico no Frida |
| esquecer as `.so` | análise pela metade | `find . -name '*.so'` e Ghidra |
| repackar app com integrity check | app não abre / detecta | use Frida |
| jadx sem memória suficiente | OOM em APK grande | aumente o heap do jadx |
| Kotlin | código feio e aproximado | leia o smali quando precisar de exatidão |

## Referências

- `docs/06-workflows.md` Cenário 4 (Android passo a passo)
- `docs/02-catalogo-ferramentas.md` §5 (d.4)

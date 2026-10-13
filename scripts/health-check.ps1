#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnóstico do ambiente UnboxRE. Somente leitura por padrão.

.DESCRIPTION
    Verifica, em ordem: layout do workspace, toolchain do host, ferramentas do núcleo,
    ferramentas do catálogo, variáveis de ambiente, servidores MCP e portas.

    Não instala nada. Não modifica nada, exceto com -Fix-Paths, que apenas CRIA
    diretórios ausentes e grava config/env/unboxre.env (nunca sobrescreve existente).

.PARAMETER Fix-Paths
    Cria os diretórios ausentes (plugins do x64dbg, work/, reports/, tools/) e grava
    config/env/unboxre.env a partir do .example, se ainda não existir.

.PARAMETER Json
    Emite o resultado como JSON (para pipeline/CI) em vez de tabela colorida.

.PARAMETER OutFile
    Com -Json, grava também em arquivo.

.EXAMPLE
    PS> .\scripts\health-check.ps1
    PS> .\scripts\health-check.ps1 -Fix-Paths
    PS> .\scripts\health-check.ps1 -Json -OutFile reports\health.json

.NOTES
    Exit code: 0 = sem FAIL · 1 = ao menos um FAIL · 2 = erro de execução do script.
#>
[CmdletBinding()]
param(
    # PowerShell não permite '-' no nome do parâmetro; o alias preserva a CLI
    # documentada ("-Fix-Paths").
    [Alias('Fix-Paths')]
    [switch]$FixPaths,
    [switch]$Json,
    [string]$OutFile
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$root = Get-RepoRoot

# Sem isto, um console em code page 437/850 transforma os acentos e setas da saída
# em mojibake. Só afeta a exibição; nada é escrito em disco.
if (-not $Json) {
    try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }
}

function Test-Layout {
    Write-Section '1. Layout do workspace'
    $expected = @(
        @{ Path = 'docs';        Why = 'documentação' },
        @{ Path = 'scripts';     Why = 'automação' },
        @{ Path = 'config';      Why = 'templates de config' },
        @{ Path = 'tools';       Why = 'ferramentas instaladas pelo bootstrap' },
        @{ Path = 'work';        Why = 'área de trabalho por alvo (fora do Git)' },
        @{ Path = 'reports';     Why = 'relatórios consolidados' },
        @{ Path = 'ghidra';      Why = 'núcleo: descompilador' },
        @{ Path = 'x64dbg';      Why = 'núcleo: debugger' },
        @{ Path = 'rea-main';    Why = 'núcleo: orquestrador' },
        @{ Path = 'x64dbg-mcp-server-main'; Why = 'núcleo: ponte MCP' }
    )
    foreach ($e in $expected) {
        $p = Join-Path $root $e.Path
        if (Test-PathExists $p) {
            Add-Result "layout:$($e.Path)" 'OK' $e.Why
        } else {
            $created = New-DirIfMissing -Path $p -Apply:$FixPaths
            if ($FixPaths -and $created) {
                Add-Result "layout:$($e.Path)" 'WARN' "ausente → criado agora ($($e.Why))"
            } else {
                Add-Result "layout:$($e.Path)" 'FAIL' "ausente: $($e.Why)" "crie o diretório ou rode -Fix-Paths"
            }
        }
    }

    # Pastas de plugins do x64dbg: sem elas o plugin MCP não carrega (gap G4)
    foreach ($arch in @('x64', 'x32')) {
        $plugins = Join-Path $root "x64dbg\release\$arch\plugins"
        $rel = "x64dbg/release/$arch/plugins"
        if (Test-PathExists $plugins) {
            Add-Result "plugins:$arch" 'OK' $rel
        } else {
            $created = New-DirIfMissing -Path $plugins -Apply:$FixPaths
            if ($FixPaths -and $created) {
                Add-Result "plugins:$arch" 'WARN' "ausente → criado agora"
            } else {
                Add-Result "plugins:$arch" 'WARN' "ausente: o x64dbg-MCP não carrega sem esta pasta" "rode -Fix-Paths"
            }
        }
    }
}

function Test-HostToolchain {
    Write-Section '2. Toolchain do host'

    # PowerShell
    $psv = $PSVersionTable.PSVersion
    if ($psv.Major -ge 5) {
        Add-Result 'ps:version' 'OK' "$psv (mínimo 5.1)"
    } else {
        Add-Result 'ps:version' 'FAIL' "$psv" 'instale PowerShell 5.1 ou 7+'
    }

    # Node/npm — necessários para REA e para os scripts .mjs deste toolkit
    foreach ($t in @(
        @{ N = 'node'; Args = @('-v'); Min = 18; Why = 'REA e scripts do toolkit' },
        @{ N = 'npm';  Args = @('-v'); Min = 9;  Why = 'instalação de deps do REA' },
        @{ N = 'git';  Args = @('--version'); Min = 0; Why = 'controle de versão e submódulos' }
    )) {
        $v = Get-CommandVersion -Name $t.N -VersionArgs $t.Args
        if ($null -eq $v) {
            Add-Result "host:$($t.N)" 'FAIL' "ausente ($($t.Why))" "instale $($t.N)"
        } else {
            Add-Result "host:$($t.N)" 'OK' "$v — $($t.Why)"
        }
    }

    # Java — exigido pelo Ghidra e pelo REA
    $javaHome = $env:JAVA_HOME
    $javaExe = Get-CommandVersion -Name 'java' -VersionArgs @('-version')
    if ($javaHome -and (Test-PathExists (Join-Path $javaHome 'bin'))) {
        Add-Result 'host:java' 'OK' "JAVA_HOME=$javaHome"
    } elseif ($javaExe) {
        Add-Result 'host:java' 'WARN' "java no PATH ($javaExe) mas JAVA_HOME não está definido" 'defina JAVA_HOME para o JDK do Ghidra'
    } else {
        Add-Result 'host:java' 'FAIL' 'nenhum JDK encontrado' 'instale um JDK compatível com o Ghidra'
    }

    # Ferramentas de build de componentes locais
    $buildTools = @(
        @{ N = 'zig';    Args = @('version'); Why = 'compila o x64dbg-MCP (mín. 0.14.0)' },
        @{ N = 'rustc';  Args = @('--version'); Why = 'algumas ferramentas do catálogo' },
        @{ N = 'cargo';  Args = @('--version'); Why = 'algumas ferramentas do catálogo' },
        @{ N = 'cmake';  Args = @('--version'); Why = 'builds nativos' },
        @{ N = 'python'; Args = @('--version'); Why = 'scripts e ferramentas Python' },
        @{ N = 'pip';    Args = @('--version'); Why = 'instalação de ferramentas Python' },
        @{ N = 'wsl';    Args = @('--status'); Why = 'ambiente Linux (ELF, pwndbg, unblob)' }
    )
    foreach ($t in $buildTools) {
        $v = Get-CommandVersion -Name $t.N -VersionArgs $t.Args
        if ($null -eq $v) {
            Add-Result "host:$($t.N)" 'WARN' "ausente ($($t.Why))" "instale quando precisar — ver docs/04-instalacao.md"
        } else {
            # 'wsl --status' devolve muitas linhas; resume
            $short = $v
            if ($short.Length -gt 90) { $short = $short.Substring(0, 87) + '...' }
            Add-Result "host:$($t.N)" 'OK' $short
        }
    }

    # Versão do Zig precisa ser >= 0.14.0 (build.zig.zon do MCP server)
    $zon = Join-Path $root 'x64dbg-mcp-server-main\build.zig.zon'
    if (Test-PathExists $zon) {
        $txt = Get-Content -LiteralPath $zon -Raw
        if ($txt -match 'minimum_zig_version\s*=\s*"([^"]+)"') {
            $need = $Matches[1]
            $have = Get-CommandVersion -Name 'zig' -VersionArgs @('version')
            if ($null -eq $have) {
                Add-Result 'mcp:zig-min' 'WARN' "requer Zig >= $need; zig ausente" ("instale Zig >= " + $need)
            } else {
                $haveClean = ($have -replace '[^0-9\.]', '').Trim('.')
                if ([version]$haveClean -ge [version]$need) {
                    Add-Result 'mcp:zig-min' 'OK' "zig $haveClean >= $need"
                } else {
                    Add-Result 'mcp:zig-min' 'FAIL' "zig $haveClean < $need" "atualize o Zig"
                }
            }
        }
    }
}

function Test-CoreTools {
    Write-Section '3. Ferramentas do núcleo'

    # Ghidra
    $ghidraDir = Join-Path $root 'ghidra\ghidra_12.1.4_PUBLIC'
    if (-not (Test-PathExists $ghidraDir)) {
        $cand = Get-ChildItem -Path (Join-Path $root 'ghidra') -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'ghidra_*_PUBLIC' } | Select-Object -First 1
        if ($cand) { $ghidraDir = $cand.FullName }
    }
    if (Test-PathExists $ghidraDir) {
        Add-Result 'ghidra:install' 'OK' $ghidraDir
        $headless = Join-Path $ghidraDir 'support\analyzeHeadless.bat'
        if (Test-PathExists $headless) {
            Add-Result 'ghidra:headless' 'OK' 'support/analyzeHeadless.bat'
        } else {
            Add-Result 'ghidra:headless' 'FAIL' 'analyzeHeadless.bat ausente' 'instalação do Ghidra incompleta'
        }
        $procDir = Join-Path $ghidraDir 'Ghidra\Processors'
        if (Test-PathExists $procDir) {
            $archs = @(Get-ChildItem $procDir -Directory -ErrorAction SilentlyContinue).Count
            Add-Result 'ghidra:processors' 'OK' "$archs arquiteturas disponíveis"
        }
        # GHIDRA_INSTALL_DIR: definido E apontando para uma instalação que existe.
        # Uma variável obsoleta é pior que nenhuma — o REA falha com erro obscuro.
        if ($env:GHIDRA_INSTALL_DIR) {
            if (Test-PathExists (Join-Path $env:GHIDRA_INSTALL_DIR 'support\analyzeHeadless.bat')) {
                Add-Result 'ghidra:env' 'OK' "GHIDRA_INSTALL_DIR=$($env:GHIDRA_INSTALL_DIR)"
            } else {
                Add-Result 'ghidra:env' 'WARN' "GHIDRA_INSTALL_DIR aponta para caminho inválido: $($env:GHIDRA_INSTALL_DIR)" "corrija para $ghidraDir em config/env/unboxre.env"
            }
        } else {
            Add-Result 'ghidra:env' 'WARN' 'GHIDRA_INSTALL_DIR não definido' 'defina para o REA encontrar o Ghidra (config/env/unboxre.env)'
        }
    } else {
        Add-Result 'ghidra:install' 'FAIL' 'diretório do Ghidra não encontrado' 'confira ghidra/'
    }

    # x64dbg
    $x64 = Join-Path $root 'x64dbg\release\x64\x64dbg.exe'
    $x32 = Join-Path $root 'x64dbg\release\x32\x32dbg.exe'
    $launcher = Join-Path $root 'x64dbg\release\x96dbg.exe'
    if ((Test-PathExists $x64) -and (Test-PathExists $x32)) {
        Add-Result 'x64dbg:binaries' 'OK' 'x64dbg.exe + x32dbg.exe presentes'
    } elseif (Test-PathExists $launcher) {
        Add-Result 'x64dbg:binaries' 'WARN' 'launcher presente, mas falta x64/x32' 'verifique a extração do x64dbg'
    } else {
        Add-Result 'x64dbg:binaries' 'FAIL' 'x64dbg não encontrado em x64dbg/release/' 'reinstale o snapshot'
    }

    # x64dbg-MCP plugin instalado?
    $pluginPaths = @(
        (Join-Path $root 'x64dbg\release\x64\plugins\x64dbg-MCP-Server.dp64'),
        (Join-Path $root 'x64dbg\release\x64\plugins\x64dbg_mcp_server.dp64')
    )
    $foundPlugin = $pluginPaths | Where-Object { Test-PathExists $_ } | Select-Object -First 1
    if ($foundPlugin) {
        Add-Result 'mcp:plugin' 'OK' (Split-Path -Leaf $foundPlugin)
    } else {
        Add-Result 'mcp:plugin' 'FAIL' 'plugin MCP não instalado no x64dbg' 'rode scripts/re-build.ps1 -Apply'
    }

    # x64dbg mcp_config.json (token gerado no 1º run)
    $cfg = Join-Path $root 'x64dbg\mcp_config.json'
    if (Test-PathExists $cfg) {
        $j = Get-JsonFileSafe -Path $cfg
        $port = '?'
        if ($j -and $j.PSObject.Properties.Name -contains 'port') { $port = $j.port }
        Add-Result 'mcp:config' 'OK' "x64dbg/mcp_config.json presente (porta $port)"
    } else {
        Add-Result 'mcp:config' 'WARN' 'token ainda não gerado' 'abra o x64dbg uma vez para o plugin gerar o token'
    }

    # REA
    $rea = Join-Path $root 'rea-main\scripts\rea.mjs'
    if (Test-PathExists $rea) {
        Add-Result 'rea:entry' 'OK' 'rea-main/scripts/rea.mjs'
        $reaNM = Join-Path $root 'rea-main\node_modules'
        if (Test-PathExists $reaNM) {
            Add-Result 'rea:deps' 'OK' 'node_modules presente'
        } else {
            Add-Result 'rea:deps' 'WARN' 'node_modules ausente (não construído)' 'rode scripts/re-build.ps1 -Apply'
        }
    } else {
        Add-Result 'rea:entry' 'FAIL' 'rea-main/scripts/rea.mjs ausente' 'confira o checkout do REA'
    }

    # MCP server compilado?
    $dist = Get-ChildItem -Path (Join-Path $root 'x64dbg-mcp-server-main') -Recurse -Include '*.dll','*.dp64','*.dp32' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dist) {
        Add-Result 'mcp:build' 'OK' ("build encontrado: " + $dist.Name)
    } else {
        Add-Result 'mcp:build' 'FAIL' 'nenhum artefato compilado' 'rode scripts/re-build.ps1 -Apply'
    }
}

function Test-CatalogTools {
    Write-Section '4. Ferramentas do catálogo (instaladas?)'
    $catalog = @(
        @{ N = 'r2';       Why = 'radare2 — CLI/scriptável, diff de binários' },
        @{ N = 'radiff2';  Why = 'radare2 — diff de binários' },
        @{ N = 'upx';      Why = 'unpack UPX' },
        @{ N = 'diec';     Why = 'Detect It Easy — identifica packer/compilador' },
        @{ N = 'yara';     Why = 'YARA — assinaturas' },
        @{ N = 'capa';     Why = 'capa — capacidades' },
        @{ N = 'frida';    Why = 'Frida — instrumentação' },
        @{ N = 'frida-trace'; Why = 'Frida — trace automático de APIs' },
        @{ N = 'jadx';     Why = 'jadx — DEX → Java' },
        @{ N = 'apktool';  Why = 'apktool — APK → smali/recursos' },
        @{ N = 'binwalk';  Why = 'binwalk — recon de firmware' },
        @{ N = 'unblob';   Why = 'unblob — extração de firmware' },
        @{ N = 'wasm2wat'; Why = 'wabt — WASM → WAT' },
        @{ N = 'mitmdump'; Why = 'mitmproxy — interceptação HTTP' },
        @{ N = 'tshark';   Why = 'Wireshark — captura/análise' },
        @{ N = 'dumpcap';  Why = 'Wireshark — captura sem UI' },
        @{ N = 'de4dot';   Why = 'de4dot — desofuscação .NET' },
        @{ N = 'qiling';   Why = 'Qiling — emulação de sistema' }
    )
    $present = 0
    foreach ($t in $catalog) {
        if (Test-CommandExists $t.N) {
            $present++
            Add-Result "catalog:$($t.N)" 'OK' $t.Why
        } else {
            Add-Result "catalog:$($t.N)" 'SKIP' "não instalada — $($t.Why)"
        }
    }
    Add-Result 'catalog:summary' 'INFO' "$present de $($catalog.Count) presentes no PATH" 'instale por perfil: scripts/bootstrap-windows.ps1 -Profile core|static|dynamic'

    # Ferramentas no diretório tools/ (instaladas pelo bootstrap, fora do PATH)
    $toolsDir = Join-Path $root 'tools'
    if (Test-PathExists $toolsDir) {
        $installed = @(Get-ChildItem $toolsDir -Directory -ErrorAction SilentlyContinue).Count
        Add-Result 'catalog:tools-dir' 'INFO' "$installed ferramenta(s) em tools/"
    }
}

function Test-Environment {
    Write-Section '5. Variáveis de ambiente'
    $envExample = Join-Path $root 'config\env\unboxre.env.example'
    $envReal = Join-Path $root 'config\env\unboxre.env'

    if (Test-PathExists $envReal) {
        Add-Result 'env:file' 'OK' 'config/env/unboxre.env presente'
    } elseif (Test-PathExists $envExample) {
        if ($FixPaths) {
            Copy-Item -LiteralPath $envExample -Destination $envReal -Force
            Add-Result 'env:file' 'WARN' 'criado config/env/unboxre.env a partir do .example' 'revise os caminhos'
        } else {
            Add-Result 'env:file' 'WARN' 'config/env/unboxre.env ausente' 'rode -Fix-Paths ou copie o .example'
        }
    } else {
        Add-Result 'env:file' 'FAIL' 'config/env/unboxre.env.example ausente' 'arquivo de referência do repositório faltando'
    }

    foreach ($v in @('UNBOXRE_WORKSPACE', 'UNBOXRE_WORK', 'GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'X64DBG_TOKEN')) {
        $val = [Environment]::GetEnvironmentVariable($v)
        if ($val) {
            $shown = $val
            if ($v -eq 'X64DBG_TOKEN') { $shown = '<definido — não exibido>' }
            # Variáveis que apontam para caminhos precisam apontar para algo real.
            if ($v -in @('UNBOXRE_WORKSPACE', 'UNBOXRE_WORK', 'GHIDRA_INSTALL_DIR', 'JAVA_HOME') -and -not (Test-PathExists $val)) {
                Add-Result "env:$v" 'WARN' "$shown — caminho não existe" 'corrija em config/env/unboxre.env'
            } else {
                Add-Result "env:$v" 'OK' $shown
            }
        } else {
            Add-Result "env:$v" 'INFO' 'não definida nesta sessão' 'carregue config/env/unboxre.env antes de trabalhar'
        }
    }
}

function Test-McpRuntime {
    Write-Section '6. Servidores MCP e portas'

    # x64dbg-MCP: vive dentro do x64dbg, então a porta só existe com ele aberto
    $port9094 = Test-TcpPort -Port 9094
    $port9095 = Test-TcpPort -Port 9095
    if ($port9094) {
        Add-Result 'mcp:port9094' 'OK' 'escutando — x64dbg-MCP (x64) no ar'
    } else {
        Add-Result 'mcp:port9094' 'SKIP' 'não escutando (x64dbg fechado?)' 'abra o x64dbg com o plugin instalado'
    }
    if ($port9095) {
        Add-Result 'mcp:port9095' 'OK' 'escutando — x64dbg-MCP (x32) no ar'
    } else {
        Add-Result 'mcp:port9095' 'SKIP' 'não escutando (x64dbg x32 fechado?)'
    }

    # Autenticação: se a porta está aberta, valide o token de fato
    if ($port9094) {
        $cfg = Get-JsonFileSafe -Path (Join-Path $root 'x64dbg\mcp_config.json')
        $token = $null
        if ($cfg -and ($cfg.PSObject.Properties.Name -contains 'authToken')) { $token = $cfg.authToken }
        if (-not $token) {
            Add-Result 'mcp:auth' 'WARN' 'porta aberta mas sem token no mcp_config.json' 'verifique a configuração do plugin'
        } else {
            try {
                $body = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
                $resp = Invoke-WebRequest -Uri 'http://127.0.0.1:9094/' -Method POST `
                    -Headers @{ Authorization = "Bearer $token" } `
                    -ContentType 'application/json' -Body $body -TimeoutSec 5 -UseBasicParsing
                if ($resp.StatusCode -eq 200) {
                    Add-Result 'mcp:auth' 'OK' "tools/list respondeu 200"
                } else {
                    Add-Result 'mcp:auth' 'WARN' "status $($resp.StatusCode)" 'confira token e versão do plugin'
                }
            } catch {
                Add-Result 'mcp:auth' 'FAIL' "falha ao chamar tools/list: $($_.Exception.Message)" 'valide o token em x64dbg/mcp_config.json'
            }
        }
    }

    # Conflito: dois x64dbg abertos costumam se atropelar
    $procs = Get-Process -Name 'x64dbg','x32dbg' -ErrorAction SilentlyContinue
    if ($procs) {
        $n = @($procs).Count
        if ($n -gt 1) {
            Add-Result 'mcp:procs' 'WARN' "$n instâncias de debugger abertas" 'feche as extras para evitar conflito de porta'
        } else {
            Add-Result 'mcp:procs' 'OK' '1 instância de debugger'
        }
    } else {
        Add-Result 'mcp:procs' 'SKIP' 'nenhum debugger em execução'
    }
}

function Test-Disk {
    Write-Section '7. Recursos'
    try {
        $drive = (Get-Item $root).PSDrive
        $free = Get-PSDrive -Name $drive.Name -ErrorAction SilentlyContinue
        if ($free) {
            $freeGB = [math]::Round($free.Free / 1GB, 1)
            if ($freeGB -lt 5) {
                Add-Result 'disk:free' 'WARN' "$freeGB GB livres" 'análise de RE consome muito espaço (dumps, traces)'
            } else {
                Add-Result 'disk:free' 'OK' "$freeGB GB livres"
            }
        }
    } catch {
        Add-Result 'disk:free' 'SKIP' 'não foi possível medir'
    }
}

# ─── Execução ───────────────────────────────────────────────────────────────

try {
    if (-not $Json) {
        Write-Banner 'UnboxRE — health check' "raiz: $root"
        Write-Host ("  modo: " + $(if ($FixPaths) { 'CORRETIVO (-Fix-Paths)' } else { 'somente leitura' })) -ForegroundColor DarkGray
    }

    Test-Layout
    Test-HostToolchain
    Test-CoreTools
    Test-CatalogTools
    Test-Environment
    Test-McpRuntime
    Test-Disk

    $results = Get-Results
    $fails = @($results | Where-Object { $_.Level -eq 'FAIL' })
    $warns = @($results | Where-Object { $_.Level -eq 'WARN' })
    $oks   = @($results | Where-Object { $_.Level -eq 'OK' })

    if ($Json) {
        $payload = [pscustomobject]@{
            generatedAt = (Get-Date).ToString('o')
            root        = $root
            summary     = [pscustomobject]@{ ok = $oks.Count; warn = $warns.Count; fail = $fails.Count }
            results     = $results
        }
        $jsonText = $payload | ConvertTo-Json -Depth 8
        Write-Output $jsonText
        if ($OutFile) {
            $dir = Split-Path -Parent $OutFile
            if ($dir -and -not (Test-PathExists $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Set-Content -LiteralPath $OutFile -Value $jsonText -Encoding UTF8
        }
    } else {
        foreach ($r in $results) {
            Write-Status $r.Level ("{0} — {1}" -f $r.Check, $r.Detail)
        }
        Write-Host ''
        Write-Host ('─' * 68) -ForegroundColor DarkCyan
        $summaryColor = 'Green'
        if ($fails.Count -gt 0) { $summaryColor = 'Red' }
        elseif ($warns.Count -gt 0) { $summaryColor = 'Yellow' }
        Write-Host ("  OK: {0}   WARN: {1}   FAIL: {2}" -f $oks.Count, $warns.Count, $fails.Count) -ForegroundColor $summaryColor

        if ($fails.Count -gt 0) {
            Write-Host ''
            Write-Host '  Como corrigir:' -ForegroundColor Yellow
            foreach ($f in $fails) {
                Write-Host ("    · {0}: {1}" -f $f.Check, $f.Fix) -ForegroundColor Yellow
            }
        }
        Write-Host ''
    }

    if ($fails.Count -gt 0) { exit 1 } else { exit 0 }
} catch {
    Write-Host ("ERRO no health-check: " + $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    exit 2
}

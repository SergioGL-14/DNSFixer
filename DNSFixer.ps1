# DNSFixer - GUI Diagnostico DNS con WPF
# Version 2.0 - Migracion completa a WPF con diseno moderno

using namespace System.Windows
using namespace System.Windows.Controls
using namespace System.Windows.Media

Set-StrictMode -Version Latest

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DNSFIXER - Sistema de Diagnostico DNS" -ForegroundColor Yellow
Write-Host "  Version 2.0 WPF" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Cargar ensamblados WPF
Add-Type -AssemblyName "PresentationCore"
Add-Type -AssemblyName "PresentationFramework"
Add-Type -AssemblyName "WindowsBase"

# ============================================================
#  INICIALIZACION GLOBAL
# ============================================================

if (-not (Get-Variable -Name Global:DNSFixerApp -Scope Global -ErrorAction SilentlyContinue)) {
    $Global:DNSFixerApp = [ordered]@{
        Root          = $PSScriptRoot
        Controls      = @{}
        Config        = @{
            ExpectedPrefixes = @("10.", "69.")
            PsExecPath       = "C:\temp\PsTools\psexec.exe"
        }
        CurrentEquipo = $env:COMPUTERNAME
        CurrentTab    = "Diagnostico"
        Colors        = @{
            Primary       = "#1976D2"
            Secondary     = "#B4B4B4"
            Success       = "#4CAF50"
            Warning       = "#FF9800"
            Error         = "#F44336"
            Info          = "#2196F3"
            Background    = "#FAFAFA"
            Text          = "#333333"
            TextSecondary = "#666666"
        }
    }
}
$App = $Global:DNSFixerApp

# ============================================================
#  FUNCION WRITE-LOG (WPF Adapted)
# ============================================================

function Write-Log {
    param(
        [string]$Message,
        [System.Windows.Controls.TextBox]$txtLog,
        [string]$LogType = "system"
    )

    if (-not $txtLog) { return }

    # Thread-safe: si no estamos en el hilo UI, re-invocamos
    if ($txtLog.Dispatcher.CheckAccess() -eq $false) {
        $txtLog.Dispatcher.Invoke([action]{
            Write-Log -Message $Message -txtLog $txtLog -LogType $LogType
        })
        return
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $prefix = switch ($LogType.ToLower()) {
        "warning" { "[!] " }
        "error"   { "[X] " }
        "ok"      { "[OK] " }
        "info"    { "[i] " }
        default   { "" }
    }

    $formatted = "[$timestamp] $prefix$Message`r`n"
    $txtLog.AppendText($formatted)
    $txtLog.ScrollToEnd()
}

# ============================================================
#  FUNCION PROCESSREMOTEOUTPUT
# ============================================================

function ProcessRemoteOutput {
    param (
        [string[]]$output,
        [System.Windows.Controls.TextBox]$txtLog
    )

    if (-not $output -or $output.Count -eq 0) { return }

    $cleanOutput = @($output | Where-Object {
        ($_ -notmatch "PsExec v") -and
        ($_ -notmatch "Sysinternals - www.sysinternals.com") -and
        ($_ -notmatch "Connecting to") -and
        ($_ -notmatch "Starting powershell.exe") -and
        ($_ -notmatch "Starting PSEXESVC") -and
        ($_ -notmatch "System.Management.Automation.RemoteException") -and
        ($_ -notmatch "powershell.exe exited") -and
        ($_ -ne "") -and ($_ -ne $null)
    })

    if ($cleanOutput.Count -eq 0) { return }

    $errorPatterns = @("error", "failed", "no se pudo", "fallo", "exception")
    $errorLines = @($cleanOutput | Where-Object {
        $line = $_
        ($errorPatterns | Where-Object { $line -match $_ }).Count -gt 0
    })

    if ($errorLines.Count -gt 0) {
        Write-Log "[ERROR] Salida remota:" $txtLog -LogType "error"
        foreach ($line in $errorLines) {
            Write-Log $line $txtLog -LogType "error"
        }
    }
}

# ============================================================
#  FUNCION INVOKE-LOCALORREMOTE
# ============================================================

function Invoke-LocalOrRemote {
    param (
        [string]$Equipo,
        [ScriptBlock]$Script
    )

    $localIPs = (Get-NetIPAddress -AddressFamily IPv4 |
                 Where-Object { $_.IPAddress -notlike "169.*" } |
                 Select-Object -ExpandProperty IPAddress)

    if ($Equipo -eq $env:COMPUTERNAME -or ($localIPs -contains $Equipo)) {
        return & $Script
    } else {
        $commandStr = $Script.ToString()
        $psexecPath = $App.Config.PsExecPath
        $remoteCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"${commandStr}`""
        $fullCommand = "$psexecPath \\$Equipo $remoteCommand"

        try {
            $output = cmd /c $fullCommand 2>&1
            $cleanOutput = $output | Where-Object {
                ($_ -notmatch "^PsExec v") -and
                ($_ -notmatch "^Copyright \(C\) 2001") -and
                ($_ -notmatch "^Connecting with PsExec") -and
                ($_ -notmatch "^Starting powershell.exe") -and
                ($_ -notmatch "^Starting PSEXESVC") -and
                ($_ -notmatch "^System.Management.Automation.RemoteException") -and
                ($_ -notmatch "^powershell.exe exited") -and
                ($_ -ne "") -and ($_ -ne $null)
            }
            return $cleanOutput
        } catch {
            throw "Error ejecutando comando remoto a traves de PsExec: $_"
        }
    }
}

# ============================================================
#  FUNCION DO-DIAGNOSTIC (Diagnostico Basico)
# ============================================================

function Do-Diagnostic {
    param(
        [string]$Equipo,
        [System.Windows.Controls.TextBox]$txtLog
    )

    $txtLog.Clear()
    Write-Log "[INFO] Iniciando diagnostico basico para $Equipo" $txtLog -LogType "info"

    $ips = @()
    try {
        $ips = @(Invoke-LocalOrRemote -Equipo $Equipo -Script {
            Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { $_.IPAddress -notlike "169.*" -and $_.IPAddress -ne "127.0.0.1" } |
                Select-Object -ExpandProperty IPAddress
        })
        Write-Log "[INFO] IPs activas del equipo: $($ips -join ', ')" $txtLog -LogType "info"
    } catch {
        Write-Log "[ERROR] No se pudieron obtener las IPs activas." $txtLog -LogType "error"
    }

    try {
        $dns = Invoke-LocalOrRemote -Equipo $Equipo -Script {
            (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses -join ", "
        }
        Write-Log "[INFO] DNS configurado: $dns" $txtLog -LogType "info"
    } catch {
        Write-Log "[WARNING] No se pudo obtener el servidor DNS." $txtLog -LogType "warning"
    }

    Write-Log "[INFO] Ejecutando nslookup al nombre: $Equipo" $txtLog -LogType "info"
    try {
        $resNombre = nslookup $Equipo 2>&1
        # Filtrar lineas de ruido de PowerShell
        $nslookupClean = $resNombre | Where-Object {
            $_.ToString() -notmatch 'System\.Management\.Automation\.RemoteException'
        }
        $nslookupOutput = ($nslookupClean -join "`r`n").Trim()
        Write-Log "[INFO] Resultado de nslookup:" $txtLog -LogType "info"
        Write-Log $nslookupOutput $txtLog

        # Saltar la primera linea "Address:" (es el servidor DNS, no el resultado)
        $addressLines = @($resNombre | Where-Object { $_ -match "Address:" })
        $resueltas = @()
        if ($addressLines.Count -gt 1) {
            $resueltas = @($addressLines | Select-Object -Skip 1 |
                         ForEach-Object { ($_ -split ":",2)[1].Trim() } |
                         Where-Object { $_ -match "^\d{1,3}(\.\d{1,3}){3}$" })
        }

        if ($resueltas.Count -eq 0) {
            Write-Log "[WARNING] El DNS no devolvio ninguna IP para '$Equipo'." $txtLog -LogType "warning"
        } else {
            Write-Log "[INFO] IPs que devuelve el DNS: $($resueltas -join ', ')" $txtLog -LogType "info"
        }

        foreach ($ip in $resueltas) {
            $coincide = $false
            foreach ($prefijo in $App.Config.ExpectedPrefixes) {
                if ($ip.StartsWith($prefijo)) {
                    $coincide = $true
                    break
                }
            }

            if (-not $coincide) {
                Write-Log "[ALERTA] El registro DNS ($ip) no corresponde a ninguna red esperada ($($App.Config.ExpectedPrefixes -join ', '))." $txtLog -LogType "warning"
            } else {
                Write-Log "[OK] El registro DNS ($ip) coincide con la red esperada." $txtLog -LogType "ok"
            }
        }

        foreach ($ip in $resueltas) {
            if ($ips -contains $ip) {
                Write-Log "[OK] IP $ip coincide con una IP del equipo." $txtLog -LogType "ok"
            } else {
                Write-Log "[ALERTA] IP $ip no coincide con ninguna IP activa del equipo." $txtLog -LogType "warning"
            }
        }
    } catch {
        Write-Log "[ERROR] No se pudo hacer nslookup al nombre." $txtLog -LogType "error"
    }

    Write-Log "[INFO] Comprobando registros PTR (reverso)" $txtLog -LogType "info"

    $ipsValidas = @($ips | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })

    foreach ($ip in $ipsValidas) {
        try {
            $ptrResult = Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop
            $ptrName = ($ptrResult | Where-Object { $_.NameHost } | Select-Object -First 1).NameHost
            if ($ptrName) {
                Write-Log "  PTR $ip -> $ptrName" $txtLog -LogType "ok"
            } else {
                Write-Log "  PTR $ip -> Sin registro inverso" $txtLog -LogType "warning"
            }
        } catch {
            Write-Log "  PTR $ip -> No encontrado ($($_.Exception.Message -replace '\r?\n',' '))" $txtLog -LogType "warning"
        }
    }

    Write-Log "[INFO] Obteniendo TTL del registro DNS (nombre)" $txtLog -LogType "info"
    try {
        $dnsResult = Resolve-DnsName -Name $Equipo -ErrorAction Stop
        foreach ($record in $dnsResult) {
            if ($record.QueryType -and $record.TTL -ne $null) {
                Write-Log "  Tipo: $($record.QueryType) | IP: $($record.IPAddress) | TTL: $($record.TTL)s" $txtLog -LogType "info"
            }
        }
    } catch {
        Write-Log "[WARNING] No se pudo obtener TTL con Resolve-DnsName: $($_.Exception.Message)" $txtLog -LogType "warning"
    }
}

# ============================================================
#  FUNCION DO-FIXSTALEDNS (Correccion DNS)
# ============================================================

function Do-FixStaleDNS {
    param(
        [string]$Equipo,
        [System.Windows.Controls.TextBox]$txtLog
    )

    try {
        $diagnosticoTemp = New-Object System.Windows.Controls.TextBox
        Do-Diagnostic -Equipo $Equipo -txtLog $diagnosticoTemp

        if ($diagnosticoTemp.Text -match "no corresponde a la red esperada") {
            $txtLog.Text = $diagnosticoTemp.Text
            Write-Log "[INFO] Se detecto registro DNS obsoleto. Aplicando correccion..." $txtLog -LogType "info"

            ipconfig /registerdns | Out-Null
            Write-Log "[OK] Registro DNS forzado con 'ipconfig /registerdns'." $txtLog -LogType "ok"
            Start-Sleep -Seconds 1

            try {
                Invoke-LocalOrRemote -Equipo $Equipo -Script { Clear-DnsClientCache } | Out-Null
                Write-Log "[OK] Cache DNS limpiada correctamente." $txtLog -LogType "ok"
            } catch {
                Write-Log "[ERROR] Fallo al limpiar la cache DNS." $txtLog -LogType "error"
            }

            Start-Sleep -Seconds 1
            Write-Log "[INFO] Re-ejecutando diagnostico para confirmar la correccion..." $txtLog -LogType "info"
            Do-Diagnostic -Equipo $Equipo -txtLog $txtLog
        } else {
            $txtLog.Text = $diagnosticoTemp.Text
            Write-Log "[INFO] No se detectaron incidencias. No se aplicaron cambios." $txtLog -LogType "info"
        }
    } catch {
        Write-Log "[ERROR] Fallo inesperado durante la correccion DNS: $_" $txtLog -LogType "error"
    }
}

# ============================================================
#  FUNCION DO-CLEANUP (Limpieza de Cache)
# ============================================================

function Do-Cleanup {
    param(
        [string]$Equipo,
        [System.Windows.Controls.TextBox]$txtLog
    )
    Write-Log "[INFO] Limpiando cache DNS..." $txtLog -LogType "info"
    try {
        Invoke-LocalOrRemote -Equipo $Equipo -Script { Clear-DnsClientCache } | Out-Null
        Write-Log "[OK] Cache DNS limpiada correctamente." $txtLog -LogType "ok"
    } catch {
        Write-Log "[ERROR] No se pudo limpiar la cache DNS: $_" $txtLog -LogType "error"
    }
}

# ============================================================
#  FUNCION DO-EXPORT (Exportar Log)
# ============================================================

function Do-Export {
    param(
        [string]$Equipo,
        [System.Windows.Controls.TextBox]$txtLog
    )
    if (-not $txtLog.Text) {
        [System.Windows.MessageBox]::Show("No hay resultados para exportar.", "Exportar log", "OK", "Warning")
        return
    }
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmm")
    $nombreArchivo = "DNSFixer_$Equipo" + "_$timestamp.txt"

    $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
    $saveDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    $saveDialog.FileName = $nombreArchivo
    $saveDialog.Filter = "Archivo de texto (*.txt)|*.txt"

    if ($saveDialog.ShowDialog()) {
        try {
            $txtLog.Text | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.MessageBox]::Show("Log exportado correctamente a:`n$($saveDialog.FileName)", "Exportacion completa", "OK", "Information")
        } catch {
            [System.Windows.MessageBox]::Show("Error al guardar el archivo:`n$_", "Error", "OK", "Error")
        }
    }
}

# ============================================================
#  FUNCION DO-ANALYSIS (Analisis Inteligente)
# ============================================================

function Do-Analysis {
    param(
        [string]$Equipo,
        [System.Windows.Controls.TextBox]$txtLog
    )
    if (-not $txtLog.Text) {
        Write-Log "[INFO] El log esta vacio. Ejecuta primero un diagnostico." $txtLog -LogType "info"
        return
    }
    $contenido = $txtLog.Text
    $resumen = "`r`n========================================`r`n  ANALISIS INTELIGENTE DEL LOG`r`n========================================`r`n"

    # Contar por tipo de mensaje real en el log
    $errores   = ([regex]::Matches($contenido, "\[ERROR\]|\[X\]")).Count
    $alertas   = ([regex]::Matches($contenido, "\[ALERTA\]|\[WARNING\]")).Count
    $oks       = ([regex]::Matches($contenido, "\[OK\]")).Count
    $noResuelve = $contenido -match "no devolvio ninguna IP"
    $noEncontrado = $contenido -match "Non-existent domain|no encuentra"
    $ptrOk     = ([regex]::Matches($contenido, "PTR .+ -> (?!No encontrado|Sin registro)")).Count
    $ptrFail   = ([regex]::Matches($contenido, "PTR .+ -> (No encontrado|Sin registro)")).Count

    # Resumen de conteo
    $resumen += "  Resultados OK: $oks | Alertas: $alertas | Errores: $errores`r`n"
    $resumen += "  PTR correctos: $ptrOk | PTR fallidos: $ptrFail`r`n`r`n"

    # Diagnostico contextual
    if ($errores -eq 0 -and $alertas -eq 0 -and $oks -gt 0 -and -not $noResuelve) {
        $resumen += "  [RESULTADO] Diagnostico LIMPIO`r`n"
        $resumen += "  Todo parece estar correctamente configurado.`r`n"
    } elseif ($noResuelve -or $noEncontrado) {
        $resumen += "  [RESULTADO] El DNS no resuelve el nombre del equipo`r`n"
        $resumen += "  Esto puede ser normal en redes domesticas sin DNS interno.`r`n"
        $resumen += "  En red corporativa, esto indica que el registro DNS falta o esta obsoleto.`r`n`r`n"
        $resumen += "  Recomendaciones:`r`n"
        $resumen += "    - Ejecuta 'Corregir DNS' para forzar ipconfig /registerdns`r`n"
        $resumen += "    - Verifica que el equipo tiene sufijo DNS correcto`r`n"
        $resumen += "    - Contacta al admin de DNS si persiste el problema`r`n"
        if ($ptrOk -gt 0) {
            $resumen += "`r`n  [NOTA] Los registros PTR (inverso) SI resuelven correctamente.`r`n"
            $resumen += "  Esto sugiere que el problema es solo el registro A (directo).`r`n"
        }
    } elseif ($errores -gt 0 -or $alertas -gt 0) {
        $resumen += "  [RESULTADO] Se detectaron inconsistencias`r`n"
        $resumen += "  Errores: $errores | Alertas: $alertas`r`n`r`n"
        $resumen += "  Recomendaciones:`r`n"
        $resumen += "    - Ejecuta la correccion DNS si no lo has hecho`r`n"
        $resumen += "    - Limpia la cache DNS`r`n"
        $resumen += "    - Verifica registros PTR si estan ausentes`r`n"
    } else {
        $resumen += "  [RESULTADO] Sin datos suficientes`r`n"
        $resumen += "  Ejecuta primero un diagnostico basico o avanzado.`r`n"
    }

    $resumen += "`r`n========================================"
    Write-Log $resumen $txtLog -LogType "info"
}

# ============================================================
#  FUNCION DO-ADVANCEDDIAGNOSTIC (Diagnostico Avanzado)
# ============================================================

function Do-AdvancedDiagnostic {
    param(
        [string]$Equipo,
        [System.Windows.Controls.TextBox]$txtLog
    )
    Write-Log "[INFO] Iniciando diagnostico avanzado para $Equipo" $txtLog -LogType "info"
    Do-Diagnostic -Equipo $Equipo -txtLog $txtLog
    try {
        $ipconfigOutput = Invoke-LocalOrRemote -Equipo $Equipo -Script { ipconfig /all }
        Write-Log "`r`n[INFO] Resultado de ipconfig /all:" $txtLog -LogType "info"
        Write-Log ($ipconfigOutput -join "`r`n") $txtLog
    } catch {
        Write-Log "[ERROR] Fallo la ejecucion de 'ipconfig /all'." $txtLog -LogType "error"
    }
    try {
        $netshOutput = Invoke-LocalOrRemote -Equipo $Equipo -Script { netsh interface ipv4 show config }
        Write-Log "`r`n[INFO] Configuracion IPv4:" $txtLog -LogType "info"
        Write-Log ($netshOutput -join "`r`n") $txtLog
    } catch {
        Write-Log "[ERROR] Fallo la ejecucion de 'netsh interface ipv4 show config'." $txtLog -LogType "error"
    }
    try {
        $adapterInfo = Invoke-LocalOrRemote -Equipo $Equipo -Script {
            Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } |
                Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress |
                Format-Table -AutoSize | Out-String
        }
        Write-Log "`r`n[INFO] Adaptadores activos:" $txtLog -LogType "info"
        Write-Log ($adapterInfo -join "`r`n") $txtLog
    } catch {
        Write-Log "[ERROR] Fallo la obtencion de informacion del adaptador." $txtLog -LogType "error"
    }
    Write-Log "`r`n[INFO] Diagnostico avanzado completado." $txtLog -LogType "ok"
}

# ============================================================
#  CREACION DE PANELES POR PESTANA
# ============================================================

function Create-ActionButton {
    param(
        [string]$Content,
        [string]$Icon,
        [string]$Color,
        [ScriptBlock]$OnClick
    )

    $btn = New-Object System.Windows.Controls.Button
    $btn.Content = "$Icon  $Content"
    $btn.Height = 40
    $btn.Margin = "0,0,0,10"
    $btn.Background = $Color
    $btn.Foreground = "White"
    $btn.BorderThickness = 0
    $btn.FontSize = 13
    $btn.FontWeight = "Bold"
    $btn.Cursor = "Hand"
    $btn.HorizontalContentAlignment = "Left"
    $btn.Padding = "15,0,0,0"

    # Efectos hover
    $btn.Add_MouseEnter({ $this.Opacity = 0.8 })
    $btn.Add_MouseLeave({ $this.Opacity = 1.0 })

    if ($OnClick) {
        $btn.Add_Click($OnClick)
    }

    return $btn
}

function Create-DiagnosticoPanel {
    $panel = New-Object System.Windows.Controls.StackPanel

    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = [char]::ConvertFromUtf32(0x1F50D) + " DIAGNOSTICO"
    $title.FontSize = 14
    $title.FontWeight = "Bold"
    $title.Foreground = $App.Colors.Text
    $title.Margin = "0,0,0,15"
    [void]$panel.Children.Add($title)

    $desc = New-Object System.Windows.Controls.TextBlock
    $desc.Text = "Realiza un analisis completo de la configuracion DNS del equipo."
    $desc.FontSize = 11
    $desc.Foreground = $App.Colors.TextSecondary
    $desc.TextWrapping = "Wrap"
    $desc.Margin = "0,0,0,15"
    [void]$panel.Children.Add($desc)

    $btnDiag = Create-ActionButton "Ejecutar Diagnostico" $([char]0x25B6) $App.Colors.Primary {
        $equipo = $Global:DNSFixerApp.Controls.TxtEquipo.Text.Trim()
        Do-Diagnostic -Equipo $equipo -txtLog $Global:DNSFixerApp.Controls.TxtLog
    }
    [void]$panel.Children.Add($btnDiag)

    $btnDiagAvanzado = Create-ActionButton "Diagnostico Avanzado" $([char]0x2699) $App.Colors.Info {
        $equipo = $Global:DNSFixerApp.Controls.TxtEquipo.Text.Trim()
        Do-AdvancedDiagnostic -Equipo $equipo -txtLog $Global:DNSFixerApp.Controls.TxtLog
    }
    [void]$panel.Children.Add($btnDiagAvanzado)

    return $panel
}

function Create-CorreccionPanel {
    $panel = New-Object System.Windows.Controls.StackPanel

    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = [char]::ConvertFromUtf32(0x1F527) + " CORRECCION"
    $title.FontSize = 14
    $title.FontWeight = "Bold"
    $title.Foreground = $App.Colors.Text
    $title.Margin = "0,0,0,15"
    [void]$panel.Children.Add($title)

    $desc = New-Object System.Windows.Controls.TextBlock
    $desc.Text = "Corrige automaticamente registros DNS obsoletos y limpia la cache."
    $desc.FontSize = 11
    $desc.Foreground = $App.Colors.TextSecondary
    $desc.TextWrapping = "Wrap"
    $desc.Margin = "0,0,0,15"
    [void]$panel.Children.Add($desc)

    $btnCorregir = Create-ActionButton "Corregir DNS" $([char]0x2692) $App.Colors.Success {
        $equipo = $Global:DNSFixerApp.Controls.TxtEquipo.Text.Trim()
        Do-FixStaleDNS -Equipo $equipo -txtLog $Global:DNSFixerApp.Controls.TxtLog
    }
    [void]$panel.Children.Add($btnCorregir)

    $btnLimpiar = Create-ActionButton "Limpiar Cache DNS" $([char]0x2672) $App.Colors.Warning {
        $equipo = $Global:DNSFixerApp.Controls.TxtEquipo.Text.Trim()
        Do-Cleanup -Equipo $equipo -txtLog $Global:DNSFixerApp.Controls.TxtLog
    }
    [void]$panel.Children.Add($btnLimpiar)

    return $panel
}

function Create-AnalisisPanel {
    $panel = New-Object System.Windows.Controls.StackPanel

    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = [char]::ConvertFromUtf32(0x1F4CA) + " ANALISIS"
    $title.FontSize = 14
    $title.FontWeight = "Bold"
    $title.Foreground = $App.Colors.Text
    $title.Margin = "0,0,0,15"
    [void]$panel.Children.Add($title)

    $desc = New-Object System.Windows.Controls.TextBlock
    $desc.Text = "Analiza los resultados del diagnostico y proporciona recomendaciones."
    $desc.FontSize = 11
    $desc.Foreground = $App.Colors.TextSecondary
    $desc.TextWrapping = "Wrap"
    $desc.Margin = "0,0,0,15"
    [void]$panel.Children.Add($desc)

    $btnAnalisis = Create-ActionButton "Analisis Inteligente" $([char]0x2605) $App.Colors.Info {
        $equipo = $Global:DNSFixerApp.Controls.TxtEquipo.Text.Trim()
        Do-Analysis -Equipo $equipo -txtLog $Global:DNSFixerApp.Controls.TxtLog
    }
    [void]$panel.Children.Add($btnAnalisis)

    $btnExportar = Create-ActionButton "Exportar Log" $([char]::ConvertFromUtf32(0x1F4BE)) $App.Colors.Secondary {
        $equipo = $Global:DNSFixerApp.Controls.TxtEquipo.Text.Trim()
        Do-Export -Equipo $equipo -txtLog $Global:DNSFixerApp.Controls.TxtLog
    }
    [void]$panel.Children.Add($btnExportar)

    return $panel
}

function Create-AvanzadoPanel {
    $panel = New-Object System.Windows.Controls.StackPanel

    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = [char]0x2699 + " CONFIGURACION"
    $title.FontSize = 14
    $title.FontWeight = "Bold"
    $title.Foreground = $App.Colors.Text
    $title.Margin = "0,0,0,15"
    [void]$panel.Children.Add($title)

    $desc = New-Object System.Windows.Controls.TextBlock
    $desc.Text = "Configura los parametros avanzados de DNSFixer."
    $desc.FontSize = 11
    $desc.Foreground = $App.Colors.TextSecondary
    $desc.TextWrapping = "Wrap"
    $desc.Margin = "0,0,0,15"
    [void]$panel.Children.Add($desc)

    # Prefijos IP esperados
    $lblPrefijos = New-Object System.Windows.Controls.TextBlock
    $lblPrefijos.Text = "Prefijos IP esperados:"
    $lblPrefijos.FontSize = 11
    $lblPrefijos.FontWeight = "Bold"
    $lblPrefijos.Margin = "0,10,0,5"
    [void]$panel.Children.Add($lblPrefijos)

    $txtPrefijos = New-Object System.Windows.Controls.TextBox
    $txtPrefijos.Text = ($App.Config.ExpectedPrefixes -join ", ")
    $txtPrefijos.Height = 28
    $txtPrefijos.Padding = "5"
    $txtPrefijos.Margin = "0,0,0,15"
    [void]$panel.Children.Add($txtPrefijos)
    $App.Controls.TxtPrefijos = $txtPrefijos

    $btnGuardarConfig = Create-ActionButton "Guardar Configuracion" $([char]0x2714) $App.Colors.Success {
        $newPrefixes = $Global:DNSFixerApp.Controls.TxtPrefijos.Text -split "," | ForEach-Object { $_.Trim() }
        $Global:DNSFixerApp.Config.ExpectedPrefixes = $newPrefixes
        [System.Windows.MessageBox]::Show("Configuracion guardada correctamente.", "Configuracion", "OK", "Information")
    }
    [void]$panel.Children.Add($btnGuardarConfig)

    return $panel
}

# ============================================================
#  FUNCION SWITCH-TAB
# ============================================================

function Switch-Tab {
    param([string]$TabName)

    $App.CurrentTab = $TabName

    # Actualizar colores de pestanas
    foreach ($key in @($App.Controls.TabButtons.Keys)) {
        if ($key -eq $TabName) {
            $App.Controls.TabButtons[$key].Background = $App.Colors.Primary
        } else {
            $App.Controls.TabButtons[$key].Background = $App.Colors.Secondary
        }
    }

    # Mostrar/ocultar paneles
    foreach ($key in @($App.Controls.ActionPanels.Keys)) {
        if ($key -eq $TabName) {
            $App.Controls.ActionPanels[$key].Visibility = [System.Windows.Visibility]::Visible
        } else {
            $App.Controls.ActionPanels[$key].Visibility = [System.Windows.Visibility]::Collapsed
        }
    }
}

# ============================================================
#  CREACION DE LA INTERFAZ GRAFICA (WPF)
# ============================================================

function Create-MainWindow {
    Write-Host "Creando ventana principal DNSFixer (WPF)..." -ForegroundColor Cyan

    # Crear ventana principal
    $window = New-Object System.Windows.Window
    $window.Title = "DNSFixer - Diagnostico y Correccion DNS v2.0"
    $window.Height = 850
    $window.Width = 1300
    $window.MinHeight = 700
    $window.MinWidth = 1100
    $window.Background = $App.Colors.Background
    $window.WindowStartupLocation = "CenterScreen"
    $window.WindowStyle = "SingleBorderWindow"
    $window.ResizeMode = "CanResize"

    # Grid principal con 3 filas
    $mainGrid = New-Object System.Windows.Controls.Grid
    $mainGrid.Background = $App.Colors.Background

    # Definir filas: Titulo (45px) + Pestanas (50px) + Contenido (*)
    $row0 = New-Object System.Windows.Controls.RowDefinition
    $row0.Height = 45
    $row1 = New-Object System.Windows.Controls.RowDefinition
    $row1.Height = 50
    $row2 = New-Object System.Windows.Controls.RowDefinition
    $row2.Height = "*"
    [void]$mainGrid.RowDefinitions.Add($row0)
    [void]$mainGrid.RowDefinitions.Add($row1)
    [void]$mainGrid.RowDefinitions.Add($row2)

    # ============================================================
    #  ROW 0: TITULO Y ENTRADA DE EQUIPO
    # ============================================================

    $headerGrid = New-Object System.Windows.Controls.Grid
    $headerGrid.Margin = "20,10,20,0"
    [System.Windows.Controls.Grid]::SetRow($headerGrid, 0)

    $colTitulo = New-Object System.Windows.Controls.ColumnDefinition
    $colTitulo.Width = "*"
    $colInput = New-Object System.Windows.Controls.ColumnDefinition
    $colInput.Width = "Auto"
    [void]$headerGrid.ColumnDefinitions.Add($colTitulo)
    [void]$headerGrid.ColumnDefinitions.Add($colInput)

    # Titulo
    $lblTitulo = New-Object System.Windows.Controls.TextBlock
    $lblTitulo.Text = "$([char]::ConvertFromUtf32(0x1F50D)) DNSFIXER"
    $lblTitulo.FontSize = 24
    $lblTitulo.FontWeight = "Bold"
    $lblTitulo.Foreground = $App.Colors.Primary
    $lblTitulo.VerticalAlignment = "Center"
    [System.Windows.Controls.Grid]::SetColumn($lblTitulo, 0)
    [void]$headerGrid.Children.Add($lblTitulo)

    # Panel de entrada de equipo
    $inputPanel = New-Object System.Windows.Controls.StackPanel
    $inputPanel.Orientation = "Horizontal"
    $inputPanel.VerticalAlignment = "Center"
    [System.Windows.Controls.Grid]::SetColumn($inputPanel, 1)

    $lblEquipo = New-Object System.Windows.Controls.TextBlock
    $lblEquipo.Text = "Equipo:"
    $lblEquipo.FontSize = 12
    $lblEquipo.Foreground = $App.Colors.Text
    $lblEquipo.VerticalAlignment = "Center"
    $lblEquipo.Margin = "0,0,10,0"
    [void]$inputPanel.Children.Add($lblEquipo)

    $txtEquipo = New-Object System.Windows.Controls.TextBox
    $txtEquipo.Text = $App.CurrentEquipo
    $txtEquipo.Width = 200
    $txtEquipo.Height = 28
    $txtEquipo.FontSize = 12
    $txtEquipo.Padding = "5,3,5,3"
    $txtEquipo.VerticalContentAlignment = "Center"
    [void]$inputPanel.Children.Add($txtEquipo)
    $App.Controls.TxtEquipo = $txtEquipo

    [void]$headerGrid.Children.Add($inputPanel)
    [void]$mainGrid.Children.Add($headerGrid)

    # ============================================================
    #  ROW 1: PESTANAS HORIZONTALES
    # ============================================================

    $tabPanel = New-Object System.Windows.Controls.StackPanel
    $tabPanel.Orientation = "Horizontal"
    $tabPanel.Background = $App.Colors.Background
    $tabPanel.Margin = "20,0,20,0"
    [System.Windows.Controls.Grid]::SetRow($tabPanel, 1)

    # Crear pestanas
    $tabData = @(
        @{ Content = "Diagnostico";   Icon = [char]::ConvertFromUtf32(0x1F50D); Tag = "Diagnostico" }
        @{ Content = "Correccion";    Icon = [char]::ConvertFromUtf32(0x1F527); Tag = "Correccion" }
        @{ Content = "Analisis";      Icon = [char]::ConvertFromUtf32(0x1F4CA); Tag = "Analisis" }
        @{ Content = "Configuracion"; Icon = [char]0x2699;  Tag = "Avanzado" }
    )

    $App.Controls.TabButtons = @{}

    foreach ($tab in $tabData) {
        $btn = New-Object System.Windows.Controls.Button
        $btn.Content = "$($tab.Icon)  $($tab.Content)"
        $btn.Width = 200
        $btn.Height = 40
        $btn.Margin = "0,0,5,0"
        $btn.Foreground = "White"
        $btn.BorderThickness = 0
        $btn.FontSize = 12
        $btn.FontWeight = "Bold"
        $btn.Cursor = "Hand"
        $btn.Tag = $tab.Tag

        if ($tab.Tag -eq $App.CurrentTab) {
            $btn.Background = $App.Colors.Primary
        } else {
            $btn.Background = $App.Colors.Secondary
        }

        $btn.Add_MouseEnter({
            if ($this.Tag -ne $Global:DNSFixerApp.CurrentTab) {
                $this.Opacity = 0.8
            }
        })
        $btn.Add_MouseLeave({
            $this.Opacity = 1.0
        })
        $btn.Add_Click({
            Switch-Tab -TabName $this.Tag
        })

        [void]$tabPanel.Children.Add($btn)
        $App.Controls.TabButtons[$tab.Tag] = $btn
    }

    [void]$mainGrid.Children.Add($tabPanel)

    # ============================================================
    #  ROW 2: CONTENIDO (Grid con 2 columnas)
    # ============================================================

    $contentGrid = New-Object System.Windows.Controls.Grid
    $contentGrid.Margin = "20,10,20,20"
    [System.Windows.Controls.Grid]::SetRow($contentGrid, 2)

    # Columnas: Panel de acciones (350px) + Log (*)
    $colPanel = New-Object System.Windows.Controls.ColumnDefinition
    $colPanel.Width = 350
    $colLog = New-Object System.Windows.Controls.ColumnDefinition
    $colLog.Width = "*"
    [void]$contentGrid.ColumnDefinitions.Add($colPanel)
    [void]$contentGrid.ColumnDefinitions.Add($colLog)

    # Panel izquierdo con acciones
    $actionsBorder = New-Object System.Windows.Controls.Border
    $actionsBorder.Background = "White"
    $actionsBorder.BorderBrush = "#DDDDDD"
    $actionsBorder.BorderThickness = 1
    $actionsBorder.CornerRadius = 5
    $actionsBorder.Padding = 20
    $actionsBorder.Margin = "0,0,10,0"
    [System.Windows.Controls.Grid]::SetColumn($actionsBorder, 0)

    $actionsStack = New-Object System.Windows.Controls.StackPanel
    $actionsStack.Orientation = "Vertical"
    $actionsBorder.Child = $actionsStack

    # Titulo del panel
    $titlePanel = New-Object System.Windows.Controls.TextBlock
    $titlePanel.Text = "ACCIONES"
    $titlePanel.FontSize = 16
    $titlePanel.FontWeight = "Bold"
    $titlePanel.Foreground = $App.Colors.Text
    $titlePanel.Margin = "0,0,0,20"
    [void]$actionsStack.Children.Add($titlePanel)

    # Contenedor de paneles dinamicos
    $App.Controls.ActionPanels = @{}

    # Panel Diagnostico
    $panelDiagnostico = Create-DiagnosticoPanel
    [void]$actionsStack.Children.Add($panelDiagnostico)
    $App.Controls.ActionPanels["Diagnostico"] = $panelDiagnostico

    # Panel Correccion
    $panelCorreccion = Create-CorreccionPanel
    $panelCorreccion.Visibility = [System.Windows.Visibility]::Collapsed
    [void]$actionsStack.Children.Add($panelCorreccion)
    $App.Controls.ActionPanels["Correccion"] = $panelCorreccion

    # Panel Analisis
    $panelAnalisis = Create-AnalisisPanel
    $panelAnalisis.Visibility = [System.Windows.Visibility]::Collapsed
    [void]$actionsStack.Children.Add($panelAnalisis)
    $App.Controls.ActionPanels["Analisis"] = $panelAnalisis

    # Panel Avanzado
    $panelAvanzado = Create-AvanzadoPanel
    $panelAvanzado.Visibility = [System.Windows.Visibility]::Collapsed
    [void]$actionsStack.Children.Add($panelAvanzado)
    $App.Controls.ActionPanels["Avanzado"] = $panelAvanzado

    [void]$contentGrid.Children.Add($actionsBorder)

    # Panel derecho con log
    $logBorder = New-Object System.Windows.Controls.Border
    $logBorder.Background = "White"
    $logBorder.BorderBrush = "#DDDDDD"
    $logBorder.BorderThickness = 1
    $logBorder.CornerRadius = 5
    $logBorder.Padding = 15
    [System.Windows.Controls.Grid]::SetColumn($logBorder, 1)

    $logGrid = New-Object System.Windows.Controls.Grid
    $logRow0 = New-Object System.Windows.Controls.RowDefinition
    $logRow0.Height = "Auto"
    $logRow1 = New-Object System.Windows.Controls.RowDefinition
    $logRow1.Height = "*"
    [void]$logGrid.RowDefinitions.Add($logRow0)
    [void]$logGrid.RowDefinitions.Add($logRow1)

    # Titulo del log
    $logTitle = New-Object System.Windows.Controls.TextBlock
    $logTitle.Text = "$([char]::ConvertFromUtf32(0x1F4CB)) REGISTRO DE ACTIVIDAD"
    $logTitle.FontSize = 14
    $logTitle.FontWeight = "Bold"
    $logTitle.Foreground = $App.Colors.Text
    $logTitle.Margin = "0,0,0,10"
    [System.Windows.Controls.Grid]::SetRow($logTitle, 0)
    [void]$logGrid.Children.Add($logTitle)

    # ScrollViewer con TextBox para el log
    $scrollViewer = New-Object System.Windows.Controls.ScrollViewer
    $scrollViewer.VerticalScrollBarVisibility = "Auto"
    $scrollViewer.HorizontalScrollBarVisibility = "Auto"
    [System.Windows.Controls.Grid]::SetRow($scrollViewer, 1)

    $txtLog = New-Object System.Windows.Controls.TextBox
    $txtLog.IsReadOnly = $true
    $txtLog.TextWrapping = "Wrap"
    $txtLog.AcceptsReturn = $true
    $txtLog.VerticalScrollBarVisibility = "Auto"
    $txtLog.HorizontalScrollBarVisibility = "Auto"
    $txtLog.FontFamily = "Consolas"
    $txtLog.FontSize = 11
    $txtLog.Foreground = $App.Colors.Text
    $txtLog.Background = "#FAFAFA"
    $txtLog.BorderThickness = 0
    $txtLog.Padding = "10"
    $scrollViewer.Content = $txtLog
    $App.Controls.TxtLog = $txtLog

    [void]$logGrid.Children.Add($scrollViewer)
    $logBorder.Child = $logGrid
    [void]$contentGrid.Children.Add($logBorder)

    [void]$mainGrid.Children.Add($contentGrid)
    $window.Content = $mainGrid

    $App.Controls.MainWindow = $window
    return $window
}

# ============================================================
#  INICIALIZAR Y MOSTRAR VENTANA
# ============================================================

$window = Create-MainWindow
Write-Host "[OK] Ventana creada exitosamente" -ForegroundColor Green
Write-Host "[>>] Iniciando aplicacion..." -ForegroundColor Cyan
Write-Host ""

[void]$window.ShowDialog()

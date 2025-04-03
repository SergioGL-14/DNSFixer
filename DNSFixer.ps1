# DNSFixer - GUI Diagnóstico Inicial DNS
# ===============================
#_____  _   _  _____ ______ _______   ________ _____  
#|  __ \| \ | |/ ____|  ____|_   _\ \ / /  ____|  __ \ 
#| |  | |  \| | (___ | |__    | |  \ V /| |__  | |__) |
#| |  | | . ` |\___ \|  __|   | |   > < |  __| |  _  / 
#| |__| | |\  |____) | |     _| |_ / . \| |____| | \ \ 
#|_____/|_| \_|_____/|_|    |_____/_/ \_\______|_|  \_\
                                                      
#=================================================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Variable para definir el prefijo IP esperado
$expectedPrefix = "10."

# =====================================================================
# Función Write-Log: Añade un mensaje al log con timestamp y estilo
function Write-Log {
    param(
        [string]$Message,
        [System.Windows.Forms.RichTextBox]$txtLog,
        [string]$LogType = "system"  # valores posibles: system, warning, ok, user
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $formatted = "[$timestamp] $Message`r`n"
    
    $styles = @{
        "warning" = @{ Color = "Red";   Bold = $false }
        "ok"      = @{ Color = "Green"; Bold = $false }
        "user"    = @{ Color = "Purple";Bold = $true }
        "system"  = @{ Color = $txtLog.ForeColor.Name; Bold = $false }
    }
    
    $chosen = $styles[$LogType.ToLower()]
    if (-not $chosen) { $chosen = $styles["system"] }
    
    $txtLog.SelectionStart  = $txtLog.TextLength
    $txtLog.SelectionLength = 0
    $txtLog.SelectionColor  = [System.Drawing.Color]::FromName($chosen.Color)
    
    $fontStyle = if ($chosen.Bold) { [System.Drawing.FontStyle]::Bold } else { [System.Drawing.FontStyle]::Regular }
    $txtLog.SelectionFont = New-Object System.Drawing.Font($txtLog.Font, $fontStyle)
    
    $txtLog.AppendText($formatted)
    $txtLog.SelectionColor = $txtLog.ForeColor
}

# =====================================================================
# Función ProcessRemoteOutput: Filtra la salida remota para mostrar únicamente errores
function ProcessRemoteOutput {
    param (
        [string[]]$output,
        [System.Windows.Forms.RichTextBox]$txtLog
    )
    # Definir patrones de error (ajusta según convenga)
    $errorPatterns = @("error", "failed", "no se pudo", "falló", "exception")
    $errorLines = $output | Where-Object {
         $line = $_
         $isError = $false
         foreach ($pattern in $errorPatterns) {
             if ($line -match $pattern) { $isError = $true }
         }
         return $isError
    }
    if ($errorLines.Count -gt 0) {
        Write-Log "[ERROR] Salida remota:" $txtLog -LogType "warning"
        foreach ($line in $errorLines) {
            Write-Log $line $txtLog -LogType "warning"
        }
    }
}

# =====================================================================
# Función Invoke-LocalOrRemote: Ejecuta localmente o mediante PsExec (remoto)
function Invoke-LocalOrRemote {
    param (
        [string]$Equipo,
        [ScriptBlock]$Script
    )
    # Obtener las IP locales del equipo
    $localIPs = (Get-NetIPAddress -AddressFamily IPv4 |
                 Where-Object { $_.IPAddress -notlike "169.*" } |
                 Select-Object -ExpandProperty IPAddress)
    if ($Equipo -eq $env:COMPUTERNAME -or ($localIPs -contains $Equipo)) {
        return & $Script
    } else {
        # Convertir el ScriptBlock a cadena
        $commandStr = $Script.ToString()
        # Ruta de PsExec (se asume que está en PATH; si no, ajustar la ruta)
        $psexecPath = "C:\temp\PsTools\psexec.exe"
        # Construir el comando remoto: se invoca PowerShell en el host remoto
        $remoteCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"${commandStr}`""
        $fullCommand = "$psexecPath \\$Equipo $remoteCommand"
        try {
            $output = cmd /c $fullCommand 2>&1
            return $output
        } catch {
            throw "Error ejecutando comando remoto a través de PsExec: $_"
        }
    }
}

# =====================================================================
# Función: Diagnóstico DNS (Básico)
function Do-Diagnostic {
    param(
        [string]$Equipo,
        [System.Windows.Forms.RichTextBox]$txtLog
    )
    $txtLog.Clear()
    Write-Log "[INFO] Iniciando diagnóstico básico para $Equipo" $txtLog

    try {
        $ips = Invoke-LocalOrRemote -Equipo $Equipo -Script {
            $ipv4 = Get-NetIPAddress -AddressFamily IPv4 |
                    Where-Object { $_.IPAddress -notlike "169.*" } |
                    Select-Object -ExpandProperty IPAddress
            $ipv6 = Get-NetIPAddress -AddressFamily IPv6 |
                    Select-Object -ExpandProperty IPAddress
            return ,$ipv4,$ipv6
        }
        Write-Log "[INFO] IPs activas del equipo: $($ips -join ', ')" $txtLog
    } catch {
        Write-Log "[ERROR] No se pudieron obtener las IPs activas." $txtLog -LogType "warning"
    }

    try {
        $dns = Invoke-LocalOrRemote -Equipo $Equipo -Script {
            (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses -join ", "
        }
        Write-Log "[INFO] DNS configurado: $dns" $txtLog
    } catch {
        Write-Log "[WARNING] No se pudo obtener el servidor DNS." $txtLog -LogType "warning"
    }

    Write-Log "[INFO] Ejecutando nslookup al nombre: $Equipo" $txtLog
    try {
        $resNombre = nslookup $Equipo 2>&1
        $nslookupOutput = $resNombre -join "`r`n"
        Write-Log "[INFO] Resultado de nslookup:" $txtLog
        $txtLog.AppendText($nslookupOutput + "`r`n")
        $resueltas = $resNombre |
                     Where-Object { $_ -match "Address:" } |
                     ForEach-Object { ($_ -split ":")[1].Trim() } |
                     Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
        Write-Log "[INFO] IPs que devuelve el DNS: $($resueltas -join ', ')" $txtLog

        foreach ($ip in $resueltas) {
            if (-not $ip.StartsWith($expectedPrefix)) {
                Write-Log "[ALERTA] El registro DNS ($ip) no corresponde a la red esperada ($expectedPrefix)." $txtLog -LogType "warning"
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
        Write-Log "[ERROR] No se pudo hacer nslookup al nombre." $txtLog -LogType "warning"
    }

    Write-Log "[INFO] Comprobando registros PTR (reverso)" $txtLog
    foreach ($ip in $ips) {
        try {
            $resIP = nslookup $ip 2>&1
            $ptrOutput = $resIP -join "`r`n"
            Write-Log "↪️ $ip → $ptrOutput" $txtLog
        } catch {
            Write-Log "[ERROR] Falló el PTR para $ip" $txtLog -LogType "warning"
        }
    }

    Write-Log "[INFO] Obteniendo TTL del registro DNS (nombre)" $txtLog
    try {
        $ttlCheck = nslookup -debug $Equipo 2>&1 |
                    Where-Object { $_ -match "TTL" }
        if ($ttlCheck) {
            Write-Log ([string]::Join("`r`n", $ttlCheck)) $txtLog
        } else {
            Write-Log "[WARNING] No se pudo extraer TTL." $txtLog -LogType "warning"
        }
    } catch {
        Write-Log "[ERROR] Error al intentar obtener TTL." $txtLog -LogType "warning"
    }
}

# =====================================================================
# Función: Resolver incidencia (corrección extendida)
function Do-FixStaleDNS {
    param(
        [string]$Equipo,
        [System.Windows.Forms.RichTextBox]$txtLog,
        [System.Windows.Forms.Button]$btnDiagnostico,
        [System.Windows.Forms.Button]$btnLimpiar
    )
    Write-Log "[INFO] Detectando incidencia en el registro DNS..." $txtLog
    Do-Diagnostic -Equipo $Equipo -txtLog $txtLog
    if ($txtLog.Text -match "no corresponde a la red esperada") {
         Write-Log "[INFO] Incidencia detectada. Ejecutando corrección y limpieza..." $txtLog -LogType "user"
         ipconfig /registerdns | Out-Null
         Write-Log "[OK] Registro DNS forzado con 'ipconfig /registerdns'." $txtLog -LogType "ok"
         Start-Sleep -Seconds 1
         try {
             $clearOutput = Invoke-LocalOrRemote -Equipo $Equipo -Script { Clear-DnsClientCache }
             ProcessRemoteOutput -output $clearOutput -txtLog $txtLog
             Write-Log "[OK] Caché DNS limpiada correctamente." $txtLog -LogType "ok"
         } catch {
             Write-Log "[ERROR] Falló al limpiar la caché DNS." $txtLog -LogType "warning"
         }
         Start-Sleep -Seconds 1
         Write-Log "[INFO] Re-ejecutando diagnóstico para confirmar la corrección..." $txtLog -LogType "user"
         Do-Diagnostic -Equipo $Equipo -txtLog $txtLog
    } else {
         Write-Log "[INFO] No se detectó incidencia de registro DNS obsoleto. No se requiere acción adicional." $txtLog
    }
}

# =====================================================================
# Función: Limpiar caché DNS
function Do-Cleanup {
    param(
        [string]$Equipo,
        [System.Windows.Forms.RichTextBox]$txtLog
    )
    Write-Log "[INFO] Limpiando caché DNS..." $txtLog
    try {
        $cleanupOutput = Invoke-LocalOrRemote -Equipo $Equipo -Script { Clear-DnsClientCache }
        ProcessRemoteOutput -output $cleanupOutput -txtLog $txtLog
        Write-Log "[OK] Caché DNS limpiada correctamente." $txtLog -LogType "ok"
    } catch {
        Write-Log "[ERROR] No se pudo limpiar la caché DNS: $_" $txtLog -LogType "warning"
    }
}

# =====================================================================
# Función: Exportar log a archivo TXT
function Do-Export {
    param(
        [string]$Equipo,
        [System.Windows.Forms.RichTextBox]$txtLog
    )
    if (-not $txtLog.Text) {
        [System.Windows.Forms.MessageBox]::Show("No hay resultados para exportar.", "Exportar log", "OK", "Warning")
        return
    }
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmm")
    $nombreArchivo = "DNSFixer_$Equipo" + "_$timestamp.txt"
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    $saveDialog.FileName = $nombreArchivo
    $saveDialog.Filter = "Archivo de texto (*.txt)|*.txt"
    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            $txtLog.Text | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Log exportado correctamente a:`n$($saveDialog.FileName)", "Exportación completa", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error al guardar el archivo:`n$_", "Error", "OK", "Error")
        }
    }
}

# =====================================================================
# Función: Análisis Inteligente del log
function Do-Analysis {
    param(
        [string]$Equipo,
        [System.Windows.Forms.RichTextBox]$txtLog,
        [System.Windows.Forms.Button]$btnDiagnostico,
        [System.Windows.Forms.Button]$btnLimpiar
    )
    if (-not $txtLog.Text) {
        Write-Log "[INFO] El log está vacío. Ejecutando diagnóstico, corrección y limpieza automáticamente..." $txtLog
        $btnDiagnostico.PerformClick()
        Start-Sleep -Milliseconds 1000
        $btnLimpiar.PerformClick()
        Start-Sleep -Milliseconds 1000
    }
    $contenido = $txtLog.Text
    $resumen = "[ANÁLISIS INTELIGENTE DEL LOG]"
    $errores = ($contenido | Select-String "\[ERROR\]|\[CRÍTICO\]").Count
    $alertas = ($contenido | Select-String "\[ALERTA\]|\[WARNING\]").Count
    $coincide = ($contenido | Select-String "\[OK\] IP .* coincide").Count

    if ($errores -eq 0 -and $alertas -eq 0 -and $coincide -gt 0) {
        $resumen += " ✔️ Diagnóstico limpio: las IPs coinciden y no se detectaron errores."
    } elseif ($errores -gt 0 -or $alertas -gt 0) {
        $resumen += " ⚠️ Se detectaron posibles inconsistencias:`r`n  - Errores: $errores`r`n  - Alertas: $alertas`r`nRecomendaciones:`r`n  - Ejecuta la corrección DNS si no lo has hecho.`r`n  - Verifica registros PTR si están ausentes."
    } else {
        $resumen += " ℹ️ No se encontraron resultados concluyentes. Revisa manualmente el análisis."
    }
    Write-Log $resumen $txtLog
}

# =====================================================================
# Función: Diagnóstico Avanzado
function Do-AdvancedDiagnostic {
    param(
        [string]$Equipo,
        [System.Windows.Forms.RichTextBox]$txtLog
    )
    Write-Log "[INFO] Iniciando diagnóstico avanzado para $Equipo" $txtLog
    Do-Diagnostic -Equipo $Equipo -txtLog $txtLog
    try {
         $ipconfigOutput = Invoke-LocalOrRemote -Equipo $Equipo -Script { ipconfig /all }
         ProcessRemoteOutput -output $ipconfigOutput -txtLog $txtLog
         Write-Log "[INFO] 'ipconfig /all' completado." $txtLog
    } catch {
         Write-Log "[ERROR] Falló la ejecución de 'ipconfig /all'." $txtLog -LogType "warning"
    }
    try {
         $netshOutput = Invoke-LocalOrRemote -Equipo $Equipo -Script { netsh interface ipv4 show config }
         ProcessRemoteOutput -output $netshOutput -txtLog $txtLog
         Write-Log "[INFO] 'netsh interface ipv4 show config' completado." $txtLog
    } catch {
         Write-Log "[ERROR] Falló la ejecución de 'netsh interface ipv4 show config'." $txtLog -LogType "warning"
    }
    try {
         $adapterInfo = Invoke-LocalOrRemote -Equipo $Equipo -Script { Get-NetAdapter | Format-List * | Out-String }
         ProcessRemoteOutput -output $adapterInfo -txtLog $txtLog
         Write-Log "[INFO] Configuración de adaptadores obtenida." $txtLog
    } catch {
         Write-Log "[ERROR] Falló la obtención de información del adaptador." $txtLog -LogType "warning"
    }
    Write-Log "[INFO] Diagnóstico avanzado completado." $txtLog
}

# =====================================================================
# Creación de la Interfaz Gráfica (GUI)
$form = New-Object System.Windows.Forms.Form
$form.Text = "DNSFixer - Diagnóstico y Corrección DNS (Mejorado y Avanzado)"
$form.Size = New-Object System.Drawing.Size(700, 600)
$form.StartPosition = "CenterScreen"
$form.BackColor = "Gainsboro"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$lblEquipo = New-Object System.Windows.Forms.Label
$lblEquipo.Text = "Nombre del equipo (o IP):"
$lblEquipo.Location = New-Object System.Drawing.Point(20,20)
$lblEquipo.AutoSize = $true
$form.Controls.Add($lblEquipo)

$txtEquipo = New-Object System.Windows.Forms.TextBox
$txtEquipo.Location = New-Object System.Drawing.Point(180,18)
$txtEquipo.Width = 200
$txtEquipo.Text = $env:COMPUTERNAME
$form.Controls.Add($txtEquipo)

$groupOpciones = New-Object System.Windows.Forms.GroupBox
$groupOpciones.Text = "Opciones"
$groupOpciones.Location = New-Object System.Drawing.Point(20,60)
$groupOpciones.Size = New-Object System.Drawing.Size(640, 220)
$form.Controls.Add($groupOpciones)

# Fila 1, Columna 1: Diagnóstico DNS
$btnDiagnostico = New-Object System.Windows.Forms.Button
$btnDiagnostico.Text = "▶ Diagnóstico DNS"
$btnDiagnostico.Location = New-Object System.Drawing.Point(20,30)
$btnDiagnostico.Width = 180
$btnDiagnostico.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnDiagnostico.BackColor = "SteelBlue"
$btnDiagnostico.ForeColor = "White"
$btnDiagnostico.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnDiagnostico)

# Fila 1, Columna 2: Corregir DNS (funcionalidad extendida)
$btnCorregir = New-Object System.Windows.Forms.Button
$btnCorregir.Text = "Corregir DNS"
$btnCorregir.Location = New-Object System.Drawing.Point(220,30)
$btnCorregir.Width = 180
$btnCorregir.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnCorregir.BackColor = "SteelBlue"
$btnCorregir.ForeColor = "White"
$btnCorregir.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnCorregir)

# Fila 1, Columna 3: Limpiar caché DNS
$btnLimpiar = New-Object System.Windows.Forms.Button
$btnLimpiar.Text = "Limpiar caché DNS"
$btnLimpiar.Location = New-Object System.Drawing.Point(420,30)
$btnLimpiar.Width = 180
$btnLimpiar.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnLimpiar.BackColor = "SteelBlue"
$btnLimpiar.ForeColor = "White"
$btnLimpiar.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnLimpiar)

# Fila 2, Columna 1: Análisis Intel
$btnAnalisis = New-Object System.Windows.Forms.Button
$btnAnalisis.Text = "Análisis Intel"
$btnAnalisis.Location = New-Object System.Drawing.Point(20,70)
$btnAnalisis.Width = 180
$btnAnalisis.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnAnalisis.BackColor = "DarkGreen"
$btnAnalisis.ForeColor = "White"
$btnAnalisis.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnAnalisis)

# Fila 2, Columna 2: Exportar TXT
$btnExportar = New-Object System.Windows.Forms.Button
$btnExportar.Text = "Exportar TXT"
$btnExportar.Location = New-Object System.Drawing.Point(220,70)
$btnExportar.Width = 180
$btnExportar.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnExportar.BackColor = "MediumPurple"
$btnExportar.ForeColor = "White"
$btnExportar.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnExportar)

# Fila 2, Columna 3: Diagnóstico Avanzado
$btnAdvanced = New-Object System.Windows.Forms.Button
$btnAdvanced.Text = "Diagnóstico Avanzado"
$btnAdvanced.Location = New-Object System.Drawing.Point(420,70)
$btnAdvanced.Width = 180
$btnAdvanced.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnAdvanced.BackColor = "DarkGreen"
$btnAdvanced.ForeColor = "White"
$btnAdvanced.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnAdvanced)

$groupLogs = New-Object System.Windows.Forms.GroupBox
$groupLogs.Text = "Resultado del análisis"
$groupLogs.Location = New-Object System.Drawing.Point(20,300)
$groupLogs.Size = New-Object System.Drawing.Size(640, 260)
$form.Controls.Add($groupLogs)

$txtLog = New-Object System.Windows.Forms.RichTextBox
$txtLog.Multiline = $true
$txtLog.ScrollBars = "Vertical"
$txtLog.ReadOnly = $true
$txtLog.Location = New-Object System.Drawing.Point(10,20)
$txtLog.Size = New-Object System.Drawing.Size(620, 230)
$groupLogs.Controls.Add($txtLog)

# =====================================================================
# Asignación de Eventos a los Botones
$btnDiagnostico.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    Do-Diagnostic -Equipo $equipo -txtLog $txtLog
})

$btnCorregir.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    Do-FixStaleDNS -Equipo $equipo -txtLog $txtLog -btnDiagnostico $btnDiagnostico -btnLimpiar $btnLimpiar
})

$btnLimpiar.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    Do-Cleanup -Equipo $equipo -txtLog $txtLog
})

$btnExportar.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    Do-Export -Equipo $equipo -txtLog $txtLog
})

$btnAnalisis.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    Do-Analysis -Equipo $equipo -txtLog $txtLog -btnDiagnostico $btnDiagnostico -btnLimpiar $btnLimpiar
})

$btnAdvanced.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    Do-AdvancedDiagnostic -Equipo $equipo -txtLog $txtLog
})

# =====================================================================
# Mostrar el Formulario
[void]$form.ShowDialog()

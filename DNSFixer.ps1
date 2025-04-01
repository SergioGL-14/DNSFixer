# DNSFixer - GUI Diagnóstico Inicial DNS
# ===============================
#_____  _   _  _____ ______ _______   ________ _____  
#|  __ \| \ | |/ ____|  ____|_   _\ \ / /  ____|  __ \ 
#| |  | |  \| | (___ | |__    | |  \ V /| |__  | |__) |
#| |  | | . ` |\___ \|  __|   | |   > < |  __| |  _  / 
#| |__| | |\  |____) | |     _| |_ / . \| |____| | \ \ 
#|_____/|_| \_|_____/|_|    |_____/_/ \_\______|_|  \_\
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Variable para definir el prefijo IP esperado
$expectedPrefix = "10."

# ====================================================================
# Función Write-Log: Añade un mensaje al log con formato y timestamp
function Write-Log {
    param(
        [string]$Message,
        [System.Windows.Forms.RichTextBox]$txtLog,
        [string]$LogType = "system"  # valores posibles: system, warning, ok, user
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $fullMessage = "[$timestamp] $Message`r`n"
    
    switch ($LogType.ToLower()) {
        "warning" {
            $color = [System.Drawing.Color]::Red
            $bold = $false
        }
        "ok" {
            $color = [System.Drawing.Color]::Green
            $bold = $false
        }
        "user" {
            $color = [System.Drawing.Color]::Purple
            $bold = $true
        }
        default {
            $color = $txtLog.ForeColor
            $bold = $false
        }
    }
    
    $txtLog.SelectionStart = $txtLog.TextLength
    $txtLog.SelectionLength = 0
    $txtLog.SelectionColor = $color
    if ($bold) {
        $txtLog.SelectionFont = New-Object System.Drawing.Font($txtLog.Font, [System.Drawing.FontStyle]::Bold)
    } else {
        $txtLog.SelectionFont = New-Object System.Drawing.Font($txtLog.Font, [System.Drawing.FontStyle]::Regular)
    }
    $txtLog.AppendText($fullMessage)
    $txtLog.SelectionColor = $txtLog.ForeColor
}

# ====================================================================
# Función para ejecutar un comando local o remoto utilizando PsExec
# con manejo de la salida y chequeo de código de retorno
function Invoke-LocalOrRemote {
    param (
        [string]$Equipo,
        [ScriptBlock]$Script
    )
    # Obtener las IP locales del equipo
    $localIPs = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.*" } | Select-Object -ExpandProperty IPAddress)
    
    # Si el equipo es local, se ejecuta el script localmente.
    if ($Equipo -eq $env:COMPUTERNAME -or ($localIPs -contains $Equipo)) {
        return & $Script
    } else {
        # Ruta completa a psexec.exe (ajusta según tu entorno)
        $psexecPath = "C:\temp\PsTools\psexec.exe"
        
        # Generar un nombre de archivo temporal único y ruta local
        $tempFilename = ([System.IO.Path]::GetRandomFileName() + ".ps1")
        $localTempFile = Join-Path $env:TEMP $tempFilename
        
        # Guardar el contenido del ScriptBlock en el archivo temporal
        $scriptContent = $Script.ToString()
        Set-Content -Path $localTempFile -Value $scriptContent -Encoding UTF8
        
        # Definir carpeta remota y ruta para el archivo (C:\Temp, debe existir o se crea)
        $remoteTempFolder = "C:\Temp"
        $remoteFile = Join-Path $remoteTempFolder $tempFilename
        
        # 1) Crear la carpeta remota si no existe
        $mkdirArgs = @("\\$Equipo","-accepteula","cmd /c `"if not exist `"$remoteTempFolder`" mkdir `"$remoteTempFolder`"`")
        $mkdirResult = & $psexecPath $mkdirArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "PsExec (mkdir) devolvió código $LASTEXITCODE. Salida:`r`n$($mkdirResult -join '`r`n')"
        }
        
        # 2) Copiar el archivo temporal al equipo remoto mediante la ruta UNC
        $remoteUNCPath = "\\$Equipo\C$" + $remoteTempFolder.Substring(2)  # Convierte "C:\Temp" -> "\Temp"
        $remoteUNCFile = Join-Path $remoteUNCPath $tempFilename
        try {
            Copy-Item -Path $localTempFile -Destination $remoteUNCFile -ErrorAction Stop
        } catch {
            throw "Error al copiar el archivo temporal al equipo remoto: $_"
        }
        
        # 3) Ejecutar el archivo remoto usando PsExec
        $commandToRun = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$remoteFile`""
        $execArgs = @("\\$Equipo","-accepteula",$commandToRun)
        $execResult = & $psexecPath $execArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "PsExec (ejecución) devolvió código $LASTEXITCODE. Salida:`r`n$($execResult -join '`r`n')"
        }
        
        # 4) Eliminar el archivo remoto
        $delArgs = @("\\$Equipo","-accepteula","cmd /c `"del `"$remoteFile`"`")
        $delResult = & $psexecPath $delArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "PsExec (del) devolvió código $LASTEXITCODE. Salida:`r`n$($delResult -join '`r`n')"
        }
        
        # 5) Eliminar el archivo temporal local
        Remove-Item -Path $localTempFile -Force
        
        # Devolvemos la salida de la ejecución del script remoto (execResult) si es útil
        return $execResult
    }
}

# ====================================================================
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
            $ipv4 = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.*" } | Select-Object -ExpandProperty IPAddress
            $ipv6 = Get-NetIPAddress -AddressFamily IPv6 | Select-Object -ExpandProperty IPAddress
            return ,$ipv4,$ipv6
        }
        Write-Log "[INFO] IPs activas del equipo: $($ips -join ', ')" $txtLog
    } catch {
        Write-Log "[ERROR] No se pudieron obtener las IPs activas. Detalle: $_" $txtLog -LogType "warning"
    }

    try {
        $dns = Invoke-LocalOrRemote -Equipo $Equipo -Script {
            return (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses -join ", "
        }
        Write-Log "[INFO] DNS configurado: $dns" $txtLog
    } catch {
        Write-Log "[WARNING] No se pudo obtener el servidor DNS. Detalle: $_" $txtLog -LogType "warning"
    }

    Write-Log "[INFO] Ejecutando nslookup al nombre: $Equipo" $txtLog
    try {
        $resNombre = nslookup $Equipo 2>&1
        $nslookupOutput = $resNombre -join "`r`n"
        Write-Log "[INFO] Resultado de nslookup:" $txtLog
        $txtLog.AppendText($nslookupOutput + "`r`n")

        # Extraer las líneas con 'Address:' y convertir a IP
        $resueltas = $resNombre | Where-Object { $_ -match "Address:" } |
            ForEach-Object { ($_ -split ":")[1].Trim() } |
            Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }

        Write-Log "[INFO] IPs que devuelve el DNS: $($resueltas -join ', ')" $txtLog

        # Compara con la red esperada
        foreach ($ip in $resueltas) {
            if (-not $ip.StartsWith($expectedPrefix)) {
                Write-Log "[ALERTA] El registro DNS ($ip) no corresponde a la red esperada ($expectedPrefix)." $txtLog -LogType "warning"
            } else {
                Write-Log "[OK] El registro DNS ($ip) coincide con la red esperada." $txtLog -LogType "ok"
            }
        }
        # Compara con IPs activas del equipo
        foreach ($ip in $resueltas) {
            if ($ips -contains $ip) {
                Write-Log "[OK] IP $ip coincide con una IP del equipo." $txtLog -LogType "ok"
            } else {
                Write-Log "[ALERTA] IP $ip no coincide con ninguna IP activa del equipo." $txtLog -LogType "warning"
            }
        }
    } catch {
        Write-Log "[ERROR] No se pudo hacer nslookup al nombre. Detalle: $_" $txtLog -LogType "warning"
    }

    Write-Log "[INFO] Comprobando registros PTR (reverso)" $txtLog
    foreach ($ip in $ips) {
        try {
            $resIP = nslookup $ip 2>&1
            $ptrOutput = $resIP -join "`r`n"
            Write-Log "↪️ $ip → $ptrOutput" $txtLog
        } catch {
            Write-Log "[ERROR] Falló el PTR para $ip. Detalle: $_" $txtLog -LogType "warning"
        }
    }

    Write-Log "[INFO] Obteniendo TTL del registro DNS (nombre)" $txtLog
    try {
        $ttlCheck = nslookup -debug $Equipo 2>&1 | Where-Object { $_ -match "TTL" }
        if ($ttlCheck) {
            Write-Log ([string]::Join("`r`n", $ttlCheck)) $txtLog
        } else {
            Write-Log "[WARNING] No se pudo extraer TTL." $txtLog -LogType "warning"
        }
    } catch {
        Write-Log "[ERROR] Error al intentar obtener TTL. Detalle: $_" $txtLog -LogType "warning"
    }
}

# ====================================================================
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
         Invoke-LocalOrRemote -Equipo $Equipo -Script { Clear-DnsClientCache }
         Write-Log "[OK] Caché DNS limpiada correctamente." $txtLog -LogType "ok"
         Start-Sleep -Seconds 1
         Write-Log "[INFO] Re-ejecutando diagnóstico para confirmar la corrección..." $txtLog -LogType "user"
         Do-Diagnostic -Equipo $Equipo -txtLog $txtLog
    } else {
         Write-Log "[INFO] No se detectó incidencia de registro DNS obsoleto. No se requiere acción adicional." $txtLog
    }
}

# ====================================================================
# Función: Limpiar caché DNS
function Do-Cleanup {
    param(
        [string]$Equipo,
        [System.Windows.Forms.RichTextBox]$txtLog
    )
    Write-Log "[INFO] Limpiando caché DNS..." $txtLog
    try {
        Invoke-LocalOrRemote -Equipo $Equipo -Script {
            Clear-DnsClientCache
        }
        Write-Log "[OK] Caché DNS limpiada correctamente." $txtLog -LogType "ok"
    } catch {
        Write-Log "[ERROR] No se pudo limpiar la caché DNS: $_" $txtLog -LogType "warning"
    }
}

# ====================================================================
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

# ====================================================================
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

# ====================================================================
# Función: Diagnóstico Avanzado
function Do-AdvancedDiagnostic {
    param(
        [string]$Equipo,
        [System.Windows.Forms.RichTextBox]$txtLog
    )
    Write-Log "[INFO] Iniciando diagnóstico avanzado para $Equipo" $txtLog
    Do-Diagnostic -Equipo $Equipo -txtLog $txtLog
    try {
         $ipconfigOutput = ipconfig /all 2>&1
         Write-Log "[INFO] Resultado de 'ipconfig /all':" $txtLog
         $txtLog.AppendText($ipconfigOutput -join "`r`n" + "`r`n")
    } catch {
         Write-Log "[ERROR] Falló la ejecución de 'ipconfig /all'. Detalle: $_" $txtLog -LogType "warning"
    }
    try {
         $netshOutput = netsh interface ipv4 show config 2>&1
         Write-Log "[INFO] Resultado de 'netsh interface ipv4 show config':" $txtLog
         $txtLog.AppendText($netshOutput -join "`r`n" + "`r`n")
    } catch {
         Write-Log "[ERROR] Falló la ejecución de 'netsh interface ipv4 show config'. Detalle: $_" $txtLog -LogType "warning"
    }
    try {
         $adapterInfo = Get-NetAdapter | Format-List * | Out-String
         Write-Log "[INFO] Configuración de adaptadores:" $txtLog
         $txtLog.AppendText($adapterInfo + "`r`n")
    } catch {
         Write-Log "[ERROR] Falló la obtención de información del adaptador. Detalle: $_" $txtLog -LogType "warning"
    }
    Write-Log "[INFO] Diagnóstico avanzado completado." $txtLog
}

# ====================================================================
# Creación de la Interfaz Gráfica (GUI)
# ====================================================================
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
$txtEquipo.Location = New-Object System.Drawing.Point(150,18)
$txtEquipo.Width = 200
$txtEquipo.Text = $env:COMPUTERNAME
$form.Controls.Add($txtEquipo)

$groupOpciones = New-Object System.Windows.Forms.GroupBox
$groupOpciones.Text = "Opciones"
$groupOpciones.Location = New-Object System.Drawing.Point(20,60)
$groupOpciones.Size = New-Object System.Drawing.Size(640, 220)
$form.Controls.Add($groupOpciones)

# Botones de la primera fila
$btnDiagnostico = New-Object System.Windows.Forms.Button
$btnDiagnostico.Text = "▶ Diagnóstico DNS"
$btnDiagnostico.Location = New-Object System.Drawing.Point(20,30)
$btnDiagnostico.Width = 180
$btnDiagnostico.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnDiagnostico.BackColor = "SteelBlue"
$btnDiagnostico.ForeColor = "White"
$btnDiagnostico.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnDiagnostico)

$btnCorregir = New-Object System.Windows.Forms.Button
$btnCorregir.Text = "Corregir DNS"
$btnCorregir.Location = New-Object System.Drawing.Point(220,30)
$btnCorregir.Width = 180
$btnCorregir.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnCorregir.BackColor = "SteelBlue"
$btnCorregir.ForeColor = "White"
$btnCorregir.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnCorregir)

$btnLimpiar = New-Object System.Windows.Forms.Button
$btnLimpiar.Text = "Limpiar caché DNS"
$btnLimpiar.Location = New-Object System.Drawing.Point(420,30)
$btnLimpiar.Width = 180
$btnLimpiar.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnLimpiar.BackColor = "SteelBlue"
$btnLimpiar.ForeColor = "White"
$btnLimpiar.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnLimpiar)

# Botones de la segunda fila
$btnAnalisis = New-Object System.Windows.Forms.Button
$btnAnalisis.Text = "Análisis Intel"
$btnAnalisis.Location = New-Object System.Drawing.Point(20,70)
$btnAnalisis.Width = 180
$btnAnalisis.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnAnalisis.BackColor = "DarkGreen"
$btnAnalisis.ForeColor = "White"
$btnAnalisis.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnAnalisis)

$btnExportar = New-Object System.Windows.Forms.Button
$btnExportar.Text = "Exportar TXT"
$btnExportar.Location = New-Object System.Drawing.Point(220,70)
$btnExportar.Width = 180
$btnExportar.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnExportar.BackColor = "MediumPurple"
$btnExportar.ForeColor = "White"
$btnExportar.FlatStyle = "Flat"
$groupOpciones.Controls.Add($btnExportar)

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

# ====================================================================
# Asignación de Eventos a los Botones
# ====================================================================
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

# ====================================================================
# Mostrar el Formulario
# ====================================================================
[void]$form.ShowDialog()

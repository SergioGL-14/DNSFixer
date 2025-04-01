# DNSFixer - Diagnóstico y Corrección DNS con PowerShell

**DNSFixer** es una herramienta en PowerShell que proporciona un conjunto de funciones para diagnosticar y corregir problemas de DNS en entornos Windows, todo a través de una **interfaz gráfica (GUI)**. Utiliza [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) para ejecutar scripts de manera local o remota, facilitando la gestión de múltiples equipos.

## Características Principales

- **Diagnóstico Básico DNS**: Obtención de IPs activas, comprobación de DNS configurado, ejecución de `nslookup` (directo e inverso), verificación de TTL.
- **Corrección de Registros Obsoletos**: Limpieza de caché DNS y forzado de registro (`ipconfig /registerdns`) en caso de detectar IPs fuera de la subred esperada.
- **Diagnóstico Avanzado**: Muestra configuración detallada de red (`ipconfig /all`, `netsh interface ipv4 show config`, etc.).
- **Análisis Inteligente**: Escanea el log en busca de errores, alertas o confirmaciones de éxito y genera un resumen al final.
- **Interfaz Gráfica (GUI)**: Todo se realiza de forma fácil e intuitiva gracias al formulario hecho con .NET Windows Forms.
- **Soporte Local y Remoto**: Permite ejecutar el diagnóstico/corrección en la máquina local o en equipos remotos mediante PsExec.

## Requisitos

1. **PowerShell 5.x o superior** (funciona en Windows 10/11 y Windows Server).
2. **PsExec** de Sysinternals (colócalo, por ejemplo, en `C:\temp\PsTools\psexec.exe` o ajusta la ruta en el script).
3. **Ejecución de scripts habilitada**: Requiere `Set-ExecutionPolicy Bypass` (o RemoteSigned) para que el script se ejecute sin restricciones innecesarias.
4. **Permisos de Administrador**: Especialmente importante si planeas forzar registros DNS o limpiar la caché en equipos remotos.

## Uso

1. **Clonar o Descargar** este repositorio.
2. Situar `psexec.exe` en la carpeta configurada dentro del script (o editar la ruta en la función `Invoke-LocalOrRemote`).
3. Abrir PowerShell **como Administrador** y ejecutar `DNSFixer.ps1`.
4. Se mostrará una ventana con distintos botones:
    - **Diagnóstico DNS**: Realiza un chequeo básico.
    - **Corregir DNS**: Si detecta IPs obsoletas, fuerza un nuevo registro DNS y limpia la caché.
    - **Limpiar caché DNS**: Limpia únicamente la caché DNS.
    - **Análisis Intel**: Genera un resumen de lo que hay en el log.
    - **Exportar TXT**: Permite guardar el log en un archivo de texto.
    - **Diagnóstico Avanzado**: Ejecuta pruebas adicionales (ipconfig /all, netsh, etc.) para un informe más completo.

## Personalización

- En la parte superior del script, encontrarás la variable `$expectedPrefix = "10."`. Cámbiala a la subred (o subredes) que quieras marcar como “válidas” para tu entorno.
- Ajusta la ruta de PsExec (`$psexecPath`) según sea necesario.

## Capturas (Opcional)

*(Si lo deseas, puedes incluir capturas de pantalla de la interfaz para ilustrar el funcionamiento.)*

## Contribuciones

- Se aceptan _pull requests_ para mejoras en la lógica, la interfaz o la compatibilidad con nuevas versiones de Windows.
- Abre un _issue_ si detectas bugs o quieres proponer nuevas funcionalidades.

## Licencia

> Este proyecto está disponible bajo la [MIT License](LICENSE)

---

¡Gracias por usar **DNSFixer**! Si tienes dudas o sugerencias, no dudes en crear un issue o ponerte en contacto.

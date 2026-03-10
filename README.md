# DNSFixer v2.0

**Herramienta de diagnóstico y corrección DNS para entornos Windows**

Aplicación gráfica desarrollada en PowerShell con interfaz WPF, diseñada para técnicos de soporte IT. Permite diagnosticar, analizar y corregir problemas de resolución DNS en equipos locales y remotos de forma rápida y visual.

---

## Índice

- [DNSFixer v2.0](#dnsfixer-v20)
  - [Índice](#índice)
  - [Características principales](#características-principales)
  - [Requisitos del sistema](#requisitos-del-sistema)
  - [Instalación y ejecución](#instalación-y-ejecución)
    - [Ejecución rápida](#ejecución-rápida)
    - [Política de ejecución](#política-de-ejecución)
    - [Configuración de PsExec (opcional, para uso remoto)](#configuración-de-psexec-opcional-para-uso-remoto)
  - [Arquitectura técnica](#arquitectura-técnica)
    - [Patrón de diseño](#patrón-de-diseño)
  - [Estructura del proyecto](#estructura-del-proyecto)
  - [Guía de uso por pestañas](#guía-de-uso-por-pestañas)
    - [1. Diagnóstico](#1-diagnóstico)
    - [2. Corrección](#2-corrección)
    - [3. Análisis](#3-análisis)
    - [4. Configuración](#4-configuración)
  - [Ejecución remota con PsExec](#ejecución-remota-con-psexec)
    - [Funcionamiento](#funcionamiento)
    - [Requisitos para uso remoto](#requisitos-para-uso-remoto)
  - [Solución de problemas](#solución-de-problemas)
  - [Changelog](#changelog)
    - [v2.0 (2026-02-06)](#v20-2026-02-06)
    - [v1.0](#v10)
  - [Licencia y créditos](#licencia-y-créditos)

---

## Características principales

| Característica | Descripción |
|---|---|
| **Diagnóstico básico** | Obtiene IPs activas, servidor DNS, nslookup, registros PTR y TTL |
| **Diagnóstico avanzado** | Incluye `ipconfig /all`, configuración IPv4 y adaptadores de red |
| **Corrección automática** | Detecta registros obsoletos y ejecuta `ipconfig /registerdns` + limpieza de caché |
| **Limpieza de caché** | Ejecuta `Clear-DnsClientCache` en local o remoto |
| **Análisis inteligente** | Analiza el log del diagnóstico y genera un resumen con conteo de errores, alertas y recomendaciones contextuales |
| **Exportación** | Guarda el log completo a archivo `.txt` con diálogo de guardado |
| **Ejecución remota** | Soporta diagnóstico y corrección en equipos remotos vía PsExec |
| **Interfaz moderna** | WPF con layout responsivo, pestañas horizontales y paleta Material Design |

---

## Requisitos del sistema

| Requisito | Detalle |
|---|---|
| **Sistema operativo** | Windows 10 / 11 / Server 2016+ |
| **PowerShell** | 5.1 o superior |
| **Framework** | .NET Framework 4.5+ (incluido en Windows 10+) |
| **Permisos** | Administrador (recomendado para corrección y limpieza) |
| **PsExec** | Requerido solo para ejecución remota (`C:\temp\PsTools\psexec.exe`) |

---

## Instalación y ejecución

### Ejecución rápida

```powershell
# Desde PowerShell (como Administrador recomendado)
cd "C:\ruta\a\DNSFixer"
.\DNSFixer.ps1
```

### Política de ejecución

Si PowerShell bloquea la ejecución:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\DNSFixer.ps1
```

### Configuración de PsExec (opcional, para uso remoto)

1. Descarga [PsExec de Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
2. Coloca `psexec.exe` en `C:\temp\PsTools\`
3. La ruta se puede modificar en el código fuente (`$App.Config.PsExecPath`)

---

## Arquitectura técnica

```
┌─────────────────────────────────────────────────────┐
│                    DNSFixer v2.0                    │
├─────────────────────────────────────────────────────┤
│  UI Layer          │  WPF (PresentationFramework)   │
│  Layout            │  Grid responsivo (3 filas)     │
│  Navegación        │  Pestañas horizontales (4)     │
│  Estado global     │  $Global:DNSFixerApp           │
│  Thread-safety     │  Dispatcher.CheckAccess()      │
├─────────────────────────────────────────────────────┤
│  Lógica DNS        │  nslookup, Resolve-DnsName     │
│  Corrección        │  ipconfig /registerdns          │
│  Limpieza          │  Clear-DnsClientCache          │
│  Red               │  Get-NetIPAddress, netsh       │
│  Remoto            │  PsExec (cmd /c)               │
├─────────────────────────────────────────────────────┤
│  Paleta de colores │  Material Design               │
│  Primary: #1976D2  │  Success: #4CAF50              │
│  Warning: #FF9800  │  Error: #F44336                │
│  Info: #2196F3     │  Background: #FAFAFA           │
└─────────────────────────────────────────────────────┘
```

### Patrón de diseño

- **Estado centralizado:** Objeto `$Global:DNSFixerApp` almacena controles, configuración, colores y pestaña activa.
- **Funciones puras de diagnóstico:** Cada función (`Do-Diagnostic`, `Do-FixStaleDNS`, etc.) recibe el equipo y el control de log como parámetros.
- **Invoke-LocalOrRemote:** Abstracción que ejecuta el mismo ScriptBlock en local o remoto según el equipo indicado.
- **Write-Log thread-safe:** Usa `Dispatcher.CheckAccess()` para garantizar escritura segura al TextBox desde cualquier hilo.

---

## Estructura del proyecto

```
DNSFixer/
├── DNSFixer.ps1                              # Aplicación principal (WPF v2.0)
├── # DNSFixer - GUI Diagnóstico Inicial DNS.ps1   # Script original (Windows Forms v1.0)
└── readme.md                                      # Documentación del proyecto
```

**Dependencia externa (opcional):**

```
C:\temp\PsTools\psexec.exe    # Para ejecución remota
```

---

## Guía de uso por pestañas

### 1. Diagnóstico

Pestaña principal para analizar la configuración DNS de un equipo.

**Ejecutar Diagnóstico** — Realiza las siguientes comprobaciones:

| Paso | Qué hace | Cmdlet / Herramienta |
|---|---|---|
| 1 | Obtener IPs activas del equipo (IPv4) | `Get-NetIPAddress` |
| 2 | Obtener servidor DNS configurado | `Get-DnsClientServerAddress` |
| 3 | Resolver nombre del equipo vía DNS | `nslookup` |
| 4 | Validar si las IPs resueltas coinciden con los prefijos esperados | Comparación con `$App.Config.ExpectedPrefixes` |
| 5 | Verificar que la IP resuelta coincide con alguna IP activa | Comparación directa |
| 6 | Comprobar registros PTR (resolución inversa) | `Resolve-DnsName -Type PTR` |
| 7 | Obtener TTL de los registros DNS | `Resolve-DnsName` |

**Diagnóstico Avanzado** — Ejecuta todo lo anterior más:

| Paso adicional | Cmdlet / Herramienta |
|---|---|
| Configuración IP completa | `ipconfig /all` |
| Configuración IPv4 de interfaces | `netsh interface ipv4 show config` |
| Listado de adaptadores activos | `Get-NetAdapter` (solo Status = Up) |

---

### 2. Corrección

Herramientas para reparar problemas DNS detectados.

**Corregir DNS:**

1. Ejecuta un diagnóstico silencioso en segundo plano
2. Si detecta que el registro DNS no corresponde a la red esperada:
   - Fuerza re-registro con `ipconfig /registerdns`
   - Limpia la caché DNS con `Clear-DnsClientCache`
   - Re-ejecuta el diagnóstico para confirmar la corrección
3. Si no detecta incidencias, informa que no se aplicaron cambios

**Limpiar Caché DNS:**

- Ejecuta `Clear-DnsClientCache` en el equipo indicado (local o remoto)
- Útil cuando los resultados de nslookup están cacheados con información antigua

---

### 3. Análisis

Herramientas de interpretación y exportación.

**Análisis Inteligente:**

Escanea el contenido del log buscando patrones y genera un informe estructurado:

```
========================================
  ANALISIS INTELIGENTE DEL LOG
========================================
  Resultados OK: 2 | Alertas: 0 | Errores: 0
  PTR correctos: 2 | PTR fallidos: 0

  [RESULTADO] El DNS no resuelve el nombre del equipo
  Esto puede ser normal en redes domesticas sin DNS interno.
  En red corporativa, esto indica que el registro DNS falta.

  Recomendaciones:
    - Ejecuta 'Corregir DNS' para forzar ipconfig /registerdns
    - Verifica que el equipo tiene sufijo DNS correcto

  [NOTA] Los registros PTR (inverso) SI resuelven correctamente.
  Esto sugiere que el problema es solo el registro A (directo).
========================================
```

**Exportar Log:**

- Abre un diálogo de guardado para exportar el log completo a `.txt`
- Nombre por defecto: `DNSFixer_<equipo>_<fecha>.txt`

---

### 4. Configuración

Permite ajustar los parámetros de validación de la herramienta.

**Prefijos IP esperados:**

Este es el parámetro central de DNSFixer. Define qué rangos de red se consideran "correctos" al validar un registro DNS.

| Campo | Valor por defecto | Ejemplo personalizado |
|---|---|---|
| Prefijos IP | `10., 69.` | `172.16., 10., 192.168.1.` |

**¿Cómo funciona la validación?**

Cuando el diagnóstico resuelve la IP de un equipo vía DNS, compara esa IP contra cada prefijo configurado:

- Si la IP **comienza** con alguno de los prefijos → **OK** ✅ (el registro DNS es correcto)
- Si **no coincide** con ninguno → **ALERTA** ⚠️ (posible registro DNS obsoleto)

**Ejemplo práctico:**

```
Prefijos configurados: 10., 69.

DNS resuelve EQUIPO-001 → 10.0.5.23    → ✅ OK (empieza por "10.")
DNS resuelve EQUIPO-001 → 192.168.1.50 → ⚠️ ALERTA (no coincide con ningún prefijo)
```

**¿Cuándo modificar los prefijos?**

- Cuando tu red corporativa usa rangos distintos a los configurados por defecto
- Si operas en múltiples sedes con diferentes subredes
- Para adaptarte a migraciones de red o cambios de infraestructura

> **Nota:** Los cambios de configuración solo persisten durante la sesión actual. Al reiniciar la aplicación, se restablecen los valores por defecto.

---

## Ejecución remota con PsExec

DNSFixer puede ejecutar diagnósticos y correcciones en equipos remotos utilizando [PsExec de Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec).

### Funcionamiento

1. Si el nombre/IP del equipo coincide con el equipo local → ejecuta directamente
2. Si es un equipo remoto → construye un comando PsExec:

```
psexec.exe \\EQUIPO-REMOTO powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "..."
```

### Requisitos para uso remoto

- `psexec.exe` en `C:\temp\PsTools\`
- El equipo remoto debe ser accesible por red
- Permisos de administrador en el equipo remoto
- El recurso compartido `ADMIN$` debe estar habilitado

---

## Solución de problemas

| Problema | Causa | Solución |
|---|---|---|
| "Non-existent domain" al resolver | El DNS no tiene registro para ese equipo | Normal en redes domésticas. En corporativa: ejecutar "Corregir DNS" |
| IPs activas no se obtienen | Equipo apagado o inaccesible | Verificar conectividad con `ping` |
| Corrección DNS no aplica cambios | Permisos insuficientes | Ejecutar PowerShell como Administrador |
| PsExec falla | No encontrado o bloqueado | Verificar ruta y permisos de red |
| TTL no se puede obtener | `Resolve-DnsName` no resuelve el nombre | El nombre no está registrado en DNS |
| Prefijos siempre dan ALERTA | Red actual no está en los prefijos | Ir a Configuración y añadir tu prefijo de red |
| Caché limpia pero persiste el problema | Registro obsoleto en el servidor DNS | Contactar al administrador de DNS |

---

## Changelog

### v2.0 (2026-02-06)

- **Migración completa** de Windows Forms a WPF
- **Nueva interfaz** con layout responsivo Grid, pestañas horizontales y paleta Material Design
- **Análisis inteligente** reescrito con detección contextual y recomendaciones
- **PTR mejorado** usando `Resolve-DnsName` en lugar de `nslookup`
- **TTL funcional** usando `Resolve-DnsName` con detalle de tipo y valor
- **Obtención de IPs** corregida (array plano IPv4)
- **Output limpio** en nslookup (filtrado de `RemoteException`)
- **Adaptadores** filtrados solo los activos con formato compacto
- **Estado global** con `$Global:DNSFixerApp`

### v1.0

- Versión inicial con Windows Forms
- Diagnóstico básico, corrección, limpieza, exportación y análisis

---

## Licencia y créditos

- **Autor:** Desarrollo interno
- **PsExec:** [Sysinternals / Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- **Iconografía:** Unicode Emoji + caracteres BMP
- **Paleta de colores:** Basada en [Material Design](https://material.io/design/color)

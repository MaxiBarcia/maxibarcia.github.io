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


## 📑 **Índice**
- [Resumen Ejecutivo](#1-resumen-ejecutivo)
- [Objetivos del Proyecto](#2-objetivos-del-proyecto)
- [Arquitectura de Red](#3-arquitectura-de-la-red-e-infraestructura)
- [Configuración Raspberry Pi](#4-configuracion-de-la-raspberry-pi-5-servidor-wazuh)
- [Configuración Agente](#42-configuracion-de-la-maquina-objetivo-ctf-labs---ip-21)
- [Simulación de Ataques](#5-simulacion-de-ataques-y-validacion)
- [Resultados](#6-resultados-y-analisis-en-wazuh)
- [Lecciones Aprendidas](#7-lecciones-aprendidas-y-desafios-superados)
- [Troubleshooting](#8-comandos-de-verificacion-y-troubleshooting)
- [Conclusión](#9-conclusion-y-proximos-pasos)
- [Apéndices](#apendices)

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

|Componente|Hardware/SO|IP/Dirección|Rol Principal|
|---|---|---|---|
|**Servidor Wazuh (Manager)**|Raspberry Pi 5 (64GB SD + 2TB Disco Externo) con Raspberry Pi OS|`192.168.0.200:8443`|Centraliza logs, gestiona agentes, panel web Kibana.|
|**Máquina Objetivo (Agente)**|Máquina Virtual (CTF-Labs - KALI)|`192.168.0.21`|Ejecuta el agente Wazuh y contenedores vulnerables.|
|**Máquina Atacante**|Máquina Virtual (Nyx - Kali Linux)|`192.168.0.27`|Punto desde donde se lanzan los ataques simulados.|
|**Contenedor Vulnerable**|Docker en CTF-Labs (Imagen "escolares")|`172.17.0.2` (Docker)|Contenedor con WordPress/Apache que actúa como víctima.|

**Flujo de Datos:**  
Los ataques desde `Nyx` hacia el contenedor en `CTF-Labs` generan logs en el contenedor. A través de un volumen de Docker, estos logs se sincronizan con el sistema de archivos del host `CTF-Labs` en la ruta `/home/cft/logs_victima/`, donde el agente Wazuh los lee y los envía al Manager en la Raspberry Pi para su análisis y visualización.

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

[https:///assets/images/posts/project/wazuh/cert.png](https://assets/images/posts/project/wazuh/cert.png)  
![[Pasted image 20260305185510.png|700]]  
_Captura: Descarga y generación del script de certificados._

**Nota técnica para ARM64**: Debido a que el script de generación original estaba compilado para `amd64`, en algunos pasos tuvimos que intervenir manualmente con **OpenSSL** para asegurar la compatibilidad con la arquitectura de la Raspberry Pi 5.

## **4.1.5. Configuración del `docker-compose.yml`**
[[SIEM Docker-Compose.yml de SIEM]]         <------------- Docker-Compose SIEM


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
[https:///assets/images/posts/project/wazuh/docker-up.png](https://assets/images/posts/project/wazuh/docker-up.png)  
![[Pasted image 20260306105756.png|800]]  
_Captura: Contenedores de Wazuh corriendo junto a Pi-hole y Portainer._

**4.1.7. Acceso al Dashboard**  
Finalmente, accedimos a la interfaz web a través del puerto configurado (**8443**).  
[https:///assets/images/posts/project/wazuh/wazuh_1.png](https://assets/images/posts/project/wazuh/wazuh_1.png)  
![[Pasted image 20260306110418.png|800]]  
_Captura: Dashboard de Wazuh operativo tras el Health Check inicial._

**Detalles Técnicos de Acceso**

- **URL**: `https://192.168.0.200:8443`
- **Credenciales por defecto**:
    - **Usuario**: `admin`
    - **Password**: `SecretPassword` (Configurado en el `.yml`)

**4.1.8. 🛠️ Configuración de Persistencia en Almacenamiento Externo (SSD/HDD)**  
Por defecto, los despliegues de Docker Wazuh utilizan **volúmenes nombrados**, lo que almacena los datos en la partición raíz (tarjeta SD). Para un entorno de producción o laboratorio SOC de larga duración, es imperativo realizar un **Bind Mount** hacia el disco externo.

**Preparación de los Directorios Físicos**
```bash
# Crear estructura en el disco de 2TB
mkdir -p /mnt/datos/wazuh_data/manager_etc \
         /mnt/datos/wazuh_data/manager_logs \
         /mnt/datos/wazuh_data/manager_queue \
         /mnt/datos/wazuh_data/manager_api \
         /mnt/datos/wazuh_data/indexer_data
```

**Nota sobre permisos:** Durante el proceso, nos encontramos con que el comando `chown` no funcionaba correctamente en el disco externo, manteniendo los archivos con propietario `nyx-pi`. La solución de emergencia fue dar permisos totales:
```bash
sudo chmod -R 777 /mnt/datos/wazuh_data
```

**Modificación del `docker-compose.yml`**  
Se deben sustituir las referencias de volúmenes internos por **rutas absolutas**. Es crucial identificar correctamente el punto de montaje interno de cada contenedor.

_Para Wazuh Indexer (Base de Datos):_
```bash
wazuh.indexer:
	...
	volumes:
	  - /mnt/datos/wazuh_data/indexer_data:/usr/share/wazuh-indexer/data
```

_Para Wazuh Manager (Alertas y Logs):_
```yaml

  wazuh.manager:
    user: "0:0"  # Forzado para evitar conflictos de permisos en el disco
    volumes:
      - /mnt/datos/wazuh_data/manager_logs:/var/ossec/logs
      - /mnt/datos/wazuh_data/manager_etc:/var/ossec/etc
```

**Aplicación de Cambios y Limpieza**

```bash
# 1. Detener el stack actual
cd /mnt/datos/wazuh-docker/wazuh-demo1
docker compose down
# 2. Eliminar volúmenes locales antiguos (libera espacio en la SD)
docker volume prune -f
# 3. Levantar con la nueva configuración
docker compose up -d
```

**Verificación de Analista SOC**
```bash
# Verificar existencia de alertas por año/mes
sudo ls -R /mnt/datos/wazuh_data/manager_logs/alerts/
```

- **Resultado esperado**: Presencia de la carpeta `2026/Mar/ossec-alerts-06.json`.
- **Inspección de Docker**: Al ejecutar `docker inspect`, la sección `Mounts` debe mostrar el `Source` apuntando a `/mnt/datos/...`.

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

[https:///assets/images/posts/project/wazuh/agent.png](https://assets/images/posts/project/wazuh/agent.png)  
![[Pasted image 20260306160205.png]]  
_Captura: Instalación del agente Wazuh en la máquina CTF-Labs._

**4.2.2. Configuración de Red y Permisos**
- Se ajustaron reglas de `iptables` para permitir el tráfico necesario y se configuró el logging para asegurar la trazabilidad.
- Se gestionaron permisos de usuarios y carpetas para que el agente Wazuh pudiera leer los logs del sistema y de las aplicaciones.

**4.2.3. Estrategia de Recolección de Logs desde Contenedores**
- **Punto Clave:** Para que el agente en el host pudiera ver los logs de los contenedores, se utilizó la funcionalidad de **volúmenes de Docker**.
- Al desplegar el contenedor vulnerable (con el script de DockerLabs), se montó el volumen `-v /var/log/apache2:/var/log/apache2:rw`. Esto sincroniza el directorio de logs de Apache _dentro_ del contenedor con el directorio `/var/log/apache2` _en el host_ `CTF-Labs`.
- De esta forma, el agente Wazuh en el host puede monitorear los logs del contenedor como si fueran locales.



**4.2.4. Configuración del Agente para Leer Logs**
El archivo de configuración completo del agente en `/var/ossec/etc/ossec.conf` quedó así:

```xml
<!--
  Wazuh - Agent - Default configuration for kali 2026.1
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh
-->

<ossec_config>
  <client>
    <server>
      <address>192.168.0.200</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>kali, kali2026, kali2026.1</config-profile>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>
    <nodiff>/etc/ssl/private.key</nodiff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <!-- Log analysis -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <!-- MONITOREO DE LOGS DE CONTENEDORES (AGREGADO MANUALMENTE) -->
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <!-- LOGS DE CONTENEDORES DOCKER (PUNTO CRÍTICO) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/home/cft/logs_victima/*.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/home/cft/logs_victima/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/home/cft/logs_victima/error.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/home/cft/logs_victima/access.log</location>
  </localfile>

</ossec_config>
```

**4.2.5. Verificación de la Conexión del Agente**  
Una vez configurado, verificamos que el agente se conectaba correctamente al manager desde el dashboard de Wazuh.

[https:///assets/images/posts/project/wazuh/wazuh_2.png](https://assets/images/posts/project/wazuh/wazuh_2.png)  
![[Pasted image 20260306155956.png]]  
_Captura: Agente 'CTF-Labs-nyx' conectado y activo en el panel de Wazuh._


---

##### **4.2.6. Deshabilitación del Enrollment Automático**

Para evitar que el agente intente registrarse automáticamente ignorando el archivo `client.keys`, se modificó el archivo de opciones internas:

```bash
# /var/ossec/etc/local_internal_options.conf
#
# This file should be handled with care. It contains
# run time modifications that can affect the use
# of OSSEC. Only change it if you know what you
# are doing. Look first at ossec.conf
# for most of the things you want to change.
#
# This file will not be overwritten during upgrades.
agent.auto_enroll=0
```


##### **4.2.6.1 Script de Despliegue Automatizado de Contenedores Vulnerables**
Se desarrolló un script personalizado `auto_deploy_wazuh.sh` que automatiza el despliegue de contenedores vulnerables con integración directa de logs para Wazuh.
**Script completo:**
```bash
#!/bin/bash
# Colores ANSI
CRE='\033[31m'  # Rojo
CYE='\033[33m'  # Amarillo
CGR='\033[32m'  # Verde
CBL='\033[34m'  # Azul
CBLE='\033[36m' # Cyan
CBK='\033[37m'  # Blanco
CGY='\033[38m'  # Gris
BLD='\033[1m'   # Negrita
CNC='\033[0m'   # Resetear colores
printf "\n"
printf "\t                   ${CRE} ##       ${CBK} .         \n"
printf "\t             ${CRE} ## ## ##      ${CBK} ==         \n"
printf "\t           ${CRE}## ## ## ##      ${CBK}===         \n"
printf "\t       /\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\\\___/ ===       \n"
printf "\t  ${CBL}~~~ ${CBK}{${CBL}~~ ~~~~ ~~~ ~~~~ ~~ ~ ${CBK}/  ===- ${CBL}~~~${CBK}\n"
printf "\t       \\\______${CBK} o ${CBK}         __/           \n"
printf "\t         \\\    \\\        __/            \n"
printf "\t          \\\____\\\______/               \n"
printf "${BLD}${CBLE}                                          \n"
printf "  ___  ____ ____ _  _ ____ ____ _    ____ ___  ____ \n"
printf "  |  \ |  | |    |_/  |___ |__/ |    |__| |__] [__  \n"
printf "  |__/ |__| |___ | \_ |___ |  \ |___ |  | |__] ___] \n"                                          
printf "${CNC}                                         \n"
printf "\t\t\t\t  ${CRE} ${CNC}${CYE} ${text}${CNC} ${CRE}${CNC}\n"
# Banner hecho por Ch4rum - https://instagram.com/ch4rum
# Recorre cada uno de los nombres proporcionados como parámetros
for name in "$@"; do
    base_name=$(basename "$name" .tar)
    image_id=$(docker images -q "$base_name")
    if [ ! -z "$image_id" ]; then
        echo -e "\e[38;5;230;1mSe han detectado máquinas de DockerLabs previas, debemos limpiarlas para evitar problemas, espere un momento...\e[0m"
        container_ids=$(docker ps -a -q --filter "ancestor=$image_id")
        if [ ! -z "$container_ids" ]; then
            docker stop $container_ids > /dev/null 2>&1
            docker rm $container_ids > /dev/null 2>&1
        fi
    fi
    container_ids=$(docker ps -aq --filter "id=5938*")
    if [ ! -z "$container_ids" ]; then
        echo -e "\e[38;5;230;1mSe han detectado máquinas de DockerLabs previas, debemos limpiarlas para evitar problemas, espere un momento...\e[0m"
        docker stop $container_ids > /dev/null 2>&1
        docker rm $container_ids > /dev/null 2>&1
    fi
done
for name in "$@"; do
    base_name=$(basename "$name" .tar)
    image_id=$(docker images -q "$base_name")
    if [ ! -z "$image_id" ]; then
        echo -e "\e[38;5;230;1mSe han detectado máquinas de DockerLabs previas, debemos limpiarlas para evitar problemas, espere un momento...\e[0m"
        docker rmi -f "$image_id" > /dev/null 2>&1
    fi
done
detener_y_eliminar_contenedor() {
    IMAGE_NAME="${TAR_FILE%.tar}"
    CONTAINER_NAME="${IMAGE_NAME}_container"
    if [ "$(docker ps -a -q -f name=$CONTAINER_NAME -f status=exited)" ]; then
        
        docker rm $CONTAINER_NAME > /dev/null
    fi
    
    if [ "$(docker ps -q -f name=$CONTAINER_NAME)" ]; then
        
        docker stop $CONTAINER_NAME > /dev/null
        docker rm $CONTAINER_NAME > /dev/null
    fi
    if [ "$(docker images -q $IMAGE_NAME)" ]; then
        docker rmi $IMAGE_NAME > /dev/null
    fi
    if docker network inspect $NETWORK_NAME > /dev/null 2>&1; then
        docker network rm $NETWORK_NAME > /dev/null
    fi
}
trap ctrl_c INT
function ctrl_c() {
    echo -e "\e[1mEliminando el laboratorio, espere un momento...\e[0m"
    detener_y_eliminar_contenedor
    echo -e "\nEl laboratorio ha sido eliminado por completo del sistema."
    exit 0
}
if [ $# -ne 1 ]; then
    echo "Uso: $0 <archivo_tar>"
    exit 1
fi
if ! command -v docker &> /dev/null; then
    echo -e "\033[1;36m\nDocker no está instalado. Instalando Docker...\033[0m"
    sudo apt update
    sudo apt install docker.io -y
    echo -e "\033[1;36m\nEstamos habilitando el servicio de docker. Espere un momento...\033[0m"
    sleep 10
    systemctl restart docker && systemctl enable docker
    if [ $? -eq 0 ]; then
        echo "Docker ha sido instalado correctamente."
    else
        echo "Error al instalar Docker. Por favor, verifique y vuelva a intentarlo."
        exit 1
    fi
fi
TAR_FILE="$1"
echo -e "\e[1;93m\nEstamos desplegando la máquina vulnerable, espere un momento.\e[0m"
detener_y_eliminar_contenedor
docker load -i "$TAR_FILE" > /dev/null
if [ $? -eq 0 ]; then
    IMAGE_NAME=$(basename "$TAR_FILE" .tar)
    CONTAINER_NAME="${IMAGE_NAME}_container"
    NETWORK_NAME="dockernetwork"
    if docker network inspect $NETWORK_NAME > /dev/null 2>&1; then
        echo -e "\e[38;5;230;1mLa red $NETWORK_NAME ya existe. Eliminándola y recreándola...\e[0m"
        docker network rm $NETWORK_NAME > /dev/null
    fi
    docker network create $NETWORK_NAME > /dev/null
    # 🔥 PUNTO CRÍTICO: Ruta donde se guardan los logs para Wazuh
    LOGS_HOST="/home/cft/logs_victima"
    # Crear carpeta con permisos para Wazuh
    mkdir -p $LOGS_HOST
    chmod 755 $LOGS_HOST
    sudo chown root:wazuh $LOGS_HOST
    # Ejecutar contenedor con volumen montado en /var/log/apache2
    docker run -d --name $CONTAINER_NAME \
      --network $NETWORK_NAME \
      -v $LOGS_HOST:/var/log/apache2 \
      $IMAGE_NAME > /dev/null
    IP_ADDRESS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CONTAINER_NAME)
    echo -e "\e[1;96m\nMáquina desplegada, su dirección IP es --> \e[0m\e[1;97m$IP_ADDRESS\e[0m"
    echo -e "\e[1;96mLos logs de Apache están en: \e[0m\e[1;97m$LOGS_HOST\e[0m"
    echo -e "\e[1;91m\nPresiona Ctrl+C cuando termines con la máquina para eliminarla\e[0m"
else
    echo -e "\e[91m\nHa ocurrido un error al cargar el laboratorio en Docker.\e[0m"
    exit 1
fi
# Mantiene el script vivo
while true; do
    sleep 1
done
```
**Características clave del script:**

- Monta automáticamente los logs en `/home/cft/logs_victima/` (carpeta monitoreada por Wazuh)
- Establece permisos `root:wazuh` para que el agente pueda leer los logs
- Crea una red aislada para los contenedores
- Muestra la IP del contenedor desplegado


##### **4.2.7. Configuración Definitiva del Agente para Monitoreo de Logs**

La configuración final del agente en `/var/ossec/etc/ossec.conf` incluye múltiples entradas para garantizar la captura de todos los logs:

xml

<!-- Monitoreo de logs de Apache desde contenedores -->
<localfile>
  <log_format>apache</log_format>
  <location>/home/cft/logs_victima/access.log</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>/home/cft/logs_victima/error.log</location>
</localfile>
<!-- Monitoreo genérico de todos los logs en la carpeta -->
<localfile>
  <log_format>syslog</log_format>
  <location>/home/cft/logs_victima/*.log</location>
</localfile>

**Nota:** Se observaron advertencias de archivos duplicados (`WARNING: (1958): Log file is duplicated`), pero no afectan el funcionamiento del sistema.

#### **5. Simulación de Ataques y Validación**

Para probar la detección del SIEM, se realizaron varios ataques controlados desde la máquina atacante `Nyx` (192.168.0.27) hacia el contenedor WordPress en `CTF-Labs`.

##### **5.1. Ataque de Fuerza Bruta con Hydra**

Hydra es una herramienta de inicio de sesión en red que puede realizar ataques de fuerza bruta rápida.

**5.1.1. Preparación del Diccionario**  
En la máquina `Nyx`, creamos un pequeño diccionario de contraseñas para la prueba.
```bash
cupp -i (entrar en modo interactivo en la herramienta)  
(a continuación lo que se rellena, lo que no aparezca se completa como vacío o negativo (No))  
> First Name: Luis  
> Surname:  
> Nickname: TLuisillo_o  
> Birthdate (DDMMYYYY): 09101981  
> Do you want to add some key words about the victim? Y/[N]: y  
> Please enter the words, separated by comma. [i.e. hacker,juice,black], spaces will be removed: 19131337
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

##### **5.4. Verificación del Estado del Agente en el Manager**

Una vez conectado, se verificó el estado del agente desde el manager:
```bash
# En Raspberry Pi (dentro del contenedor manager)
/var/ossec/bin/agent_control -l
```

**Resultado:**
```
ID: 006, Name: cft, IP: any, Active
```

El agente con ID **006** (nombre "cft") se muestra como **Active**, confirmando la correcta comunicación bidireccional.



## 📋 **Apéndice D: Credenciales del Laboratorio**
| Servicio               | Usuario     | Contraseña                                                         | Notas                                     |
| ---------------------- | ----------- | ------------------------------------------------------------------ | ----------------------------------------- |
| Wazuh Dashboard        | `admin`     | `SecretPassword`                                                   | Acceso web a `https://192.168.0.200:8443` |
| Wazuh Indexer          | `admin`     | `SecretPassword`                                                   | Backend de datos                          |
| Wazuh API              | `wazuh-wui` | `MyS3cr37P450r.*-`                                                 | Para comunicación dashboard-manager       |
| Agente Wazuh (ID 006)  | `cft`       | `cd53614b2e09e64524b40c6f41fee0d09edb9b04aaf202f483a46df3d3605bc7` | Clave en `/var/ossec/etc/client.keys`     |
| WordPress (contenedor) | `luisillo`  | (la que se encuentre en el diccionario)                            | Usuario de prueba para ataques            |

#### **6. Resultados y Análisis en Wazuh**

Tras los ataques, se procedió a analizar las alertas generadas en el dashboard de Wazuh.

| ID/Referencia                                                      | Descripción                                                                   |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| `agent.auto_enroll=0`                                              | Opción en `local_internal_options.conf` para deshabilitar registro automático |
| `cd53614b2e09e64524b40c6f41fee0d09edb9b04aaf202f483a46df3d3605bc7` | Clave del agente 006                                                          |
| `SecretPassword`                                                   | Contraseña del dashboard y indexer                                            |
| `MyS3cr37P450r.*-`                                                 | Contraseña de la API de Wazuh                                                 |
| `/home/cft/logs_victima`                                           | Punto de montaje de logs de contenedores                                      |
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
    
- **Formato del archivo client.keys:** Un error crítico fue que el archivo `client.keys` no tenía el formato correcto, causando errores de "Invalid password". La solución fue usar `echo "ID:name:any:KEY" | sudo tee /var/ossec/etc/client.keys` para garantizar el formato adecuado con salto de línea al final.
    
- **Enrollment automático del agente:** El agente intentaba registrarse automáticamente ignorando el archivo `client.keys`. Se solucionó añadiendo `agent.auto_enroll=0` en `/var/ossec/etc/local_internal_options.conf`.
    
- **Múltiples secciones `<ossec_config>`:** Inicialmente, la configuración del agente tenía dos secciones `<ossec_config>`, lo que impedía que se aplicaran correctamente las reglas de monitoreo de logs. La solución fue unificar todo en una sola sección.

| **Formato incorrecto de client.keys** | Error "Invalid password" en logs del agente | Usar `echo "ID:name:any:KEY" \| sudo tee /var/ossec/etc/client.keys` para garantizar el formato correcto |
| **Enrollment automático activado** | Agente ignora client.keys e intenta registrarse | Añadir `agent.auto_enroll=0` en `local_internal_options.conf` |
| **Puerto 443 ocupado** | Error al levantar dashboard | Cambiar a puerto 8443 en `docker-compose.yml` |
| **Permisos en disco externo** | `chown` no funciona en disco de 2TB | Usar `sudo chmod -R 777` y `user: "0:0"` en el contenedor |

#### **8. Comandos de Verificación y Troubleshooting**

**Cómo usar el script:**
```bash
# Dar permisos de ejecución
chmod +x auto_deploy_wazuh.sh

# Ejecutar con un archivo .tar de DockerLabs
./auto_deploy_wazuh.sh escolares.tar

# La salida mostrará:
#   Máquina desplegada, su dirección IP es --> 172.17.0.2
#   Los logs de Apache están en: /home/cft/logs_victima

# Para detener y eliminar el contenedor: Ctrl+C
```


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
**Para verificar que el agente está monitoreando los logs de contenedores:**

```bash
sudo tail -f /var/ossec/logs/ossec.log | grep -i "victima\|analyzing"
```

**Para verificar el ID correcto del agente:**

```bash
sudo cat /var/ossec/etc/client.keys
/var/ossec/bin/agent_control -l  # En el manager
```

##### **8.1. Problemas Específicos Encontrados y Soluciones**

|Problema|Síntoma|Solución|
|---|---|---|
|**Error de permisos en disco externo**|`chown` no funcionaba en disco de 2TB|`sudo chmod -R 777 /mnt/datos/wazuh_data` y `user: "0:0"` en docker-compose|
|**Archivo client.keys con formato incorrecto**|Error "Invalid password" en logs del agente|Usar `echo "ID:name:any:KEY" \| sudo tee /var/ossec/etc/client.keys`|
|**Enrollment automático activado**|Agente ignora client.keys e intenta registrarse|Añadir `agent.auto_enroll=0` en `local_internal_options.conf`|
|**Múltiples secciones `<ossec_config>`**|Configuración de logs no se aplicaba|Unificar todo en una sola sección|
|**Rutas duplicadas en ossec.conf**|`WARNING: (1958)` en logs|Eliminar entradas redundantes (opcional)|
|**Contenedor no genera logs**|No hay archivos en `/home/cft/logs_victima/`|Verificar montaje: `-v $LOGS_HOST:/var/log/apache2`|
|**IP del atacante enmascarada**|Alertas muestran `172.17.0.1` en lugar de IP real|Usar Suricata en host o configurar Docker para preservar IP|

#### **9. Conclusión y Próximos Pasos**

La implementación de este laboratorio SIEM casero con Wazuh sobre una Raspberry Pi 5 ha sido un éxito rotundo. Más allá de tener un sistema funcional, el verdadero valor del proyecto ha sido el viaje: enfrentarse a problemas reales de compatibilidad ARM64, lidiar con permisos en sistemas de archivos, comprender las complejidades de la red en Docker y, finalmente, ver cómo un ataque simulado de fuerza bruta se traduce en alertas enriquecidas con MITRE ATT&CK en un dashboard profesional.

Este entorno no es solo un "juguete", sino una plataforma de entrenamiento sólida que replica los flujos de trabajo de un Centro de Operaciones de Ciberseguridad (SOC) real.

**Próximos pasos recomendados:**

1. **Implementar reglas personalizadas** para WordPress en Wazuh
    
2. **Configurar alertas por correo electrónico** para notificaciones en tiempo real
    
3. **Añadir más agentes** (Windows, Linux) para diversificar el laboratorio
    
4. **Integrar Suricata** para detección de intrusiones a nivel de red
    
5. **Automatizar el despliegue** con scripts de Ansible
    

## 📋 **Apéndice A: Glosario de IDs y Referencias**

|ID/Referencia|Descripción|
|---|---|
|**006**|ID del agente Wazuh en la máquina CTF-Labs (Kali)|
|**005**|ID anterior del agente (reemplazado por 006)|
|**wazuh-demo1-wazuh.manager-1**|Nombre del contenedor del manager|
|**172.17.0.2**|IP del contenedor vulnerable dentro de Docker|
|**192.168.0.200**|IP de la Raspberry Pi (manager)|
|**192.168.0.21**|IP de CTF-Labs (agente)|
|**/home/cft/logs_victima**|Punto de montaje de logs en el host|
|**agent.auto_enroll=0**|Opción para deshabilitar el registro automático|
|**31509**|Regla de Wazuh: "CMS login attempt"|
|**31510**|Regla de Wazuh: "CMS brute force attempt"|

## 🏆 **Logros Clave del Proyecto**

✅ **Arquitectura funcional**: SIEM completo con Raspberry Pi 5 como servidor central  
✅ **Recolección de logs de contenedores**: Logs de Apache desde contenedores Docker monitorizados por el agente host  
✅ **Detección de ataques**: Reglas 31509 y 31510 detectaron exitosamente intentos de login y fuerza bruta  
✅ **Integración MITRE ATT&CK**: Alertas enriquecidas con T1110 (Brute Force)  
✅ **Persistencia en disco externo**: Datos almacenados en disco de 2TB, no en la SD  
✅ **Resolución de problemas críticos**: Permisos, ARM64, formato de claves, enrollment automático  
✅ **Documentación completa**: Proceso replicable y bien documentado para futuras referencias
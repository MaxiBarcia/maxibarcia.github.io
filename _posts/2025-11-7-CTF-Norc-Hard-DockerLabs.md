---
title: "Write-up Dockerlabs - Hard - Norc"
excerpt: Detailed  report on the phishing campaign.
categories:
  - Write-up
  - Privilege Escalation
  - Laboratory
  - dockerlabs
tags:
  - nmap
  - sqli
  - sqlmap
  - wordpress
  - cronjob
  - capabilities
toc: true
toc_label: Report Contents
toc_sticky: true
header:
  # Ruta de la imagen de cabecera que aparecerá en el banner del post
  overlay_image: /assets/images/headers/dockerlabs.png
  overlay_filter: 0.7
og_image: /assets/images/headers/dockerlabs.png
seo_title: Write-up de Hacking en Dockerlabs - Norc 
seo_description: Análisis detallado de la vulneración de la máquina Norc de Dockerlabs, incluyendo inyección SQL, RCE y escalada de privilegios mediante Cronjob.
author: Maxi Barcia
date: 2025-11-07
draft: false
---


![image-center](/assets/images/headers/dockerlabs.png){: .align-center}

### Lanzamiento laboratorio
![DockerLabs](/assets\images\posts\DockerLabs\norc\docker1.png){: .align-center}

Se procede a lanzar el docker sobre la maquina a vulnerar con numero de ip --> 172.17.0.2{: .align-center}



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

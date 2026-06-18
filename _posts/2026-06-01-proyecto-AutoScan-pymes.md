---
title: "CI/CD - AutoVulnerabilities"
project: "AutoVulnerabilities / Verificador DNS"
platform: "FastAPI"
os: "Ubuntu 22.04 / 24.04"
tags:
  - FastAPI
  - Python
  - Docker
  - ZAP
  - Security-Scanning
  - DAST
  - CI/CD
  - GitHub-Actions
hashtags:
  - "#FastAPI"
  - "#Python"
  - "#DAST"
  - "#ZAP"
  - "#Security"
  - "#CI/CD"
image:
  path: /assets/img/posts/project/autovulnerabilities/banner.png
  alt: "AutoVulnerabilities - Plataforma de Escaneo de Vulnerabilidades"
toc: true
toc_label: "📑 Contenido"
toc_sticky: true
---

Nombre: AutoVulnerabilities / Verificador DNS
**Repositorio:** [https://github.com/maxibarciaklbrs/verificador-dominios](https://github.com/maxibarciaklbrs/verificador-dominios)
Autor: maxibarciaklbrs
Fecha: 2026-06-01

### 1. Resumen Ejecutivo

Este documento detalla el proceso completo para desplegar y operar una **plataforma automatizada de escaneo de vulnerabilidades orientada a pequeñas y medianas empresas (PyMEs)**.

El sistema, construido con **FastAPI**, utiliza un mecanismo de verificación de propiedad de dominio (mediante un **registro TXT en DNS**) como puerta de entrada. Una vez que la PyME acredita la titularidad, la plataforma desencadena automáticamente un **escaneo de seguridad orquestado con OWASP ZAP** sobre su sitio web, generando un reporte ejecutivo con los hallazgos.

Este reporte complementa el código fuente del repositorio, proporcionando los **pasos, configuraciones y dependencias de infraestructura necesarias** (gestión de procesos, proxy inverso, tareas programadas, etc.) que no están documentadas en el mismo, con el objetivo de hacer el despliegue completamente replicable.

### 2. Arquitectura y Componentes del Sistema

El flujo completo integra los siguientes componentes, que deben ser desplegados e integrados en un servidor:

| Componente                 | Tecnología                       | Propósito en el Modelo de Negocio                                                                                      |
| -------------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **API**                    | Python 3.11+ / FastAPI           | Lógica central: registro de PyMEs, verificación DNS, simulación de pago y **orquestación de escaneos ZAP**.            |
| **Orquestador de Escaneo** | `asyncio` & `subprocess`         | Gestiona la ejecución asíncrona de contenedores Docker con OWASP ZAP, evitando bloquear el servidor.                   |
| **Motor de Escaneo**       | OWASP ZAP (Docker)               | Realiza el análisis de vulnerabilidades activo y pasivo sobre el sitio web de la PyME.                                 |
| **Servidor ASGI**          | Uvicorn                          | Ejecuta la aplicación FastAPI. Se recomienda gestionarlo como un servicio del sistema.                                 |
| **Proxy Inverso**          | Nginx                            | Actúa como entrada pública, gestiona SSL y redirige el tráfico a Uvicorn.                                              |
| **Gestor de Procesos**     | Systemd (Linux)                  | Mantiene Uvicorn ejecutándose en segundo plano y lo reinicia automáticamente si falla.                                 |
| **Tareas Programadas**     | Cron                             | Para mantenimiento: limpieza de reportes antiguos, backups y renovación de certificados SSL.                           |
| **Base de Datos**          | SQLite (archivo `.db` / `.json`) | Almacena datos de clientes PyME, estados de pago y referencias a reportes. **Este archivo no está en el repositorio**. |
| **Notificaciones**         | SMTP, Telegram                   | Alerta al administrador sobre nuevos registros y pagos, y envía el reporte/resumen al cliente.                         |
| **Logs**                   | Archivos `.log` y `.txt`         | Auditoría de acciones del sistema. **Estos archivos no están en el repositorio**.                                      |
#### Requisitos Previos del Servidor

| Requisito             | Especificación                             |
| --------------------- | ------------------------------------------ |
| **Sistema Operativo** | Ubuntu 22.04 / 24.04 LTS                   |
| **RAM**               | Mínimo 4GB (recomendado 8GB para escaneos) |
| **CPU**               | 2 cores mínimo                             |
| **Espacio en disco**  | 20GB mínimo                                |
| **Acceso**            | SSH, puertos 80 y 443 abiertos             |
### 3. Infraestructura y Configuración Requerida

Para que el proyecto funcione, se debe preparar el servidor con los siguientes elementos:

#### 3.1 Sistema Operativo y Dependencias Base (Ejemplo: Ubuntu 22.04/24.04)

```bash

# Actualizar sistema e instalar Python, Git, Docker y el compilador necesario
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.11 python3.11-venv python3.11-dev git build-essential docker.io nginx
```
#### 3.2 Archivo de Entorno (`.env`) – **IMPORTANTE**

Este archivo **no debe subirse al repositorio** y debe crearse manualmente en el servidor. Define las credenciales y configuraciones sensibles. El archivo **.env** se debe almacenar en la ruta seleccionada
```bash
# Crear archivo .env
nano .env

# SMTP (Configuración de correo saliente)
SMTP_HOST=smtp.tu-proveedor.com
SMTP_PORT=587
SMTP_USER=tu-usuario@correo.com
SMTP_PASSWORD=tu-contraseña-fuerte
SMTP_FROM_EMAIL=escaneos@tuseguridad.com
MI_EMAIL=admin@tuseguridad.com
# Telegram
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=123456789
# Base de Datos y archivos
ARCHIVO_PENDIENTES=pendientes_verificacion.json
DIRECTORIO_REPORTES=reportes
```
#### 3.3 Crear y Activar Entorno Virtual
```bash
# Crear entorno virtual con Python 3.11
python3.11 -m venv venv
# Activar entorno virtual
source venv/bin/activate
```

#### Sección 3.4 - Configuración de Nginx **

En tu documento, la sección 3.4 solo tiene los comandos de activación, pero **falta el contenido del archivo de Nginx**.

**Agregar antes de "Comandos para activarlo":**

```bash
nginx

# Crear archivo de configuración
sudo nano /etc/nginx/sites-available/AutoVulnerabilities
```

**Contenido del archivo:**

```bash
nginx

server {
    listen 80;
    server_name tudominio.com;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
    }
    location /static/ {
        alias /home/ubuntu/AutoVulnerabilities/static/;
        expires 30d;
    }
}
```

---

### 2. **Sección 3.5 - Servicio Systemd (completamente faltante)**

Después de la sección de Nginx, **agregar**:

#### 3.5 Configurar Servicio Systemd

```bash

# Crear archivo de servicio
sudo nano /etc/systemd/system/AutoVulnerabilities.service
```

**Contenido:**

```bash

[Unit]
Description=Plataforma de Escaneo de Vulnerabilidades (AutoVulnerabilities)
After=network.target docker.target
Requires=docker.target
[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/AutoVulnerabilities
Environment="PATH=/home/ubuntu/AutoVulnerabilities/venv/bin"
ExecStart=/home/ubuntu/AutoVulnerabilities/venv/bin/uvicorn app_fastapi:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
```

**Comandos para activarlo:**

```bash

sudo systemctl daemon-reload
sudo systemctl enable AutoVulnerabilities
sudo systemctl start AutoVulnerabilities
sudo systemctl status AutoVulnerabilities
```

**Comandos para activarlo:**

```bash

# Crear enlace simbólico
sudo ln -s /etc/nginx/sites-available/tu-proyecto /etc/nginx/sites-enabled/
# Eliminar default (opcional)
sudo rm -f /etc/nginx/sites-enabled/default
# Verificar configuración
sudo nginx -t
# Reiniciar Nginx
sudo systemctl restart nginx
```

### 4. Flujo de Despliegue Paso a Paso (Replicable)

1. **Preparación del Servidor:** Ejecutar los comandos de la sección 3.1.
    
2. **Clonar Repositorio y Configurar Entorno:**
    
    ```bash
    
    git clone https://github.com/maxibarciaklbrs/verificador-dominios.git
    cd verificador-dominios
    python3.11 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
    
3. **Configurar Variables de Entorno:** Crear y editar el archivo `.env` (Sección 3.2).
    
4. **Inicializar Base de Datos:** El sistema creará automáticamente los archivos (`pendientes_verificacion.json`, `registros.txt`) en la primera ejecución.
    
5. **Preparar Docker:** Agregar tu usuario al grupo docker para ejecutar ZAP sin `sudo`: `sudo usermod -aG docker $USER` (requiere cerrar sesión y volver a entrar).
    
6. **Configurar y Arrancar Servicios:**
    
    - Crear y activar el servicio systemd (Sección 3.3).
        
    - Configurar y reiniciar Nginx (Sección 3.4).
        
7. **Configurar Mantenimiento:** Añadir las tareas programadas en crontab (Sección 3.5).
    
8. **Verificar el Despliegue:** Acceder a `http://tudominio.com/health`. La respuesta esperada es `{"status":"ok"}`. Probar el flujo de verificación y escaneo completo.
    

### 5. Endpoints Críticos de la API (Modelo de Negocio)

|Método|Endpoint|Función en el Servicio de Escaneo|Autenticación|
|---|---|---|---|
|`GET`|`/`|Muestra el formulario de registro para la PyME.|Pública|
|`POST`|`/submit`|Registra la PyME, envía instrucciones de verificación.|Pública|
|`POST`|`/validar-dns`|**Verifica la propiedad del dominio** (paso previo al escaneo).|Interna (token)|
|`GET`|`/pago/{codigo}`|Muestra la página de pago simulado/real.|Interna (por código)|
|`POST`|`/webhook-pago`|Confirma el pago y **desbloquea el servicio de escaneo**.|Interna|
|`POST`|`/lanzar-escaneo`|**Orquesta el escaneo con ZAP** y lo ejecuta en segundo plano.|Interna (requiere pago)|
|`GET`|`/descargar/{archivo}`|Permite descargar el reporte en HTML.|Interna (token)|
|`GET`|`/health`|Health check para balanceadores/monitoreo.|Pública|

### 6. Instalación y Configuración de OWASP ZAP

#### 6.1 Verificar Docker

```bash

# Verificar que Docker está instalado
docker --version
# Agregar usuario al grupo docker (para ejecutar sin sudo)
sudo usermod -aG docker ubuntu
# Cerrar sesión y volver a entrar, o aplicar cambios
newgrp docker
```

#### 6.2 Descargar Imagen de ZAP

```bash

# Descargar la imagen estable de ZAP
docker pull ghcr.io/zaproxy/zaproxy:stable
```

#### 6.3 Probar ZAP Manualmente

```bash

# Escaneo de prueba contra un sitio
docker run --rm -v $(pwd):/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://ejemplo.com -r reporte_prueba.html
```

#### 6.4 Verificar que el Proyecto Puede Ejecutar ZAP

```bash

# Probar la importación desde la aplicación
source venv/bin/activate
python -c "from app.services.zap_service import ejecutar_escaneo_zap; print('✅ OK')"
```

### 7. Configuración de Crontab (Mantenimiento)

```bash

# Editar crontab
crontab -e
```

**Añadir estas líneas:**

```bash

# Limpiar reportes antiguos (más de 7 días) - 2 AM
0 2 * * * find /home/ubuntu/tu-proyecto/reportes/ -name "*.html" -mtime +7 -delete
# Backup de base de datos - 3 AM
0 3 * * * cp /home/ubuntu/tu-proyecto/pendientes_verificacion.json /home/ubuntu/backups/pendientes_$(date +\%Y\%m\%d).json
```

---

### 8. Instalación de BurpSuite (PENDIENTE)

> **⚠️ SECCIÓN EN DESARROLLO - IMPLEMENTACIÓN FUTURA**

**Estado:** Pendiente de planificación

**Tareas pendientes para BurpSuite:**

- Evaluar integración vía API (Burp REST API)
    
- Configurar modo headless
    
- Definir umbrales de escaneo (rápido/profundo)
    
- Integrar resultados con el sistema de reportes actual
    
- Automatizar rotación de licenses para múltiples escaneos
    

**Requisitos estimados:**

- Licencia BurpSuite Professional (Enterprise para múltiples escaneos)
    
- Java Runtime Environment (JRE) 11+
    
- Recursos adicionales (RAM +2GB)
    

**Comandos de instalación (por confirmar):**

```bash

# Descargar BurpSuite (pendiente de metodología)
wget https://portswigger.net/burp/releases/download?product=community
# Ejecutar en modo headless (investigación en curso)
# java -jar burp.jar --headless --config-file=scan_config.json --target-url=$TARGET
```

---

### 9. Verificación del Despliegue

```bash

# 1. Verificar que el servicio está corriendo
sudo systemctl status tu-proyecto
# 2. Verificar Nginx
curl http://localhost/health
# Respuesta esperada: {"status":"ok","version":"2.0.0"}
# 3. Verificar que Docker funciona
docker ps
# 4. Verificar logs
tail -f /home/ubuntu/tu-proyecto/uvicorn.log
```

---

### 10. Variables del Proyecto (Resumen)

|Variable|Valor|Dónde se usa|
|---|---|---|
|`Ruta del proyecto`|`/home/ubuntu/tu-proyecto`|En todos los comandos|
|`Usuario del sistema`|`ubuntu`|En el servicio systemd|
|`Puerto de la app`|`8000` (interno)|Uvicorn, Nginx|
|`Puerto web`|`80` / `443`|Nginx|
|`Archivo de entrada`|`app_fastapi:app`|Uvicorn|

---

### 11. Solución de Problemas Comunes

|Problema|Posible Causa|Solución|
|---|---|---|
|`502 Bad Gateway`|Uvicorn no está corriendo|`sudo systemctl restart tu-proyecto`|
|Permiso denegado en Docker|Usuario no está en grupo docker|`sudo usermod -aG docker ubuntu` + logout/login|
|Error de importación|Entorno virtual no activado|`source venv/bin/activate`|
|ZAP no genera reporte|Timeout o URL incorrecta|Verificar logs: `tail -f uvicorn.log`|
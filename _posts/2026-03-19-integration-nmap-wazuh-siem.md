---
layout: post
title: "Integración Nmap-Wazuh: Detección Automatizada de Escaneos de Red"
description: "Guía completa para integrar Nmap con Wazuh y detectar escaneos de red automáticamente. Incluye scripts, reglas personalizadas y mapeo MITRE ATT&CK T1046."
categories: [wazuh, siem, nmap, threat-detection, soc]
tags: [wazuh, nmap, siem, threat-hunting, mitre-attack, python, raspberry-pi, security-monitoring, network-scanning, t1046]
image:
  path: /assets/images/posts/nmap-wazuh/banner-integracion.png
  alt: "Integración Nmap-Wazuh - Dashboard de alertas"
  featured: true
author: maximiliano-barcia
comments: true
pin: false
toc: true
math: false
mermaid: false
---

## **Integración Nmap-Wazuh: Detección Automatizada de Escaneos de Red**

**Autor:** Maximiliano Barcia  
**Fecha:** 18-03-2026  
**Versión:** 1.0

---

## **1. Objetivo de la Integración**

Detectar automáticamente escaneos de red en la infraestructura mediante Nmap, enviando los resultados a Wazuh para correlación y alertado. 
_Esta capacidad de descubrimiento proactivo de activos es fundamental en un equipo SOC para monitorizar cambios en la superficie de ataque._


---

## **2. Arquitectura de la Solución**

- **Agente de Escaneo:** Máquina `CTF-Labs` (Kali Linux). Ejecuta el script en Python.
- **Generación de Logs:** El script escribe los resultados en `/home/cft/logs_victima/nmap-scans.log`.
- **Recolección:** El agente Wazuh en `CTF-Labs` está configurado para monitorizar ese archivo.
- **Procesamiento:** El manager Wazuh (Raspberry Pi) recibe y analiza los logs.
- **Reglas de Detección:** Se crearon reglas personalizadas con IDs `200400`, `200401`, `200402`, enriqueciendo los datos con MITRE ATT&CK.
- **Visualización:** Las alertas se muestran en el dashboard de Wazuh.
    

---

## **3. Implementación en el Agente (CTF-Labs)**

### **3.1. Scripts de Escaneo**

Se dispone de dos versiones del script Python, que utilizan la librería `python-nmap`.

#### **Script Principal (Escaneo de Subredes)**

Este script, adaptado de SOCFortress, escanea las subredes definidas y envía los resultados al log de Wazuh.
```python
################################
### Python Script to Run Network Scans and append results to Wazuh Active Responses Log
### Requirements:
###     NMAP installed in Agent
###     python-nmap (https://pypi.org/project/python-nmap/)
### Replace the Array "subnets" with the subnets to scan from this agent.
### Do NOT include subnets with a network firewall in the path of the agent and the subnet.
################################
import nmap
import time
import json
nm = nmap.PortScanner()
#Add subnets to scan to the Subnets Array
subnets=['192.168.252.0/24','192.168.1.0/24']
for subnet in subnets:
    json_output={}
    nm.scan(subnet)
    for host in nm.all_hosts():
        json_output['nmap_host']=host
        for proto in nm[host].all_protocols():
            if proto not in ["tcp", "udp"]:
                continue
            json_output['nmap_protocol']=proto
            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                hostname = ""
                json_output['nmap_port']=port
                for h in nm[host]["hostnames"]:
                    hostname = h["name"]
                    json_output['nmap_hostname']=hostname
                    hostname_type = h["type"]
                    json_output['nmap_hostname_type']=hostname_type
                    json_output['nmap_port_name']=nm[host][proto][port]["name"]
                    json_output['nmap_port_state']=nm[host][proto][port]["state"]
                    json_output['nmap_port_product']=nm[host][proto][port]["product"]
                    json_output['nmap_port_extrainfo']=nm[host][proto][port]["extrainfo"]
                    json_output['nmap_port_reason']=nm[host][proto][port]["reason"]
                    json_output['nmap_port_version']=nm[host][proto][port]["version"]
                    json_output['nmap_port_conf']=nm[host][proto][port]["conf"]
                    json_output['nmap_port_cpe']=nm[host][proto][port]["cpe"]
                    with open("/var/ossec/logs/active-responses.log", "a") as active_response_log:
                        active_response_log.write(json.dumps(json_output))
                        active_response_log.write("\n")
                time.sleep(2)
```

#### **Script Alternativo (Pruebas Rápidas)**

Este script está diseñado para pruebas rápidas y enfocadas, escaneando una IP específica y puertos concretos.

```python
#!/usr/bin/env python3
################################
### Script RÁPIDO para probar la integración
### Escanea solo una IP y puertos específicos
################################
import nmap
import time
import json
print("[*] Iniciando script de prueba RÁPIDO...")
nm = nmap.PortScanner()
# 🔥 CAMBIA ESTO: Pon la IP de tu máquina CTF-Labs o la de tu router
# Puedes poner varias separadas por comas: '192.168.0.1,192.168.0.21'
targets = '192.168.0.1'  # <--- CAMBIA A UNA IP QUE RESPONDA
puertos = '22,80,443,8080'  # Solo estos puertos específicos
print(f"[*] Escaneando {targets} (puertos: {puertos})...")
try:
    # Escaneo rápido con puertos específicos
    nm.scan(hosts=targets, ports=puertos, arguments='-sS -T4')
    
    print(f"[+] Hosts encontrados: {nm.all_hosts()}")
    
    for host in nm.all_hosts():
        print(f"\n[+] Host: {host}")
        print(f"    Estado: {nm[host].state()}")
        
        if nm[host].state() != 'up':
            continue
            
        for proto in nm[host].all_protocols():
            print(f"    Protocolo: {proto}")
            lport = list(nm[host][proto].keys())
            lport.sort()
            
            for port in lport:
                service = nm[host][proto][port]
                print(f"      └─ Puerto: {port}")
                print(f"         Estado: {service['state']}")
                print(f"         Servicio: {service.get('name', 'desconocido')}")
                print(f"         Producto: {service.get('product', '')}")
                print(f"         Versión: {service.get('version', '')}")
                
                # Crear JSON
                json_output = {
                    "nmap_host": host,
                    "nmap_host_state": nm[host].state(),
                    "nmap_protocol": proto,
                    "nmap_port": port,
                    "nmap_port_name": service.get('name', ''),
                    "nmap_port_state": service.get('state', ''),
                    "nmap_port_product": service.get('product', ''),
                    "nmap_port_version": service.get('version', ''),
                    "scan_type": "test_rapido"
                }
                
                # Guardar en archivo temporal
                with open("/tmp/nmap_test_output.json", "a") as f:
                    f.write(json.dumps(json_output))
                    f.write("\n")
                
                time.sleep(0.5)  # Pequeña pausa para no saturar
                
    print(f"\n[✓] Escaneo completado en {len(nm.all_hosts())} hosts")
    print(f"[✓] Resultados guardados en /tmp/nmap_test_output.json")
    
except Exception as e:
    print(f"[!] ERROR: {e}")
```

### **3.2. Instalación de Dependencias**

Es necesario instalar la librería `python-nmap` en el agente. Se recomienda usar ambos métodos para asegurar la disponibilidad:
```bash
# Instalación con pip (puede requerir --break-system-packages en Kali)
pip install python-nmap --break-system-packages
# Instalación desde los repositorios del sistema
sudo apt install python3-nmap
```
### **3.3. Ejecución y Verificación del Script**

#### **Output del Script en Ejecución**
```bash

└─$ python3 nmap-python.py 
[*] Iniciando script de prueba RÁPIDO...
[*] Escaneando 192.168.0.1 (puertos: 22,80,443,8080)...
[+] Hosts encontrados: ['192.168.0.1']
[+] Host: 192.168.0.1
    Estado: up
    Protocolo: tcp
      └─ Puerto: 22
         Estado: filtered
         Servicio: ssh
         Producto: 
         Versión: 
      └─ Puerto: 80
         Estado: open
         Servicio: http
         Producto: 
         Versión: 
      └─ Puerto: 443
         Estado: open
         Servicio: https
         Producto: 
         Versión: 
      └─ Puerto: 8080
         Estado: filtered
         Servicio: http-proxy
         Producto: 
         Versión: 
[✓] Escaneo completado en 1 hosts
[✓] Resultados guardados en /tmp/nmap_test_output.json
```

#### **Contenido del Log Generado**

El script produce líneas en formato JSON, una por cada puerto escaneado.
```json
 cat /tmp/nmap_test_output.json            
{"nmap_host": "192.168.0.1", "nmap_host_state": "up", "nmap_protocol": "tcp", "nmap_port": 22, "nmap_port_name": "ssh", "nmap_port_state": "filtered", "nmap_port_product": "", "nmap_port_version": "", "scan_type": "test_rapido"}
{"nmap_host": "192.168.0.1", "nmap_host_state": "up", "nmap_protocol": "tcp", "nmap_port": 80, "nmap_port_name": "http", "nmap_port_state": "open", "nmap_port_product": "", "nmap_port_version": "", "scan_type": "test_rapido"}
{"nmap_host": "192.168.0.1", "nmap_host_state": "up", "nmap_protocol": "tcp", "nmap_port": 443, "nmap_port_name": "https", "nmap_port_state": "open", "nmap_port_product": "", "nmap_port_version": "", "scan_type": "test_rapido"}
{"nmap_host": "192.168.0.1", "nmap_host_state": "up", "nmap_protocol": "tcp", "nmap_port": 8080, "nmap_port_name": "http-proxy", "nmap_port_state": "filtered", "nmap_port_product": "", "nmap_port_version": "", "scan_type": "test_rapido"}
```


### **3.4. Configuración del Agente Wazuh para Leer los Logs**

Es necesario indicar al agente Wazuh que monitorice el archivo donde se escriben los logs del escaneo.

**Verificar la configuración actual:**
```bash
sudo grep -A 2 "active-responses" /home/cft/logs_victima/ossec.conf
```

El resultado esperado debe ser similar a:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/home/cft/logs_victima/nmap-scans.log</location>
</localfile>
```

**Si no existe, agregar la configuración:**
```bash
sudo nano /var/ossec/etc/ossec.conf
```


## Buscar la sección  localfile  y añadir el bloque XML dentro de  ossec_config 

**Permisos y ubicación del script:**
```bash
# Guardar el script
nano ~/wazuh-scripts/nmap-wazuh.py
# Pega el contenido del script elegido
# Dar permisos de ejecución
chmod +x ~/wazuh-scripts/nmap-wazuh.py
# Ejecutar prueba
python3 ~/wazuh-scripts/nmap-wazuh.py
```

### **3.5. Verificación de la Recolección de Logs**

Una vez configurado, se puede verificar en tiempo real que los logs están siendo escritos y que el agente Wazuh los está procesando.

**Comprobar que el script escribe en el archivo de logs:**
```bash
sudo tail -f /home/cft/logs_victima/nmap-scans.log 
```

Salida esperada (actualizándose con cada escaneo):
```json
{"nmap_host": "192.168.0.1", "nmap_host_state": "up", "nmap_protocol": "tcp", "nmap_port": 22, "nmap_port_name": "ssh", "nmap_port_state": "filtered", "nmap_port_product": "", "nmap_port_version": "", "scan_type": "test_rapido"}
...
```

**Comprobar que el agente Wazuh lee el archivo:**
```bash
sudo tail -f /var/ossec/logs/ossec.log | grep "nmap-scans"
```

Salida esperada:
```text
2026/03/18 15:39:11 wazuh-logcollector: INFO: (1957): New file that matches the '/home/cft/logs_victima/*.log' pattern: '/home/cft/logs_victima/nmap-scans.log'.
```

### **3.6. Automatización del Escaneo (Crontab)**

Para que el escaneo se ejecute de forma periódica y automática, se programa una tarea en crontab.
```bash
# Editar el crontab del usuario root
sudo crontab -e
# (Seleccionar nano como editor, opción 1)
# Agregar la siguiente línea al final del archivo para ejecutar el script cada hora
0 * * * * /usr/bin/python3 /home/kali/Estudios/Herramientas/<Nombre_script>.py

_Nota:_ Ajustar la ruta al script y al intérprete de Python según la instalación.
```

---

## **4. Configuración en el Manager Wazuh (Raspberry Pi)**

### **4.1. Verificación del Decoder (JSON)**

Dado que los logs se generan en formato JSON, Wazuh puede procesarlos automáticamente con su decoder `json`. Se puede verificar con la herramienta de test.

**Formato de log de ejemplo:**
```json
{"nmap_host": "192.168.0.1", "nmap_host_state": "up", "nmap_protocol": "tcp", "nmap_port": 8080, "nmap_port_name": "http-proxy", "nmap_port_state": "filtered", "nmap_port_product": "", "nmap_port_version": "", "scan_type": "test_rapido"}
```

Al introducir este log en la herramienta **Decoders Test** del dashboard de Wazuh, se confirma que alcanza la **Phase 2 (decoding)** sin necesidad de un decoder personalizado.

![Decoders](/assets/images/posts/project/nmap-wazuh/decoder.png)

_Captura: Resultado del test de decoder mostrando Phase 2._

### **4.2. Creación de Reglas Personalizadas**

Las reglas se añaden en el archivo `local_rules.xml` del manager. Esto se puede hacer tanto por consola como por el navegador.

**Desde la consola del manager (Raspberry Pi):**
```bash
# Editar el archivo de reglas locales
sudo nano /var/ossec/etc/rules/local_rules.xml
```

**Desde el navegador Wazuh:**  
_Navegación:_ `Management` → `Ruleset` → `Manage rules files` → Seleccionar `local_rules.xml` y editar.

**Contenido a añadir en `local_rules.xml`:**
```xml
<group name="nmap,network,scan,">
    <!-- Regla base: detecta cualquier evento de nmap -->
    <rule id="200400" level="3">
        <decoded_as>json</decoded_as>
        <field name="nmap_host">\.+</field>
        <description>NMAP: Escaneo detectado - Host $(nmap_host) tiene puerto $(nmap_port) ($(nmap_port_name)) - Estado: $(nmap_port_state)</description>
        <options>no_full_log</options>
    </rule>
    <!-- Regla de correlación: múltiples puertos en el mismo host -->
    <rule id="200401" level="7" frequency="8" timeframe="120">
        <if_matched_sid>200400</if_matched_sid>
        <same_source_ip />
        <description>NMAP: Posible escaneo de puertos - Se detectaron 8+ puertos en $(nmap_host) en 2 minutos</description>
        <mitre>
            <id>T1046</id> <!-- Network Service Scanning -->
        </mitre>
    </rule>
    <!-- Regla para puertos abiertos específicos (más crítica) -->
    <rule id="200402" level="5">
        <if_sid>200400</if_sid>
        <field name="nmap_port_state">open</field>
        <description>NMAP: Puerto ABIERTO detectado en $(nmap_host):$(nmap_port) - $(nmap_port_name)</description>
    </rule>
</group>
```

### **4.3. Verificación de Sintaxis y Reinicio del Servicio**

Es crucial verificar que las reglas no contengan errores de sintaxis antes de reiniciar el servicio.

**Verificar sintaxis:**
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Si no hay errores, el comando no devuelve nada (o indica OK).

**Reiniciar el servicio Wazuh Manager:**  
_Desde consola:_
```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager  # Verificar que está "active (running)"
```

_Desde el navegador:_  
`Server Management` → `Settings` → `Editar` → `Restart manager`

---

## **5. Resultados en el Dashboard (Threat Hunting)**

Una vez realizados los pasos anteriores, al ejecutar un escaneo con el script, las alertas aparecen en el dashboard de Wazuh.

![Wazuh-Manager](/assets/images/posts/project/nmap-wazuh/wazuh-report-log.png)
_Captura: Eventos en Threat Hunting mostrando las reglas 200400, 200401 y 200402 activadas por los logs de Nmap._

---

## **6. Análisis y Explicación de las Reglas Personalizadas**

Para un entendimiento más profundo, se desglosa la lógica de cada regla implementada:

|ID Regla|Nivel|Lógica de Detección|Contexto de Seguridad (MITRE ATT&CK)|
|---|---|---|---|
|**200400**|3|Se activa por cada puerto detectado en un host. Usa `<decoded_as>json</decoded_as>` para procesar el log y `<field name="nmap_host">\.+</field>` para asegurar que existe el campo.|**Técnica:** Escaneo de Puertos (T1046). Nivel bajo para informar del descubrimiento de un servicio.|
|**200402**|5|Se activa cuando un puerto específico tiene el estado "open". Hereda de la regla 200400 (`<if_sid>200400</if_sid>`).|**Técnica:** Escaneo de Puertos (T1046). Nivel medio, ya que un puerto abierto es un punto de entrada potencial.|
|**200401**|7|Regla de correlación. Se activa si en 120 segundos se detectan 8 o más eventos de la regla 200400 desde el mismo host (`<same_source_ip />`).|**Técnica:** Escaneo de Puertos (T1046). Nivel alto, ya que múltiples puertos en poco tiempo indican un escaneo activo y malicioso.|

---

## **7. Consideraciones de Rendimiento y Precisión**

- **Falsos Positivos:** Las reglas están diseñadas para un laboratorio. En producción, el nivel 7 de la regla `200401` podría necesitar ajustes en `frequency` y `timeframe` para evitar alertar por escaneos de herramientas de administración legítimas.
- **Impacto en Red:** El script original de SOCFortress escanea subredes enteras (`/24`). Es crucial ajustar los objetivos (`targets`) en producción para no saturar la red o ser detectado como un atacante por otros sistemas de seguridad.
- **Recursos del Agente:** El escaneo de red puede consumir CPU. La programación con `cron` (por ejemplo, cada hora) es una práctica excelente para equilibrar visibilidad y rendimiento.
    

---

## **8. Mejoras y Próximos Pasos (Ideas para la Versión 3.0)**

- **Integración con Active Response:** Automatizar el bloqueo temporal de una IP que dispare la regla `200401` usando un script de respuesta activa de Wazuh.
- **Enriquecimiento de Datos:** Utilizar `CDB lists` de Wazuh para correlacionar las IPs escaneadas con listas de activos críticos (servidores de base de datos, etc.) y elevar el nivel de alerta si se escanea un puerto sensible en un activo crítico.
- **Dashboard Personalizado:** Crear un dashboard específico en Wazuh que muestre la actividad de escaneo, los puertos abiertos más comunes y los hosts más escaneados, para una visibilidad más rápida.
    

---

## **9. Conclusión Final**

La integración de Nmap con Wazuh convierte un escáner de red manual en un sensor de descubrimiento de activos continuo y automatizado. Las reglas personalizadas permiten no solo detectar el "qué" (un puerto abierto), sino también el "cómo" (un escaneo agresivo) y enriquecerlo con inteligencia de amenazas (MITRE ATT&CK). Este proyecto demuestra la capacidad de construir casos de uso de seguridad a medida sobre una plataforma SIEM de código abierto, una habilidad esencial para cualquier analista de ciberseguridad.

---


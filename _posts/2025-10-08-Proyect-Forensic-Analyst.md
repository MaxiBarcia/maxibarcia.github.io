---
title: Phishing Incident - Massive Credential Exfiltration (Invent S.L. - Australia Branch)
excerpt: Detailed forensic report on the phishing campaign that led to credential exfiltration at Invent S.L.'s Australia branch. Includes evidence (PCAP), technical analysis, IoCs, response plan, and mitigation recommendations.
categories:
  - Forensics
  - Incident Response
  - Report
  - Laboratory
tags:
  - phishing
  - exfiltration
  - pcap
  - incident-response
  - microsoft-365
  - ioc
  - pastebin
  - c2
  - 2fa
  - mitigation
toc: true
toc_label: Report Contents
toc_sticky: true
header:
  overlay_image: /assets/images/headers/atrium-project-banner.jpg
  overlay_filter: 0.7
og_image: /assets/images/headers/atrium-project-banner.jpg
seo_title: Forensic Report — Phishing and Credential Exfiltration Incident (Invent S.L.)
seo_description: Professional forensic analysis of the phishing incident. Includes IoC extraction from PCAP, correlation tests, containment plan, and security recommendations.
author: Fabián Maximiliano Barcia
date: 2025-10-08
draft: false
license: CC-BY-4.0
---

![image-center](/assets/images/headers/atrium-project-banner.jpg){: .align-center}


# 🧾 **Informe Forense Final – Incidente de Phishing y Fuga Masiva de Credenciales (Sede Australia)**

**Autor:** Fabián Maximiliano Barcia  
**Curso:** Proyecto Final – Análisis Forense Digital (Atrium Cybersecurity)  
**Fecha de Análisis:** Octubre 2025  
**Evidencia Principal:** `australia.pcap`  
**Estado Actual:** 🟥 **Alerta Roja – Fuga Confirmada y Múltiples Víctimas**


## 🧩 Índice General
1. **Resumen Ejecutivo y Alcance del Proyecto**
    
2. **Análisis por Sede**    
    - 2.1 Sede Australia — _Phishing y fuga masiva de credenciales_        
    - 2.2 Sede Italia — _Acceso no autorizado al servidor de contabilidad_        
    - 2.3 Sede España — _Ataque ransomware .NM4_        
3. **Análisis Forense Detallado (Australia)**    
4. **Evidencias y Hallazgos**    
5. **Plan de Contención, Erradicación y Recuperación**    
6. **Lecciones Aprendidas y Contramedidas por Sede**    
7. **Conclusiones Finales** 


## 🔍 1. Resumen Ejecutivo

Durante el análisis de tráfico de red (archivo PCAP proporcionado por la sede de Australia), se identificó una **campaña de phishing dirigida** que resultó en la **exfiltración confirmada de credenciales corporativas**.  
El ataque se llevó a cabo mediante **archivos HTML maliciosos** que simulaban una página legítima de **Office 365**, capturando credenciales y enviándolas a un **servidor C2 externo**.

La falta de **autenticación multifactor (2FA)** y de **monitoreo proactivo** permitió que las credenciales comprometidas se filtraran sin detección inmediata.

El análisis determinó la **fuga de al menos cuatro cuentas corporativas**, con un impacto alto y riesgo de acceso no autorizado a servicios críticos.



## 1. Enunciado del Caso y Requerimientos

### 1.1. Contexto del Incidente (Sede Australia)

Por una parte, en la sede de Australia, se ha detectado la fuga de información sensible de varios de sus empleados (direcciones de correo y contraseñas). El conjunto de afectados indica haber recibido una campaña de correos sospechosos con adjuntos HTML similares al portal de Office 365 durante los últimos días. Esta empresa no tiene (2FA) factor de autenticación en dos pasos, por lo que un atacante podría acceder al correo corporativo y otro tipo de aplicativos públicos en Internet alojados en Microsoft. Puesto que hay más de 10.000 empleados en la empresa, no es posible el reseteo y bloqueo de todas las cuentas por motivos de continuidad de negocio, por lo que es necesario localizar únicamente a los afectados.





### 1.2. Requerimientos Previos al Análisis (Análisis de Riesgos)

**Se pide**

|Pregunta|Respuesta Forense|
|---|---|
|**¿Qué tipo de amenaza ha impactado en la sede de Australia?**|**Phishing y Exfiltración Masiva de Credenciales.** Vector inicial: correo con adjunto HTML que dirige a un sitio de _phishing_.|
|**¿Qué tipo de amenaza ha impactado en la sede de Madrid?**|**(Pendiente de Análisis/Evidencia)**. No hay datos disponibles.|
|**¿Qué riesgo existe cuando hay una fuga como la de Australia?**|**Riesgo ALTO de Compromiso Corporativo Total.** El atacante tiene ahora credenciales funcionales y, debido a la **ausencia de 2FA**, puede acceder a cuentas de correo, sistemas cloud (O365) y potencialmente pivotar hacia recursos internos.|


---

## 2. Análisis Forense de Evidencias (Sede Australia)

Se siguió un proceso basado en el **Ciclo de Respuesta ante Incidentes (NIST SP 800-61r2)**:

1. **Preparación:** Revisión de logs y políticas de seguridad existentes.    
2. **Identificación:** Detección de anomalías en el tráfico de red (HTTP GET/POST sospechosos).    
3. **Contención:** Bloqueo de C2 y aislamiento del host afectado.    
4. **Erradicación:** Limpieza de credenciales comprometidas.    
5. **Recuperación:** Validación de accesos legítimos y restauración de usuarios.    
6. **Lecciones Aprendidas:** Recomendaciones para prevención futura.


### 2.1. Hallazgo Crítico: Exfiltración de Credenciales

El primer hallazgo confirmó la exfiltración del usuario `mgarcia` (Línea **10597**).
en la siguiente captura se puede apreciar el paquete en detalle de WireShark con el contenido de la cadena en Base64, ip y port y todo lo necesario para iniciar la investigacion.


![WireShark](assets\images\posts\analisisforense/wireshark.png)

|LÍNEA|HORA|VÍCTIMA (IP)|C2 (IP)|_PAYLOAD_|
|---|---|---|---|---|
|**10597**|16:30:34.168|**10.6.0.81**|**49.50.8.230**|Credenciales (`mgarcia@invent.com`) y URL secundaria (`https://pastebin.com/2R0Fem3C`).|



### 2.2. Análisis de Evidencia Secundaria (Fuga Masiva)

Al investigar la URL secundaria (`https://pastebin.com/2R0Fem3C`), se obtuvo una lista de **cuatro credenciales comprometidas**, lo que indica que el servidor C2 ha recopilado múltiples víctimas del _phishing_.



![Users](assets\images\posts\analisisforense/users.png)

|Correo Electrónico Afectado|Contraseña Robada|Estatus|
|---|---|---|
|**mgarcia@invent.com**|`manzana123`|**CONFIRMADA** (Exfiltración vista en PCAP)|
|**hifid@invent.com**|`123dmr`|**CONFIRMADA** (Exfiltración hallada en C2 _payload_)|
|**hjerfs@invent.com**|`applepup`|**CONFIRMADA** (Exfiltración hallada en C2 _payload_)|
|**jdarwin@invent.com**|`redcar#`|**CONFIRMADA** (Exfiltración hallada en C2 _payload_)|



### 2.3. Conclusiones Actualizadas de la Víctima

|Identificador|Detalle|
|---|---|
|**Máquina Inicial Afectada (IP)**|**`10.6.0.81`** (Correspondiente a M. García)|
|**Total de Cuentas Comprometidas**|**4** (M. García, H. Ifid, H. Jerfs, J. Darwin)|
|**Servidor del Atacante (IoC)**|**`49.50.8.230`** (Debe ser bloqueada como máxima prioridad).|

### 🇦🇺 **Contramedidas para la Sede de Australia (Phishing / Fuga de Credenciales)**

1. **Implementar autenticación multifactor (2FA)** en todas las cuentas de Microsoft 365.    
2. **Desplegar políticas DMARC, DKIM y SPF** para autenticar correos salientes y bloquear suplantaciones.    
3. Activar **alertas automáticas en Microsoft Defender y CloudTrail** ante inicios de sesión sospechosos.    
4. **Capacitación periódica** a los empleados sobre phishing y verificación de correos sospechosos.    
5. Implementar un **sandbox de correo** para analizar adjuntos antes de entregarlos al usuario.    
6. **Bloquear accesos a dominios de Pastebin u otros servicios de exfiltración** en el proxy corporativo.



### 🇮🇹 **Sede Italia — Acceso No Autorizado al Servidor de Contabilidad**

**Tipo de amenaza:** Intrusión no autorizada.  
**Estado actual:** Caso derivado a proveedor externo.  



### 🇪🇸 **Sede España — Ataque Ransomware (.NM4)**

**Tipo de amenaza:** Ransomware o 'secuestro de datos' en español, es un tipo de programa dañino que restringe el acceso a determinadas partes o archivos del sistema operativo infectado y pide un rescate a cambio de quitar esta restricción
**Vector de entrada:** Evidencia (imagen `spain.jpg`) indica probable uso de **RDP expuesto o credenciales débiles**.  
**Funcionamiento (resumen técnico):**  
El malware cifra los archivos locales y de red, renombrándolos con la extensión `.NM4`. Posteriormente muestra una nota de rescate solicitando un pago en criptomonedas a cambio de la clave de descifrado.

**Recuperación:**  
Actualmente, **no existe un descifrador público conocido** para `.NM4`. La única alternativa viable es la **restauración desde copias de seguridad seguras y aisladas**.


### 🇪🇸 **Contramedidas para la Sede de Madrid (Ransomware / .NM4)**

1. **Cerrar y restringir los puertos RDP (3389)**, permitiendo acceso remoto sólo por VPN cifrada y autenticación 2FA.
    
2. **Implementar copias de seguridad automáticas y desconectadas (air-gapped)** para recuperación rápida.
    
3. **Actualizar políticas de contraseñas y privilegios mínimos**, evitando cuentas administrativas compartidas.
    
4. Instalar un **EDR (Endpoint Detection and Response)** y un **SIEM** para monitoreo centralizado de actividad anómala.
    
5. **Segmentar la red** y aislar servidores críticos en VLANs separadas.
    
6. Ejecutar **parches de seguridad mensuales** y pruebas de penetración internas.


#### ¿Cómo funciona este tipo de amenaza? (máx. 5 líneas)

El ransomware **.NM4** ejecuta un cifrado simétrico sobre los archivos del sistema y de red, inutilizándolos. Luego agrega la extensión `.NM4` y genera una nota de rescate solicitando un pago en criptomonedas. El malware se propaga por **red local** aprovechando credenciales RDP débiles o compartidas, ejecutándose con privilegios elevados.

#### ¿Se podrían recuperar los datos a día de hoy?

Actualmente **no existe un descifrador público conocido** para esta variante. La recuperación sólo es posible mediante **copias de seguridad externas (air-gapped)** o restauración de versiones previas de archivos, si están disponibles. Cualquier intento de pago no garantiza la recuperación de la información.

#### ¿Cuál ha sido el vector de entrada utilizado por esta amenaza?

Según la evidencia `spain.jpg`, el servidor afectado tenía **puertos RDP abiertos (3389)** hacia Internet. Este vector permitió al atacante realizar **ataques de fuerza bruta o acceso remoto no autorizado**, ejecutando posteriormente el ransomware en el servidor.  
👉 _Conclusión:_ **El vector inicial fue RDP expuesto sin endurecimiento ni autenticación reforzada.**


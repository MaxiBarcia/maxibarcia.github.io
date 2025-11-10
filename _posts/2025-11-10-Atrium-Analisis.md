---
title: Análisis Exhaustivo de Seguridad en Aplicaciones Android (APKs) - Riesgos OWASP Mobile Top 10
excerpt: Reporte detallado del análisis de vulnerabilidades realizado sobre tres tipos de aplicaciones Android (.apk) —oficial, no oficial y deliberadamente vulnerable—. Se aplica la metodología de análisis estático (MobSF, JADX) y dinámico (Drozer, Burp Suite) para identificar y explotar riesgos críticos del OWASP Mobile Top 10 (M4, M3, M9).
categories:
 - Seguridad Móvil
 - Análisis de Vulnerabilidades
 - Reporte
 - Laboratorio
tags:
 - owasp-mobile
 - android
 - apk
 - mobsF
 - drozer
 - burp-suite
 - analisis-estatico
 - analisis-dinamico
 - M4-insegura
 - M3-comunicacion
toc: true
toc_label: Contenido del Reporte
toc_sticky: true
header:
  overlay_image: /assets/images/headers/phishing-banner.jpg
  overlay_filter: 0.7
og_image: /assets/images/headers/phishing-banner.jpg
seo_title: Análisis de Vulnerabilidades en APKs (MobSF, Drozer, Burp) - OWASP Mobile Top 10
seo_description: Auditoría profesional de seguridad en aplicaciones Android. Metodología de análisis estático y dinámico para explotar riesgos M4 (Content Providers) y M3 (Clear Text Traffic) según el estándar OWASP.
author: [Tu Nombre Completo]
date: 2025-11-07
draft: false
license: CC-BY-4.0
---

## Enunciado proyecto :

Seguridad en Smartphones

### Enunciado:

A lo largo de los contenidos se ha hablado de OWASP, análisis estático y análisis dinámico, vulnerabilidades, desarrollo seguro, etc. Los Smartphones no quedan libres de ataques. OWASP define un top 10 de riesgos en aplicaciones para dispositivos móviles (https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10).

### Se pide:

A partir de los contenidos estudiados y tras leer el enunciado anterior, analiza al menos tres aplicaciones (.apk) en busca de vulnerabilidades.

- Una apk no oficial, con vulnerabilidades deliberadamente introducidas, y que se publican en internet para prácticas de entrenamiento.
- Una descargada de algún repositorio no oficial de apks.
- Una descargada desde una tienda oficial.

Para el análisis se deben utilizar tanto herramientas stand-alone como online, de manera que produzcan resultados complementarios y completen un análisis exhaustivo de las aplicaciones.

En cualquier caso, una vez seleccionadas las herramientas, se puede organizar el trabajo de análisis siguiendo las siguientes tareas:

1. Recolección de información (definir alcance y secciones a evaluar).
2. Análisis estático (observar recursos de la app, código fuente, ficheros de configuración, etc.).
3. Análisis dinámico (ejecutar la app y monitorizar la actividad).

------

Este resumen encapsula la metodología y los hallazgos clave obtenidos durante el análisis de vulnerabilidades de aplicaciones Android (`.apk`), siguiendo las directrices del curso y los riesgos definidos por la **OWASP Mobile Top 10**.

---

## 1. Metodología de Análisis

El proyecto se estructuró en tres fases sobre tres tipos de APKs:

1. **Recolección:** Definición del alcance y preparación del entorno.
    
2. **Análisis Estático:** Inspección sin ejecutar el código (MobSF, JADX).
    
3. **Análisis Dinámico:** Monitorización en tiempo real (ADB, Emulador, Burp Suite, Drozer/Frida).
    

### 1.1 Herramientas Utilizadas

|Fase|Herramienta|Propósito en el Proyecto|
|---|---|---|
|**Entorno**|**Android Studio/AVD**|Creación de un emulador **rooteado** (Pixel 7a) para pruebas dinámicas.|
|**Conectividad**|**ADB** (`.\adb`)|Instalación de APKs, acceso a la `shell` del emulador y transferencia de archivos.|
|**Estático**|**MobSF**|Escaneo automático de permisos, Manifest, URL, código nativo y secretos.|
|**Estático**|**JADX**|Descompilación de APK a código Java legible para inspección manual de código inseguro.|
|**Dinámico**|**Burp Suite**|Intercepción y análisis del tráfico de red (HTTP/HTTPS) de la aplicación.|
|**Dinámico**|**Drozer**|Explotación y prueba de la comunicación insegura entre componentes (IPC).|
Se isntalo MobsF para analizar la APK
https://github.com/MobSF/Mobile-Security-Framework-MobSF
```json
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Default username and password: mobsf/mobsf
```
una vez instalado el MobSF se realizo el scaneo de la APK no oficial dando un reporte completo. 



---

## 2.              Análisis del Caso Práctico (APK No Oficial: MagicTV)

El análisis estático con MobSF sobre la APK no oficial (`MagicTV`) reveló múltiples fallos de seguridad críticos:

### A. Vulnerabilidades HIGH

|N°|Vulnerabilidad|OWASP M Top 10 (2016)|Impacto y Próxima Acción|
|---|---|---|---|
|**1.**|**Clear Text Traffic Enabled**|**M3: Transmisión de Datos Insegura**|La app usa tráfico HTTP no cifrado, permitiendo ataques **Man-in-the-Middle (MITM)**. **ACCIÓN DINÁMICA CLAVE:** Confirmar la fuga de datos sensibles usando **Burp Suite**.|
|**2.**|**Minimun SDK Anticuado (API 19)**|**M9: Código Fuente Obsoleto**|La compatibilidad con versiones antiguas expone a la app a _exploits_ del sistema operativo ya parcheados en versiones modernas.|
|**3.**|**Falta de RELRO en Librería Nativa**|**M9: Código Fuente Obsoleto**|La librería nativa (`libcrashlytics-common.so`) tiene la GOT escribible. Falla la mitigación de seguridad binaria, aumentando el riesgo de **Ejecución Remota de Código (RCE)** vía _buffer overflows_.|

### B. Vulnerabilidades WARNING (Riesgo de Componentes)

|Vulnerabilidad|Detalle|Impacto de Explotación|
|---|---|---|
|**Activity Exportada**|`com.mobile.brasiltv.activity.MainAty` está exportada (`exported=true`) sin protección de permisos.|Permite que una app maliciosa lance la Activity (posiblemente con datos maliciosos), exponiendo una vulnerabilidad de **Interacción Insegura entre Componentes (M4)**. **ACCIÓN DINÁMICA:** Probar la invocación con **Drozer**.|
|**Vulnerabilidad Janus**|Uso del esquema de firma v1.|Permite la inyección de código malicioso en la APK sin romper la firma en versiones de Android 5.0 a 8.0.|

Se procede a instalar el **ATPKTOOLS** y asi pode desencriptar la applicacion ya podeer trabajar con ella.
https://apktool.org/docs/install
https://bitbucket.org/iBotPeaches/apktool/downloads/
![[Pasted image 20251015133734.png|500]]

En la siguiente captura se puede apreciar como se revisa la APK en la web **virustotal**
![[Pasted image 20251015135853.png]]
Luego de virus total se procede a scanearlo con **mobSF**
![[Pasted image 20251015163257.png]]
![[Pasted image 20251015164836.png]]
![[Pasted image 20251023133034.png]]
se intenta realizar el dinamico pero sin respuesta alguna. 
![[Pasted image 20251015163326.png]]

Empezamos a analizar elc odigo y se pueden ver algunos permisos fuera de lugar para una aplicacion de streaming

![[Pasted image 20251015163536.png]]


en la siguiente captura se peude ver como se navega en JADX 
![[Pasted image 20251015172528.png]]




---

## 3                 Caso practico de una APK deliberadamente vulnerable. 
 **InsecureBankV2**  :  https://github.com/dineshshetty/Android-InsecureBankv2 
![[Pasted image 20251014120837.png|700]]
![[Pasted image 20251014121059.png|700]]

En la siguiente captura se puede ver el codigo fuente de la aplicacion que muestra AndroidManifest.xml
![[Pasted image 20251014130337.png|700]]
![[Pasted image 20251014130454.png|700]]
Revisando el codigo fuente de Login
![[Pasted image 20251015124304.png|700]]

Se pago el APK por virus total
![[Pasted image 20251015125323.png]]
Se descargo la base mydb y se accedio desde sqlite3.exe pero solo almacena nombes e id. 
![[Pasted image 20251014190635.png|700]]



Para utilizar BURPSUITE en el emulador.
https://www.youtube.com/watch?v=klklh5IvrBg&t=178s



## 4                               Escaneando una Aplicacion Oficial (chatgpt)

Se procede a generar una APK de chatpgt para realizar la comprobacion.

![[Pasted image 20251015173720.png]]

una vez generado el APK se envia al mobsf para su comprobacion.
Luego se a realizado los scaneos de manera privada. 
En la siguietne captura se puede apreciar como nos da un reporte del APK
![[Pasted image 20251015173627.png]]
![[Pasted image 20251015173627.png]]


------

## Analisis Dinamico. 

Se realiza la insatlacion de drozer ya que mosfb no esta funcionando. 

![[Pasted image 20251015200635.png]]
Una vez instalado drozer y conectado se revisa el
El valor **`null`** en los permisos de lectura y escritura significa que el componente **no tiene ninguna protección**, permitiendo el acceso indiscriminado.

**Authority**`com.android.insecurebankv2.TrackUserContentProvider`Este es el componente que gestiona el acceso a la base de datos (`mydb`).

![[Pasted image 20251015203806.png]]
**Authority**`com.android.insecurebankv2.TrackUserContentProvider` Este es el componente que gestiona el acceso a la base de datos (`mydb`).

**Read Permission****null****¡VULNERABILIDAD M4 CONFIRMADA!** Cualquier aplicación en el dispositivo (simulada por Drozer) puede **leer** datos de este proveedor.

**Write Permission****null****¡VULNERABILIDAD M4 CONFIRMADA!** Cualquier aplicación en el dispositivo puede **escribir o modificar** datos de este proveedor.


## Se me complico el analisis dinamico, aun tengo muy pocos conocimientos en smartphone. 
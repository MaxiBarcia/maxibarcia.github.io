---
title: "Proyecto JARVIS: Infraestructura de IA para un Laboratorio de Ciberseguridad"
description: "Diseño e implementación de una IA central (Claude Code) que administra un laboratorio de pentesting en VirtualBox: servidor MCP, SSH con mínimo privilegio, fronteras de confianza y modelo de amenazas."
project: "JARVIS - IA central personal + laboratorio"
platform: "Claude Code / MCP / VirtualBox 7.2"
os: "Windows 11 (host) + Kali Linux (VM)"
categories: [proyectos, ia, homelab]
tags:
 - AI
 - ClaudeCode
 - MCP
 - VirtualBox
 - KaliLinux
 - OpenSSH
 - Hardening
 - LeastPrivilege
 - ThreatModeling
 - Homelab

hashtags:
 - "#AI"
 - "#ClaudeCode"
 - "#MCP"
 - "#Homelab"
 - "#Hardening"
 - "#ThreatModeling"

image:
  path: /assets/img/posts/project/jarvis/banner.svg

toc: true
toc_label: "Contenido"
toc_sticky: true

---
  

**Autor:** Maximiliano Barcia (Kad)
**Fecha:** 08-11-2026
**Versión:** 1.0 — Fase de infraestructura
 

---

## Resumen Ejecutivo

  
Este proyecto documenta la construcción de la **base de infraestructura de "JARVIS"**: una IA central personal (basada en **Claude Code**) que administra mi laboratorio de ciberseguridad, mi aprendizaje y las IAs de mis proyectos de GitHub.
 

En esta primera fase se logró que la IA del equipo anfitrión (Windows) **controle el laboratorio de VirtualBox y opere la Kali Linux** mediante un servidor **MCP** propio, y que la Kali pueda conectarse de vuelta al anfitrión por **SSH con un usuario de mínimo privilegio**, sin exponer ningún servicio a la red WiFi.
  

El aspecto más importante del proyecto no fue la conectividad sino la **seguridad del diseño**: un laboratorio de hacking es, por definición, un entorno que puede comprometerse. Por eso se definieron **fronteras de confianza** explícitas y se corrigió una debilidad de diseño crítica detectada durante el propio montaje: el código que la IA ejecuta en el anfitrión estaba en una carpeta que la Kali podía modificar.

  
### Resultados

| Componente | Estado |
|---|---|
| IA en Windows controla VMs y Kali (MCP `kali-lab`) | ✅ Operativo |
| Kali → Windows por SSH con usuario limitado, solo loopback | ✅ Operativo y verificado |
| "Cerebro" compartido entre ambas IAs (instrucciones y memoria) | ✅ Operativo |
| Código ejecutable de la IA fuera del alcance de la Kali | ✅ Corregido |
| Estructura de JARVIS (perfil, estado, IAs por proyecto) | ✅ Creada |

  

### Hallazgos de seguridad del propio diseño  

| Severidad | Hallazgo | Estado |
|---|---|---|
| 🔴 **Crítica** | Servidor MCP (ejecutado en el host con el usuario principal) ubicado en carpeta compartida con **escritura** desde la Kali | ✅ Mitigado (movido fuera del recurso compartido) |
| 🟠 **Alta** | Opción evaluada de dar a la Kali una shell SSH con el usuario principal | ✅ Evitado (usuario dedicado sin admin) |
| 🟡 **Media** | Otras VMs de las redes NAT pueden alcanzar el puerto SSH del host vía loopback | ⚠️ Aceptado (solo llave, servicio manual) |
| 🟡 **Media** | Carpeta de descargas compartida con escritura contiene material sensible (VPN/llaves) | ⏳ Pendiente |

  

---

  

## 1. Contexto y Objetivos

  Trabajo en ciberseguridad (CTF en Hack The Box, PortSwigger y, a futuro, bug bounty) con un laboratorio local en VirtualBox: una **Kali Linux** como atacante y varias máquinas objetivo vulnerables.

  
**Objetivos de esta fase:**

  - Que una IA pueda **operar el laboratorio**: encender/apagar VMs, tomar snapshots y ejecutar comandos en la Kali.
- Poder trabajar **desde la Kali** con una IA que tenga acceso controlado al anfitrión.
- Compartir instrucciones y memoria entre ambas IAs.
- Hacerlo aplicando **mínimo privilegio** y **defensa en profundidad**, asumiendo que la Kali puede llegar a comprometerse.
- Crear la estructura base de JARVIS para las siguientes fases.

  

---

  

## 2. Arquitectura
  
### 2.1 Diagrama general

  
```

┌──────────────────────── WINDOWS 11 (HOST) ─────────────────────────┐

│                                                                    │

│  JARVIS (Claude Code)                                              │

│   ├── M:\Jarvis\            ← instrucciones, perfil, estado        │

│   └── MCP "kali-lab"        ← M:\Documentos\kali-mcp\server.py     │

│          │  VBoxManage (ciclo de vida de VMs)                      │

│          │  SSH → 127.0.0.1:2222 (port-forward) → Kali:22          │

│          ▼                                                         │

│  sshd (OpenSSH Server) escuchando SOLO en 127.0.0.1:22             │

│   └── usuario "labclaude" (estándar, sin admin, solo llave)        │

│                                                                    │

│  Recursos compartidos de VirtualBox (RW):  M:\GitHub , Descargas   │

└───────────────┬──────────────────────────────────▲─────────────────┘

                │ NAT Network "Red_NAT" 10.0.2.0/24│

                ▼                                  │ ssh windows

┌──────────── KALI LINUX (VM) ─────────────┐       │ (10.0.2.1 → host 127.0.0.1)

│ eth1: 10.0.2.3 (reserva DHCP)            │───────┘

│ ~/cerebro → /media/sf_GitHub/claude      │

│ Claude Code (operador de laboratorio)    │

└──────────────────────────────────────────┘

```

  

### 2.2 Componentes

| Componente       | Tecnología                              | Función                                               |
| ---------------- | --------------------------------------- | ----------------------------------------------------- |
| JARVIS           | Claude Code (Windows)                   | IA central: administra laboratorio, perfil, proyectos |
| `kali-lab`       | Servidor MCP en Python (paquete `mcp`)  | Expone herramientas para VMs y Kali                   |
| Kali_Laboratorio | Kali Linux en VirtualBox                | Máquina atacante / operador                           |
| Red_NAT          | NAT Network de VirtualBox `10.0.2.0/24` | Red del laboratorio                                   |
| sshd             | OpenSSH Server de Windows               | Acceso Kali → host                                    |
| `labclaude`      | Usuario local estándar                  | Identidad limitada para la Kali                       |
| `M:\lab-share`   | Carpeta NTFS                            | Único lugar de escritura para `labclaude`             |

  

### 2.3 Fronteras de confianza

Esta es la decisión de diseño central del proyecto:


| Zona | Confianza | Contenido | Quién escribe |
|---|---|---|---|
| `M:\Jarvis`, `M:\Documentos` | 🟢 Alta | Instrucciones de JARVIS, servidor MCP | Solo el host |
| `M:\GitHub` (compartido RW) | 🔴 Baja | Repos, "cerebro" compartido | Host **y Kali** |
| Kali | 🔴 Baja | Herramientas ofensivas, objetivos | — |


---

## 3. Implementación

### 3.1 Servidor MCP `kali-lab`: la IA controla el laboratorio
  
**MCP (Model Context Protocol)** es un protocolo abierto que permite conectar herramientas externas a un asistente de IA. Desarrollé un servidor MCP en Python que expone estas herramientas a Claude Code:

  
| Herramienta | Qué hace |
|---|---|
| `vm_list`, `vm_info` | Lista VMs y estado (vía `VBoxManage`) |
| `vm_start`, `vm_stop` | Enciende / apaga VMs |
| `vm_snapshot_list/take/restore` | Gestión de snapshots (volver a un estado limpio) |
| `kali_exec` | Ejecuta comandos en la Kali por SSH |
| `kali_upload`, `kali_download` | Transferencia de archivos |
| `kali_status` | Comprueba conectividad (hostname, usuario, IPs) |
  

La conexión a la Kali usa una **llave SSH dedicada** y un *port-forward* de la NAT Network que solo escucha en el loopback del host:
 
```

kali-ssh: tcp  [127.0.0.1]:2222  →  [10.0.2.3]:22

```
  
Registro en Claude Code (alcance de usuario):

```powershell

claude mcp add kali-lab --scope user -- python M:\Documentos\kali-mcp\server.py

```

  

Verificación:

```text

kali_status →

kali

kali

eth1   UP   10.0.2.3/24

```


### 3.2 Evaluación de alternativas: ¿cómo trabajar desde la Kali?

El objetivo era usar la IA desde la Kali y que pudiera operar sobre el host. Se evaluaron cuatro opciones:

| Opción | Ventaja | Problema | Decisión |
|---|---|---|---|
| Remote Control (controlar la sesión del host desde el navegador) | Sin abrir puertos | No disponible con autenticación por API key | ❌ |
| Claude Code en la Kali, sin acceso al host | Aislamiento total | No puede operar el host | Base |
| Servidor MCP en el host expuesto por HTTP | Herramientas acotadas | Más desarrollo; mismo riesgo si se expone una shell | Futuro |
| **SSH Kali → host con usuario limitado** | Flexible y estándar | Requiere hardening cuidadoso | ✅ Elegida |
  

Se descartó explícitamente dar SSH con el **usuario principal**: si la Kali se compromete, el atacante tendría acceso completo a la PC.

  
### 3.3 SSH Kali → Windows con mínimo privilegio

  Todo se automatizó en un script de PowerShell que se ejecuta como administrador. Medidas aplicadas:

  **1) Usuario dedicado, estándar, con contraseña aleatoria que nunca se usa:**

  

```powershell

$chars = (48..57) + (65..90) + (97..122) + (33,35,36,37,42,43,45,61,63,64)

$plain = -join (1..32 | ForEach-Object { [char]($chars | Get-Random) })

New-LocalUser -Name labclaude -Password (ConvertTo-SecureString $plain -AsPlainText -Force) `

    -PasswordNeverExpires -UserMayNotChangePassword -Description 'Claude desde Kali (SSH solo llave)'

# Grupo "Users" por SID: funciona en Windows en cualquier idioma

Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545').Name -Member labclaude

```
 

**2) Autenticación solo por llave (ed25519 generada en la Kali), con el archivo de llaves protegido:**

  
```powershell

$ak = "$env:ProgramData\ssh\labclaude_authorized_keys"

Set-Content -Path $ak -Value $PubKey -Encoding ascii

icacls $ak /inheritance:r /grant 'SYSTEM:F' /grant '*S-1-5-32-544:F'

```
 

Ubicar `authorized_keys` en `ProgramData` (y no en el perfil del usuario) evita que el propio `labclaude` pueda agregarse llaves.

  

**3) `sshd_config` endurecido** (las directivas se insertan al **inicio** del archivo: OpenSSH usa el primer valor encontrado y el archivo por defecto de Windows termina en un bloque `Match`):


```text

ListenAddress 127.0.0.1

PasswordAuthentication no

PubkeyAuthentication yes

PermitEmptyPasswords no

AllowUsers labclaude

AllowTcpForwarding no

GatewayPorts no

MaxAuthTries 3

  

Match User labclaude

       AuthorizedKeysFile __PROGRAMDATA__/ssh/labclaude_authorized_keys

```

  

**4) Sin exposición de red:** al escuchar solo en `127.0.0.1` no hace falta abrir el firewall; la regla que crea OpenSSH por defecto se desactiva.


```powershell

Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' | Disable-NetFirewallRule

```

  

**5) Servicio en arranque manual:** sshd solo corre cuando se necesita.


```powershell

Set-Service sshd -StartupType Manual

```


**6) Carpeta de intercambio** como único lugar de escritura:


```powershell

icacls M:\lab-share /grant "labclaude:(OI)(CI)M"

```

  

### 3.4 ¿Cómo llega la Kali al loopback del host?


VirtualBox NAT Network tiene **loopback mappings**: una IP de la red virtual se traduce al `127.0.0.1` del host.


```text

Red_NAT  10.0.2.0/24  Gateway 10.0.2.1

loopback mappings (ipv4)

        127.0.0.1=2

```


Por la configuración se esperaba llegar por `10.0.2.2`, pero la prueba real mostró otra cosa:


```bash

$ ssh labclaude@10.0.2.2

ssh: connect to host 10.0.2.2 port 22: Connection refused

  

$ nc -zv -w3 10.0.2.1 22

(UNKNOWN) [10.0.2.1] 22 (ssh) open

```


El host es alcanzable a través del **gateway 10.0.2.1**. Se configuró un alias en la Kali:


```text

Host windows

    HostName 10.0.2.1

    User labclaude

    IdentityFile ~/.ssh/labclaude_win

    IdentitiesOnly yes

```


### 3.5 "Cerebro" compartido entre las dos IAs


La idea inicial fue crear un enlace con `mklink /D` dentro de la carpeta de Descargas compartida. Se descartó porque:

- `mklink /D` crea un **enlace simbólico**, no un enlace duro (Windows no permite enlaces duros de directorios).

- Las versiones actuales de VirtualBox **no siguen symlinks que apuntan fuera** de la carpeta compartida.

- La carpeta destino ya existía con contenido: el comando habría fallado (o, peor, invitado a borrarla).

  

La solución fue usar un recurso compartido que ya existía (`M:\GitHub` → `/media/sf_GitHub`) y un symlink **dentro de la Kali**:

```bash

ln -sfn /media/sf_GitHub/claude ~/cerebro

```

  

### 3.6 Corrección crítica: el código de la IA estaba al alcance de la Kali

  

Al revisar el diseño se detectó esta cadena:

```

Kali (puede comprometerse)

   │ escribe en /media/sf_GitHub/claude/kali-mcp/server.py

   ▼

M:\GitHub\claude\kali-mcp\server.py   ← el mismo archivo

   │ Claude Code lo ejecuta al iniciar

   ▼

Ejecución de código en Windows con el USUARIO PRINCIPAL

```

  

Es decir, todo el trabajo de mínimo privilegio con `labclaude` quedaba **anulado**: un atacante con control de la Kali podía modificar el servidor MCP y obtener ejecución de código en el host con los privilegios del usuario principal en el siguiente inicio.

**Mitigación:** mover el servidor a una carpeta no compartida y volver a registrarlo, verificando integridad por hash antes de borrar el original.
  

```powershell

Copy-Item M:\GitHub\claude\kali-mcp\server.py M:\Documentos\kali-mcp\

(Get-FileHash origen).Hash -eq (Get-FileHash destino).Hash   # True

claude mcp remove kali-lab -s user

claude mcp add kali-lab --scope user -- python M:\Documentos\kali-mcp\server.py

Remove-Item -Recurse M:\GitHub\claude\kali-mcp

```

  
### 3.7 Estructura de JARVIS

Con la infraestructura lista se creó el esqueleto de la IA central, **fuera** de cualquier recurso compartido:

```

M:\Jarvis

├── CLAUDE.md              identidad, reglas y límites de seguridad

├── .claude\skills\        habilidades (próxima fase)

├── .claude\agents\        subagentes especializados

├── estado\ahora.md        plan por fases y pendientes

├── perfil\

│   ├── personal.md        objetivos, forma de aprender

│   └── tecnico.md         nivel por área, plataformas, certificaciones

└── proyectos\             una ficha por cada IA de proyecto

    ├── fixia.md

    ├── cyber-portfolio.md

    ├── maxibarcia-github-io.md

    └── hacking-kali.md

```

Una IA no tiene memoria propia entre sesiones: **la continuidad está en los archivos**. Cada sesión empieza leyendo `CLAUDE.md` y `estado/ahora.md`, y termina actualizándolos.


---
 

## 4. Problemas Encontrados y Soluciones

| # | Problema | Causa | Solución |
|---|---|---|---|
| 1 | `Get-WindowsCapability: La operación solicitada requiere elevación` | PowerShell sin privilegios de administrador | Ejecutar elevado (`Start-Process powershell -Verb RunAs`) y validar elevación al inicio del script |
| 2 | La instalación "parecía colgada" | La consola estaba en **modo selección** (título "Seleccionar…"), que pausa la salida del proceso | `Esc` / `Enter` para salir del modo selección |
| 3 | `New-LocalUser: ... longitud ... menor o igual que "48"` | El campo *Description* admite máximo 48 caracteres | Acortar la descripción; el script es idempotente y se re-ejecutó sin efectos colaterales |
| 4 | `Connection refused` en `10.0.2.2:22` | El acceso al host funciona por el gateway de la NAT Network | Usar `10.0.2.1`, verificado con `nc` |
| 5 | Remote Control no disponible | Función limitada al tipo de cuenta | Instalar la IA dentro de la Kali + SSH |
| 6 | Servidor MCP en carpeta RW de la Kali | Ubicación inicial sin análisis de confianza | Moverlo fuera del recurso compartido (§3.6) |

  

---

## 5. Verificación

Pruebas ejecutadas desde la Kali tras la instalación:
 

```bash

$ ssh windows whoami

<host>\labclaude

  

# ¿Es administrador?

([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')

False

  

# Escritura en la carpeta de intercambio → OK (archivo verificado desde el host y eliminado)

# Lectura del perfil del usuario principal → denegada

```
  

En el host:
  
```text

LocalAddress LocalPort

------------ ---------

127.0.0.1           22      ← sshd no escucha en interfaces de red

```

  
| Prueba | Resultado esperado | Resultado |
|---|---|---|
| Login con llave como `labclaude` | Acceso | ✅ |
| `labclaude` en grupo Administradores | No | ✅ No |
| Escritura en `M:\lab-share` | Permitida | ✅ |
| Lectura del perfil del usuario principal | Denegada | ✅ |
| sshd escuchando en WiFi / LAN | No | ✅ Solo 127.0.0.1 |
| MCP `kali-lab` tras el traslado | Connected | ✅ |

  

---
 

## 6. Modelo de Amenazas y Riesgos Residuales

| Amenaza | Vector | Mitigación | Riesgo residual |
|---|---|---|---|
| Compromiso de la Kali → host | SSH | Usuario sin admin, solo llave, sin forwarding | 🟡 Bajo-medio: acceso a lo que `labclaude` pueda leer |
| Compromiso de la Kali → código del host | Recurso compartido RW | Código e instrucciones de JARVIS fuera de recursos compartidos | 🟢 Bajo |
| VM objetivo → host | Loopback mapping de la NAT | Solo llave (que vive únicamente en la Kali), servicio manual | 🟡 Bajo |
| Exposición en la red local | sshd | `ListenAddress 127.0.0.1`, regla de firewall desactivada | 🟢 Muy bajo |
| Prompt injection a la IA del host | Archivos en `M:\GitHub` | Se tratan como no confiables por regla en `CLAUDE.md` | 🟡 Medio (control de proceso, no técnico) |
| Datos sensibles en recurso compartido | Carpeta de descargas RW | — | 🟠 Pendiente |

  

**Riesgos aceptados de forma consciente:**

- `labclaude` puede leer lo que el grupo *Users* puede leer en el sistema. Es un usuario estándar, no un sandbox.
- La Kali conserva escritura sobre `M:\GitHub` para compartir el "cerebro"; por eso esa zona es de baja confianza.

  
---
 

## 7. Lecciones Aprendidas

1. **Diseñar por fronteras de confianza, no por conectividad.** Que algo "funcione" no significa que sea seguro; la vulnerabilidad más grave fue de diseño, no de configuración.

2. **Mínimo privilegio en todas las capas:** usuario, autenticación, interfaz de escucha, firewall y tiempo de exposición (servicio manual).

3. **Probar en vez de suponer:** la documentación sugería `10.0.2.2`; la realidad era `10.0.2.1`.

4. **Scripts idempotentes:** permitieron re-ejecutar tras cada error sin dejar el sistema en un estado inconsistente.

5. **Un recurso compartido con escritura es una superficie de ataque**, especialmente en un laboratorio ofensivo.

6. **La IA es tan buena como su estructura:** sin memoria entre sesiones, la organización de archivos *es* la memoria.

  

---

## 8. Próximos Pasos

  

1. Completar el **perfil personal y técnico** de JARVIS (entrevista).
2. Crear una **IA por proyecto** (`CLAUDE.md` + skills en cada repositorio).
3. **Skills** de JARVIS: `/ctf`, `/writeup`, `/estudiar`, `/investigar`, `/repaso`.
4. Instalar Claude Code en la Kali como **operador de laboratorio**.
5. Retirar material sensible de los recursos compartidos y evaluar compartir en solo lectura.
6. Integrar una **IA local** (Ollama) y la base de conocimiento personal.


---
    

## 9. Operación Diaria
  

Un sistema no está terminado cuando "funciona una vez", sino cuando se puede **levantar, verificar y apagar** de forma repetible. Este es el procedimiento operativo.

  
### 9.1 Arranque
 

| Paso | Acción | Comando | ¿Obligatorio? |
|---|---|---|---|
| 1 | Abrir JARVIS | `cd /d M:\Jarvis` y luego `claude` | ✅ Sí |
| 2 | Encender la Kali | Pedírselo a JARVIS (usa `vm_start` del MCP) o con `VBoxManage` | Según la tarea |
| 3 | Habilitar SSH Kali → host | `net start sshd` (consola **como administrador**) | Solo si se usa |
  

```cmd

:: 1) IA central (el MCP kali-lab se carga solo: está registrado a nivel de usuario)

cd /d M:\Jarvis

claude

  

:: 2) Encender la Kali manualmente (alternativa a pedírselo a JARVIS)

"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm Kali_Laboratorio

  

:: 3) Solo si la Kali necesita entrar al host (requiere consola de administrador)

net start sshd

```

 

### 9.2 Verificación rápida

  
| Qué se comprueba | Cómo | Resultado esperado |
|---|---|---|
| MCP conectado | `/mcp` dentro de Claude Code | `kali-lab` → connected |
| Kali accesible | Pedir a JARVIS `kali_status` | hostname, usuario e IP `10.0.2.3` |
| SSH Kali → host | En la Kali: `ssh windows whoami` | `<host>\labclaude` |
| sshd solo en loopback | `Get-NetTCPConnection -LocalPort 22 -State Listen` (PowerShell) | `127.0.0.1:22` únicamente |
  

### 9.3 Apagado

```cmd

:: Cerrar SSH (consola de administrador)

net stop sshd

  

:: Apagar la Kali de forma ordenada (o pedírselo a JARVIS: vm_stop)

"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm Kali_Laboratorio acpipowerbutton

```


Antes de cerrar, JARVIS actualiza `estado/ahora.md` con lo hecho y lo pendiente, para que la próxima sesión arranque con contexto.


### 9.4 Continuidad entre sesiones
 

| Comando | Qué hace |
|---|---|
| `claude` | Nueva conversación. JARVIS recupera el contexto leyendo `CLAUDE.md` y `estado/ahora.md`. |
| `claude --continue` | Retoma la última conversación **de esa carpeta**. |
| `claude --resume` | Permite elegir una conversación anterior de esa carpeta. |
  

La conversación es efímera; **la memoria real son los archivos**. Por eso siempre se trabaja desde `M:\Jarvis` y cada sesión termina actualizando el estado.

  
--- 

## Conclusión


Esta fase dejó una base funcional y, sobre todo, **defendible**: la IA central puede administrar el laboratorio y la Kali puede colaborar con el host sin que un compromiso del entorno de pruebas se traduzca automáticamente en un compromiso de la PC.
  
El proyecto también demostró el valor de revisar críticamente el propio diseño: el hallazgo más grave lo introdujo la misma infraestructura que se estaba construyendo, y se detectó y corrigió antes de usarla en un escenario real.


--- 

  

**Contacto:** [maxibarcia.github.io](https://maxibarcia.github.io) · [LinkedIn](https://www.linkedin.com/in/maxib-sec/) · [Web](https://www.maxibarcia.com/)
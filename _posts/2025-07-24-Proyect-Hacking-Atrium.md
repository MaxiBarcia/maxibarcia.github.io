---
title: "Atrium CyberAcademy | Final Ethical Hacking Project"
excerpt: "A detailed report on the final project for the Atrium Cybersecurity Master, covering reconnaissance, exploitation, and privilege escalation on a vulnerable machine."
seo_description: "A complete penetration testing analysis and write-up of the Atrium CyberAcademy ethical hacking final project, documenting exploitation and root escalation."
categories:
  - Report
  - Ethical-Hacking
  - write-up
tags:
  - pentesting
  - cybersecurity
  - metasploit
  - RCE
toc: true
toc_label: "Table of Contents"
toc_sticky: true
header:
  overlay_image: /assets/images/headers/atrium-project-banner.jpg # <--- Place your banner image here
  overlay_filter: 0.7 
  og_image: /assets/images/headers/atrium-project-banner.jpg # <--- Social media image
---

![image-center](/assets/images/posts/atrium-report/atrium-project.png)
{: .align-center}

**Skills Demonstrated** 
**Reconnaissance & Scanning**: Nmap scanning, service and version enumeration.    
**Initial Access**: HTTP request smuggling, client-side credential bypass, OS command injection via web form.    
**Shells & Post-Exploitation**: Netcat reverse shell, Meterpreter session setup, TTY shell upgrade.   
**Privilege Escalation**: Kernel exploit (`4.4.0-87-generic`), local exploit enumeration with `Metasploit`, hash cracking (`/etc/shadow`).    
**Tools**: Nmap, cURL, Netcat, Metasploit Framework, MSFvenom, Python HTTP Server.
{: .notice--primary}

# **Project Introduction**

This report documents the entire process of an ethical hacking exercise conducted as the final project for the cybersecurity master's program at Atrium CyberAcademy. The main objective was to simulate a real-world penetration testing scenario, applying a structured methodology to identify, analyze, and exploit vulnerabilities in a controlled environment.
The project was divided into key phases:
1. **Reconnaissance and Scanning:** Discovering the network topology and active services on the target machine.    
2. **Vulnerability Analysis and Exploitation:** Identifying weaknesses in the services and executing controlled tests to gain initial access.    
3. **Post-Exploitation and Privilege Escalation:** Searching for sensitive information, exploring the system, and escalating privileges to `root` to achieve full control of the machine.    

The purpose of this report is to detail each step of the process, highlight critical findings, and share lessons learned, demonstrating the practical application of the knowledge acquired throughout the program.


> **Project Objective:** To perform reconnaissance, scanning, and identify potential vulnerabilities in a selected organization, and then execute controlled tests on a vulnerable machine.
> **Target Machine:** [https://mega.nz/file/4O0w3Tza#fGAUjHzRiGNmJY8Wlu9Mw3pC5ysP-P-nnBjvJVGTfqE](https://mega.nz/file/4O0w3Tza#fGAUjHzRiGNmJY8Wlu9Mw3pC5ysP-P-nnBjvJVGTfqE)
> {: .notice--info}

---

# 🔍 Phase 1 – Reconnaissance and Scanning

### Network Configuration and Discovery
* **Attacker Machine:** Kali Linux (IP: `192.168.1.13/24`)
* **Victim Machine:** (IP: `192.168.1.21/24`)
* **Network:** Bridge

A successful ping between the Kali machine and the victim confirmed network connectivity.

![Successful ping test](/assets/images/posts/atrium-report/ping-test.png){: .align-center}*

The `netdiscover` scan allowed us to identify the target machine on the network.

![Netdiscover result 1](/assets/images/posts/atrium-report/netdiscover-1.png){: .align-center}

![Netdiscover result 2](/assets/images/posts/atrium-report/netdiscover-2.png){: .align-center}

### Port and Service Scanning with Nmap

A full port scan was performed to identify all active services.

![Basic Nmap scan](/assets/images/posts/atrium-report/nmap-basic-scan.png){: .align-center}

**Detected Operating System:**

| System | Approximate Version | Detection Method  | Confidence |
| :----- | :------------------ | :---------------- | :--------- |
| Linux  | 3.2 - 4.14          | Nmap OS Detection | ✅ 100%     |

**Interesting Services Detected:**

| Port | Service | Product & Version | Potential |
| :--- | :--- | :--- | :--- |
| **21** | FTP | `vsftpd 3.0.3` | Anonymous access (`flag.txt` visible) |
| **25** | SMTP | `JAMES smtpd 2.3.2.1` | **Highly vulnerable** |
| **80** | HTTP | `Apache 2.4.18 (Ubuntu)` | Fuzzing (`/cyberacademy`) |
| **110** | POP3 | `JAMES pop3d 2.3.2.1` | Brute-force credentials |
| **119** | NNTP | `JAMES nntpd` | Investigable |

**Relevant Observations:**
- The **FTP service allows anonymous login** and contains a `flag.txt` file, which indicates a potential unauthenticated entry point.    
- The **Apache James server** is running three key services (SMTP, POP3, and NNTP) with **known vulnerabilities in version 2.3.2.1**, potentially allowing:    
    - User creation via telnet        
    - Command injection through emails        
    - Possible Remote Code Execution (RCE)        
- The HTTP server has a `robots.txt` file that **restricts `/cyberacademy`**, which is a clear clue for targeted analysis (often pointing to sensitive directories or test environments).    
- The operating system was identified as **Linux**, with a kernel version range between 3.2 and 4.14, commonly found in distributions such as Ubuntu 16.04 or similar.



---------

# 🔥 Phase 2 – Vulnerability Analysis and Exploitation

Choosing potential attack vectors

Based on the scan `nmap -p- --open -A`, these are the **most relevant and potentially vulnerable services** detected on IP `192.168.0.19`:

|Service|Key detail|Possible attack vector|
|---|---|---|
|**FTP (21)**|vsftpd 3.0.3 — Anonymous login enabled|Direct access; possible information leak (`flag.txt`)|
|**SMTP (25)**|Apache James Server 2.3.2.1|Known CVE, allows remote execution with created accounts|
|**POP3 (110)**|James 2.3.2.1|Collect emails with credentials created via telnet|
|**NNTP (119)**|James nntpd|Possible abuse or message harvesting|
|**HTTP (80)**|Apache 2.4.18 (Ubuntu), `/cyberacademy`|Scan with Gobuster, Nikto; possible hidden scripts or paths|
|**SSH (22)**|OpenSSH 7.2p2|Brute force if user leaks are found|

**Strategic considerations:**
- The **FTP with anonymous access** is an ideal starting point for reconnaissance and information gathering without generating noise.    
- Apache James 2.3.2.1 exposes **SMTP and POP3**, which, when used together, enable direct exploitation:    
    - Create account via telnet        
    - Send payload through email        
    - Execute commands from POP3 → RCE        
- The website on port 80 returns a title of _"Web Challenges"_, suggesting deliberately vulnerable content. The existence of the `/cyberacademy` path in `robots.txt` **indicates an interesting route to investigate**.    
- **SSH could be leveraged later on**, for example, for post-exploitation if credentials are obtained.
----------

**Exploitation of Apache James Server 2.3.2.1 (SMTP / POP3)**

#### 🎯 Objective

The goal of this exploitation is to demonstrate a **Remote Code Execution (RCE)** in **Apache James Server 2.3.2.1** by abusing its email sending and receiving logic.

Three exposed services are leveraged:
- **Port 4555** → James administration console.    
- **Port 25** → **SMTP** service (sending emails).    
- **Port 110** → **POP3** service (receiving emails).    

#### ⚙️ Attack vector
The attack involves sending a malicious email containing a **JSP payload**, which will later be processed by the James server. This allows code injection and remote execution.

Malicious email :

```ruby
HELO kali
MAIL FROM:<hola@localhost>
RCPT TO:<hola@localhost>
DATA   From: evil    Subject: exploit test
<%   
Runtime.getRuntime().exec("touch /tmp/pwned.txt");
%>
.
QUIT  
```

#### ✅ Expected outcome
The execution of this payload creates the file `/tmp/pwned.txt` on the target server, proving the ability to execute arbitrary commands remotely.

![Successful ping test](/assets/images/posts/atrium-report/telnet-conect.png)

 **Vulnerable Panel — /login_1/**

Location
[[http://192.168.0.1X/login_1/](http://192.168.0.1X/login_1/)]

**Vulnerability**
- Client-side credential validation (JavaScript)    
- Username and password were hardcoded:    

```js
if (document.form.password.value=='supersecret' && document.form.login.value=='admin')
```

  
![Captured Flag](/assets/images/posts/atrium-report/flag1.png )


---

**🔥 Critical Vulnerability Detected — /login_2/**

When performing a POST request to `/login_2/index.php` with invalid credentials:
`curl -X POST http://192.168.0.18/login_2/index.php -d "login=admin&password=test" -i`

The server responds with **HTTP 200 OK** and directly discloses the flag:
`FLAGH{BYPASSING_HTTP_METH=DS_G00D!}`

![Captured Flag](/assets/images/posts/atrium-report/flag2.png )

**False Positives Detected**

|Service / Endpoint|Initial Finding Description|Tests Performed|Result|
|---|---|---|---|
|Reverse Shell SMTP|Attempted reverse shell via payload in email|Tried multiple bash and Meterpreter payloads; no connection established|No session established, likely a false positive|
|Login /login_2/|Attempted access with basic credentials (admin:1234)|Tested multiple credentials and Authorization header with base64|Failed; however, flag found using POST method (HTTP method bypass)|
|Gobuster on /login_2|401 errors and length-based blocking during scan|Tried excluding status codes and lengths with Gobuster; found nothing|Result indicates no accessible hidden directories|


**🌐 Vulnerability — `/ping/` RCE via Command Injection**

📍 Location
`http://192.168.0.1X/ping/`

🕵️ Description
- This functionality allows the user to enter an IP address to perform a _ping_.    
- There is no input validation or sanitization.    
- It is suspected to be vulnerable to **OS Command Injection**.    

Proof of Concept
* *We entered the following payload in the ping input field:
`127.0.0.1; ls`

 🕳️ Exploitation of the `/ping/` endpoint

🎯 Objective:
Obtain a **reverse shell** through the `/ping/` form parameter, which executes system commands directly from user input.
![RCE vulneravility find](/assets/images/posts/atrium-report/vuln-rce.png)




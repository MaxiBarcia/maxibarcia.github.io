---
title: Symfonos6v2 - (VulnHub) - Medium/Hard
excerpt: '"A detailed report documenting the reconnaissance, exploitation, and privilege escalation on the Symfonos6v2 vulnerable machine."'
seo_description: ' "A complete penetration testing analysis and write-up of the Symfonos6v2 vulnerable machine, documenting exploitation and system compromise."'
categories:
  - Report
  - Ethical-Hacking
  - Write-up
  - VulnHub
  - medium
tags:
  - pentesting
  - cybersecurity
  - web-hacking
  - RCE
  - XSS
  - csrf
toc: true
toc_label: "Table of Contents"
toc_sticky: true
header:
  overlay_image: /assets/images/headers/vulnhub-banner.jpg
  overlay_filter: 0.7
  og_image: /assets/images/posts/symfonos-report/banner.png
---

![image-center](/assets/images/headers/vulnhub-banner.jpg)
{: .align-center}

### **Project Overview**

This report documents an ethical hacking exercise conducted on **symfonos: 6.1**, also known as **symfonos6v2**, a vulnerable virtual machine created by **Zayotic** and released on **VulnHub** on April 7, 2020. Classified with an **intermediate-hard** difficulty, the VM was intentionally designed to challenge the tester by forcing them to identify vulnerabilities that exploit a less-obvious attack vector.

The target is a Linux-based virtual machine with DHCP enabled, allowing it to automatically acquire an IP address on the network. The following document details the systematic process of reconnaissance, vulnerability analysis, and exploitation to achieve a full compromise of this intentionally vulnerable environment.


  URL: (https://www.vulnhub.com/entry/symfonos-61,458/)

---

  

*Skills Demonstrated*
- *Reconnaissance & Scanning*: Nmap, gobuster, and service enumeration.
- *Initial Access*: Cross-Site Scripting (XSS), CSRF attack, and web application exploitation.
- *Post-Exploitation*: Internal enumeration, vulnerable service discovery, and YAML file analysis.
- *Privilege Escalation*: Identification of misconfigured PHP services and local kernel vulnerabilities.
- *Tools*: Nmap, Gobuster, Python HTTP Server, cURL, `searchsploit`. {: .notice--primary}


---

# 1. Executive Summary

This report documents the findings of a penetration test on the Symfonos6v2 machine. The assessment successfully identified several critical flaws, including a **Cross-Site Scripting (XSS)** vulnerability in a web application and a **client-side bypass** that led to a full system compromise. The core of the attack leveraged an **XSS vulnerability** to perform a **Cross-Site Request Forgery (CSRF)** attack, creating an administrative user.

Further enumeration revealed a vulnerable PHP service and an exposed API via a YAML file. These findings confirm that the system contains multiple security misconfigurations and outdated software versions that pose a severe risk. The following report details the technical steps taken to exploit the machine, analyzes the impact of each vulnerability, and provides actionable recommendations to remediate the identified risks.

---

# 2. Project Introduction

This report documents the process of a simulated ethical hacking exercise. The objective was to apply a structured methodology to identify, analyze, and exploit vulnerabilities on the Symfonos6v2 machine.

The project was divided into key phases:

1. **Reconnaissance and Scanning:** Discovering the network topology and active services on the target machine.    
2. **Vulnerability Analysis and Exploitation:** Identifying weaknesses in the services and executing controlled tests to gain initial access.    
3. **Post-Exploitation and Privilege Escalation:** Searching for sensitive information and exploring the system to achieve full control of the machine.    

The purpose of this report is to detail each step of the process, highlight critical findings, and share lessons learned, demonstrating the practical application of knowledge acquired.

> **Project Objective:** To perform reconnaissance, scanning, and identify potential vulnerabilities on the Symfonos6v2 vulnerable machine.

---

{: .align-center}

# 3. Phase 1 – Reconnaissance and Scanning

### Network Configuration and Discovery

The first step was to identify the target machine within the network. A successful ping and `netdiscover` scan confirmed connectivity and identified the machine's IP address.

#### Port and Service Scanning with Nmap

![Nmap scan](/assets/images/posts/symfonos-report/nmap-scan.png)
{: .align-center}

A comprehensive Nmap scan was performed to identify open ports, running services, and the operating system of the target. The scan revealed the following services:

|Port|Service|Product & Version|
|---|---|---|
|**22**|SSH|`OpenSSH 7.4`|
|**80**|HTTP|`Apache 2.4` running on **CentOS**, with **PHP/5.6**|
|**3306**|MySQL|`MariaDB`|



{: .align-center}

### Web Directory Enumeration

Fuzzing the web server on port 80 with `gobuster` was crucial for discovering hidden directories. Using a large wordlist (`directory-list-2.3-big.txt`), the `/flyspray` directory was found, which became the primary attack vector.

![Gobuster](/assets/images/posts/symfonos-report/gobuster.png)
{: .align-center}

---

# 4. Phase 2 – Vulnerability Analysis and Exploitation

### Cross-Site Scripting (XSS) in Flyspray

The Flyspray application at `/flyspray` was the main entry point. A search of known exploits revealed a **Cross-Site Scripting (XSS)** vulnerability in the `real_name` field during user registration. This vulnerability is triggered when another user views the name in a comment section.

This flaw was leveraged to perform a **Cross-Site Request Forgery (CSRF)** attack. The goal was to make an administrator execute a malicious script that would create a new user with administrative rights.

- **Attack Payload:** A local Python HTTP server was set up to host a malicious JavaScript file (`pwned.js`). The XSS payload was injected into the `real_name` field.



### Privilege Escalation via CSRF

When an administrator viewed the malicious profile, the script executed in their browser, creating a new administrative user. This granted full control over the application.

- **Impact:** Full compromise of the web application.
    
- **Result:** A new administrator account was created, allowing login to the application's administrative panel.
    

![Exploit](/assets/images/posts/symfonos-report/fly.png)
{: .align-center}

### Additional Findings

During the post-exploitation phase, further vulnerabilities were discovered:

- **Vulnerable PHP Service:** The server runs **PHP 5.6**, a version with known vulnerabilities, such as the use of the `/e` flag in regular expressions, which allows for command injection attacks. {: .align-center}
    
- **YAML Configuration Files:** An API was found on port 3000, and its routes were exposed via a YAML file (`appies.yml`). This type of file can contain sensitive information and represents a potential attack surface.
    

![Exploit](/assets/images/posts/symfonos-report/user-create.png)

{: .align-center}


![PHP Vulneravbility](/assets/images/posts/symfonos-report/php-vuln.png)

---

# 5. Conclusion and Remediation

### Vulnerability Summary

The penetration test successfully identified and exploited multiple critical vulnerabilities.

|Vulnerability|Severity|Impact|
|---|---|---|
|**XSS / CSRF Attack**|**Critical**|An unauthenticated attacker can execute code and create an admin user on the system.|
|**Outdated Software**|**High**|The vulnerable PHP 5.6 service could allow Remote Code Execution (RCE).|
|**YAML Configuration**|**Medium**|Exposed API routes and potential for sensitive data leakage.|
|**Weak Authentication**|**Medium**|Client-side credentials and HTTP method bypass make login vulnerable.|


### Remediation & Recommendations

To mitigate the identified risks and improve the overall security posture, the following recommendations are provided.

- **Patch and Update Services**: Immediately update the PHP service to a non-vulnerable version. All other software and the operating system should be patched to the latest stable versions.
    
- **Secure Web Applications**: Implement strict server-side validation for all user-submitted data. All authentication must be handled securely on the server side, and sensitive data should never be exposed in public-facing files.
    
- **Principle of Least Privilege**: Ensure that all services and applications run with the minimum level of privileges required to perform their functions.
    
- **Disable Unused Ports**: Restrict access to ports and services that are not essential to reduce the attack surface.
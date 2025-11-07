---
title: "Write-up Dockerlabs - Hard - Norc"
categories:
  - Write-up
  - Privilege Escalation
  - Laboratory
  - dockerlabs
tags:
  - nmap
  - hydra
  - smbmap
  - ssh
  - samba
  - sqlmap
  - wordpress
  - cronjob
  - capabilities
toc: true
toc_label: Contenido del Reporte
toc_sticky: true
header:
  # Ruta de la imagen de cabecera que aparecerá en el banner del post
  overlay_image: /assets/images/headers/dockerlabs.png
  overlay_filter: 0.7
og_image: /assets/images/headers/dockerlabs.png
seo_title: Write-up de Hacking en Dockerlabs - Norc (SQLi, RCE, PrivEsc con Cron)
seo_description: Análisis detallado de la vulneración de la máquina Norc de Dockerlabs, incluyendo inyección SQL, RCE y escalada de privilegios mediante Cronjob.
author: Maxi Barcia
date: 2025-11-07
draft: false
---


![image-center](/assets/images/headers/dockerlabs.png)
{: .align-center}
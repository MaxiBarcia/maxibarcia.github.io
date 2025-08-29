---
title: Título de tu Write-up
excerpt: "Un resumen breve y atractivo del write-up. Por ejemplo: 'Análisis detallado de la máquina X, con enfoque en vulnerabilidades de Y.'"
categories:
  - Write-up
  - Hacking
tags:
  - ctf
  - bug-bounty
  - metodologia
toc: true
toc_label: Report content
toc_sticky: true
header: "---\rtitle: \"Título de tu Write-up\"\rexcerpt: \"Un resumen breve y atractivo del write-up. Por ejemplo: 'Análisis detallado de la máquina X, con enfoque en vulnerabilidades de Y.'\"\rcategories:\r  - Write-up\r  - Hacking\rtags:\r  - ctf\r  - bug-bounty\r  - metodologia\rtoc: true\rtoc_label: \"Contenido del Reporte\"\rtoc_sticky: true\rheader:\r  # Opcional: una imagen de banner para la cabecera\r  # overlay_image: /assets/images/headers/nombre-de-tu-imagen.jpg\r  # overlay_filter: 0.5\r  # og_image: /assets/images/headers/nombre-de-tu-imagen.jpg\r---\r\r![Imagen principal del reporte](assets/images/posts/nombre-del-archivo.png){: .align-center}\r\r> Habilidades clave: [Ejemplo: Brute Force, Hash Cracking, Análisis de PDF]\r> {: .notice--primary}\r\r# Resumen Ejecutivo\r\r*Aquí, explica en 2-3 párrafos el objetivo de la máquina o el objetivo de tu auditoría, los hallazgos más importantes y la conclusión general.*\r\r---\r\r# 01 - Reconocimiento\r\r*Detalla la fase de reconocimiento. Describe las herramientas (Nmap, Ping, etc.) y los resultados que obtuviste. Pega los comandos en bloques de código.*\r\r## Nmap\r~~~ bash\rnmap -p- --open -sS unrecover.dl\r# Aquí va el output del comando\r~~~\r\r---\r\r# 02 - Intrusión / Explotación\r\r*En esta sección, explica el proceso de ataque. Muestra cómo usaste los resultados de reconocimiento para encontrar una vulnerabilidad y explotarla. Incluye capturas de pantalla, descripciones de la vulnerabilidad y el impacto.*\r\r## [Nombre de la vulnerabilidad]\r*Descripción de la vulnerabilidad y la evidencia.*\r\r![Evidencia de la explotación](assets/images/posts/nombre-de-la-captura.png){: .align-center}\r\r---\r\r# 03 - Escalada de Privilegios\r\r*Describe cómo lograste obtener privilegios de root o de administrador. Explica la técnica, la vulnerabilidad explotada y las herramientas utilizadas.*\r\r## Escalada de Privilegios\r*Describe el método utilizado.*\r\r~~~ bash\r# Comando de escalada de privilegios\rsudo -l\r~~~\r\r---\r\r# Conclusión\r\r*Termina el reporte con un resumen de los hallazgos y un mensaje final. Puedes incluir recomendaciones generales para mejorar la seguridad.*\r\r---\r\r**NOTA:** No olvides **borrar los comentarios** (`#`) y el texto de ejemplo una vez que termines de redactar tu reporte."
---

![Imagen principal del reporte](assets/images/posts/nombre-del-archivo.png){: .align-center}

> Habilidades clave: [Ejemplo: Brute Force, Hash Cracking, Análisis de PDF]
> {: .notice--primary}

# Resumen Ejecutivo

*Aquí, explica en 2-3 párrafos el objetivo de la máquina o el objetivo de tu auditoría, los hallazgos más importantes y la conclusión general.*

---

# 01 - Reconocimiento

*Detalla la fase de reconocimiento. Describe las herramientas (Nmap, Ping, etc.) y los resultados que obtuviste. Pega los comandos en bloques de código.*

## Nmap
~~~ bash
nmap -p- --open -sS unrecover.dl
# Aquí va el output del comando
~~~

---

# 02 - Intrusión / Explotación

*En esta sección, explica el proceso de ataque. Muestra cómo usaste los resultados de reconocimiento para encontrar una vulnerabilidad y explotarla. Incluye capturas de pantalla, descripciones de la vulnerabilidad y el impacto.*

## [Nombre de la vulnerabilidad]
*Descripción de la vulnerabilidad y la evidencia.*

![Evidencia de la explotación](assets/images/posts/nombre-de-la-captura.png){: .align-center}

---

# 03 - Escalada de Privilegios

*Describe cómo lograste obtener privilegios de root o de administrador. Explica la técnica, la vulnerabilidad explotada y las herramientas utilizadas.*

## Escalada de Privilegios
*Describe el método utilizado.*

~~~ bash
# Comando de escalada de privilegios
sudo -l
~~~

---

# Conclusión

*Termina el reporte con un resumen de los hallazgos y un mensaje final. Puedes incluir recomendaciones generales para mejorar la seguridad.*

---

**NOTA:** No olvides **borrar los comentarios** (`#`) y el texto de ejemplo una vez que termines de redactar tu reporte.
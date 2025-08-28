---
# IMPORTANTE: No olvides añadir tu Front Matter aquí. Ejemplo:
title: "Título de tu Write-up"
date: YYYY-MM-DD
categories:
  - categoria-1
tags:
  - tag-1
---

## Reporte de Auditoría
*Aquí puedes escribir una introducción general al proyecto y la auditoría.*

---

## Estructura del Reporte

- [Tabla de contenidos](#01---index) → Tabla de contenidos.
- [Resumen Ejecutivo](#02---executive-summary) → Resumen ejecutivo para directivos.
- [Alcance](#03---scope) → Alcance de la auditoría (sistemas, IPs, exclusiones).
- [Metodología](#04---methodology) → Marco seguido (OSSTMM, OWASP, MITRE, etc.).
- [Análisis de Riesgos](#05---risk-assessment) → Matriz de riesgo, impacto, probabilidad, priorización.
- [Hallazgos](#06---findings) → Hallazgos técnicos (vulnerabilidades detalladas).
- [Recomendaciones](#07---recommendations) → Acciones sugeridas para mitigar cada hallazgo.
- [Conclusión](#08---conclusion) → Cierre del informe, estado de seguridad general.
- [Anexo: Evidencia](#09---annex-evidence) → Evidencias, capturas, outputs de herramientas.

---

## Datos del Cliente
- **Nombre de la empresa / cliente:**
- **Contacto principal:**
- **Área / Departamento:**

---

## Objetivos de la Auditoría
- Identificar vulnerabilidades técnicas y de configuración.
- Evaluar el impacto potencial de las mismas.
- Proveer recomendaciones prácticas de mitigación.

---

## Consideraciones
- La información contenida en este documento es **confidencial**.
- Uso exclusivo para el cliente.
- No puede ser distribuido sin autorización previa.

---

# 02 - Executive-Summary

- **Overall Objective**: …
- **Methodology summary**: …
- **Key Findings**: short list of the most critical vulnerabilities.
- **Key Recommendations**: main actions to be taken.
- **Overall Security Posture**: Low / Medium / High risk.

---

# 03 - Scope

## Scope
- Assets tested: …
- Exclusions: …
- Limitations: …

---

# 04 - Methodology

## Methodology
- Testing type: [Black/Grey/White Box]
- Frameworks referenced: [OWASP, PTES, NIST…]
- Main tools: [nmap, burp, metasploit, etc.]

---

# 05 - Risk Assessment

This section provides an overall risk evaluation of the assessed environment.
The risk level is determined by combining the likelihood of exploitation and the potential impact on the business.

### Risk Matrix

| Probabilidad \ Impact | Bajo | Medio | Alto | Crítico |
|---------------------|------|--------|------|---------|
| Baja                | Bajo | Bajo   | Medio| Medio   |
| Media               | Bajo | Medio  | Alto | Alto    |
| Alta                | Medio| Alto   | Alto | Crítico |
| Muy Alta            | Medio| Alto   | Crítico| Crítico |

---

# 06 - Findings
*Aquí puedes detallar cada vulnerabilidad encontrada. Cada hallazgo debe tener su propio subencabezado (`###`)*.
### 06.01 - Inyección de Código Remoto (RCE)
*Aquí puedes escribir un breve resumen del hallazgo.*

#### Descripción de la Vulnerabilidad
La aplicación web es vulnerable a la inyección de código remoto a través del parámetro de entrada `search`. Esto permite a un atacante ejecutar comandos del sistema operativo en el servidor.

#### Impacto
- **Confidencialidad:** Acceso no autorizado a archivos sensibles.
- **Integridad:** Posible alteración de archivos o base de datos.
- **Disponibilidad:** Podría llevar a una denegación de servicio.

#### Evidencia
El comando `whoami` fue ejecutado con éxito, revelando que el servidor web se ejecuta con el usuario 'www-data'.

![Captura de pantalla del comando 'whoami'](assets/images/captura-whoami.png)

#### Recomendaciones
- Implementar validación estricta de entradas.
- Usar un `Web Application Firewall (WAF)`.
- Restringir los permisos del usuario de la aplicación.

---

# 07 - Recommendations

The following recommendations aim to reduce the identified risks:

1. **Critical findings** must be remediated immediately (< 7 days).
2. **High findings** should be remediated within 30 days.
3. **Medium findings** should be addressed within 90 days.
4. **Low findings** can be resolved as part of routine maintenance.

Each recommendation is aligned with industry standards (OWASP ASVS, NIST CSF, ISO 27001).

---

# 08 - Conclusion

The assessment revealed several security issues that range from low to critical severity.
The organization should prioritize remediation of critical and high vulnerabilities to minimize business impact.

---

# 09 - Annex: Evidence

This section contains supporting evidence for each finding, including:

- Screenshots
- Logs
- Requests & responses
- Proof of Concept (PoC) code

> ⚠️ All evidence is provided for internal use only and must not be disclosed externally.
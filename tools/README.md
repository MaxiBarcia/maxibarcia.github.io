# Herramientas del sitio

| Archivo | Para qué | Corre en |
|---|---|---|
| `check-posts.py` | **Guard de publicación.** Detecta lo que Jekyll no ve: embeds de Obsidian (`![[...]]`), imágenes inexistentes, marcadores de borrador y rutas del laboratorio. Falla el CI si aparece un defecto nuevo. | Local y CI (Python 3) |
| `check-posts.baseline` | Defectos ya conocidos que hoy están publicados. El guard los ignora para no dejar el CI en rojo; cualquier defecto **nuevo** sigue bloqueando. Se vacía a medida que se corrigen. | — |
| `validate-images.ps1` | Validador de imágenes para PowerShell (Windows). Redundante con el guard, se mantiene para uso local. | Windows |
| `test.sh` | Build + `htmlproofer` completo, igual que el CI. | Linux/macOS |
| `run.sh`, `fix-image-paths.ps1` | Utilidades varias de servido local y corrección de rutas. | — |

## Flujo de publicación

```
escribir post  →  python3 tools/check-posts.py  →  git push  →  GitHub Actions
                                                                ├─ guard de publicación
                                                                ├─ jekyll build
                                                                ├─ htmlproofer (enlaces internos)
                                                                └─ deploy a GitHub Pages
```

El guard existe por una razón concreta: un post escrito en Obsidian arrastra embeds
`![[Pasted image ....png]]` que Markdown no entiende, y Jekyll los publica **como texto
literal**. El build no falla, `htmlproofer` no lo detecta, y el error se descubre cuando
alguien abre la página. Ponerle un paso previo al deploy es más barato que revisar a ojo.

## Comandos útiles

```sh
# validar todos los posts
python3 tools/check-posts.py

# validar solo el que estás escribiendo
python3 tools/check-posts.py _posts/2026-11-16-wazuh-sysmon-lsass-triage-l1.md

# ver también los errores conocidos (sin baseline)
mv tools/check-posts.baseline /tmp/ && python3 tools/check-posts.py
```

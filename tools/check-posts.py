#!/usr/bin/env python3
"""Guard de publicacion para los posts de Chirpy.

Corre en local y en el CI (ubuntu-latest). Detecta lo que rompe una pagina
publicada y que el build de Jekyll NO detecta:

  1. embeds de Obsidian  ![[imagen.png]]        -> Jekyll los deja como texto
  2. imagenes referenciadas que no existen      -> imagen rota en el sitio
  3. marcadores de borrador  [INSERTAR CAPTURA] -> texto de trabajo publicado
  4. rutas absolutas del laboratorio            -> fuga de infraestructura
  5. front matter ausente o sin title           -> Chirpy no genera la pagina

Uso:
    python3 tools/check-posts.py                # todos los posts
    python3 tools/check-posts.py _posts/x.md    # solo algunos
Salida: 0 si todo pasa, 1 si hay errores.
"""
from __future__ import annotations

import os
import re
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTS = os.path.join(RAIZ, "_posts")

PATRONES_PROHIBIDOS = [
    ("embed", re.compile(r"!\[\[[^\]]+\]\]"), "embed de Obsidian (![[...]]): Jekyll lo publica como texto"),
    ("marcador", re.compile(r"\[INSERTAR CAPTURA[^\]]*\]"), "marcador de borrador visible en el post"),
    ("ruta-lab", re.compile(r"[A-Za-z]:\\\\?IAs"), "ruta absoluta del laboratorio (M:\\IAs)"),
    ("ruta-lab", re.compile(r"/mnt/datos"), "ruta del disco del servidor del laboratorio"),
    ("ruta-lab", re.compile(r"estudio_1/"), "ruta interna del cerebro del laboratorio"),
]

RE_IMG = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-posts.baseline")


def cargar_baseline() -> set:
    if not os.path.exists(BASELINE):
        return set()
    with open(BASELINE, encoding="utf-8") as fh:
        return {l.strip() for l in fh if l.strip() and not l.startswith("#")}


def front_matter(texto: str):
    if not texto.startswith("---"):
        return None
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", texto, re.S)
    return m.group(1) if m else None


def revisar(ruta: str, errores: list, avisos: list) -> None:
    rel = os.path.relpath(ruta, RAIZ).replace(os.sep, "/")
    with open(ruta, encoding="utf-8", errors="replace") as fh:
        texto = fh.read()

    fm = front_matter(texto)
    if fm is None:
        errores.append(("frontmatter", f"{rel}: sin front matter valido (Chirpy no genera la pagina)"))
        return
    if not re.search(r"^title:\s*\S", fm, re.M):
        errores.append(("frontmatter", f"{rel}: front matter sin 'title'"))

    for tipo, patron, motivo in PATRONES_PROHIBIDOS:
        hallado = patron.search(texto)
        if hallado:
            linea = texto[: hallado.start()].count("\n") + 1
            errores.append((tipo, f"{rel}:{linea}: {motivo} -> {hallado.group(0)[:60]}"))

    for alt, destino in RE_IMG.findall(texto):
        if destino.startswith(("http://", "https://", "//", "data:")):
            continue
        limpio = destino.split("#")[0].split("?")[0]
        if limpio.startswith("/"):
            archivo = os.path.join(RAIZ, limpio.lstrip("/"))
        else:
            archivo = os.path.join(os.path.dirname(ruta), limpio)
        if not os.path.exists(archivo):
            linea = texto[: texto.find(destino)].count("\n") + 1
            errores.append(("imagen", f"{rel}:{linea}: imagen inexistente -> {destino}"))
        elif os.path.getsize(archivo) == 0:
            errores.append(("imagen", f"{rel}:{linea}: imagen vacia (0 bytes) -> {destino}"))

    # avisos de higiene de tags (no rompen el build, pero fragmentan el indice)
    bloque = re.search(r"^tags:[ \t]*(.*)$((?:\n[ \t]+-.*)*)", fm, re.M)
    if bloque:
        inline = bloque.group(1).strip()
        if inline.startswith("["):
            tags = [t.strip().strip("\"'") for t in inline.strip("[]").split(",")]
        else:
            tags = [re.sub(r"^\s*-\s*", "", l).strip().strip("\"'")
                    for l in bloque.group(2).split("\n") if l.strip()]
        for t in [x for x in tags if x]:
            if t != t.lower() and re.search(r"[A-Z]", t) and not re.search(r"[a-z][A-Z]", t):
                avisos.append(f"{rel}: tag '{t}' en mayusculas (el resto del sitio usa minusculas)")


def main() -> int:
    objetivos = sys.argv[1:]
    if objetivos:
        archivos = [os.path.abspath(a) for a in objetivos]
    else:
        archivos = sorted(
            os.path.join(POSTS, f) for f in os.listdir(POSTS) if f.endswith(".md")
        )

    errores: list[tuple] = []
    avisos: list[str] = []
    for a in archivos:
        if os.path.exists(a):
            revisar(a, errores, avisos)
        else:
            errores.append(("frontmatter", f"{a}: no existe"))

    base = cargar_baseline()
    conocidos = [e for e in errores
                 if f"{e[1].split(':')[0]}|{e[0]}" in base]
    nuevos = [e for e in errores if e not in conocidos]

    print(f"posts revisados: {len(archivos)}")
    if avisos:
        print(f"\navisos ({len(avisos)}):")
        for a in avisos[:8]:
            print("  -", a)
        if len(avisos) > 8:
            print(f"  ... y {len(avisos) - 8} mas")
    if conocidos:
        print(f"\nerrores ya conocidos, en baseline ({len(conocidos)}):")
        vistos = {}
        for tipo, msg in conocidos:
            vistos[msg.split(":")[0]] = vistos.get(msg.split(":")[0], 0) + 1
        for f, n in sorted(vistos.items()):
            print(f"  - {f} ({n})")
    if nuevos:
        print(f"\nERRORES NUEVOS ({len(nuevos)}):")
        for tipo, msg in nuevos:
            print("  -", msg)
        print("\nresultado: PUBLICACION BLOQUEADA")
        return 1
    print("\nresultado: OK, no hay defectos nuevos. Los posts estan listos para publicar")
    return 0


if __name__ == "__main__":
    sys.exit(main())

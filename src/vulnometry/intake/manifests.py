"""Dependency manifests and SBOMs to component lists, resolved later via OSV."""

from __future__ import annotations

import json
import re
from pathlib import Path

PURL_ECOSYSTEM = {
    "pypi": "PyPI", "npm": "npm", "golang": "Go", "maven": "Maven",
    "cargo": "crates.io", "gem": "RubyGems", "nuget": "NuGet",
    "composer": "Packagist", "hex": "Hex", "deb": "Debian", "apk": "Alpine",
}


def _from_purl(purl: str) -> dict | None:
    match = re.match(r"pkg:([^/]+)/(.+?)@([^?#]+)", purl or "")
    if not match:
        return None
    kind, name, version = match.groups()
    if kind.lower() == "maven":
        name = name.replace("/", ":", 1)
    return {"name": name, "ecosystem": PURL_ECOSYSTEM.get(kind.lower(), ""), "version": version}


def requirements(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9._\-\[\]]+)\s*==\s*([^\s;]+)", line)
        if match:
            out.append({"name": match.group(1).split("[")[0], "ecosystem": "PyPI", "version": match.group(2)})
    return out


def poetry_lock(text: str) -> list[dict]:
    out, current = [], {}
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            current = {}
        elif line.startswith("name = "):
            current["name"] = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and current.get("name"):
            out.append({"name": current["name"], "ecosystem": "PyPI", "version": line.split("=", 1)[1].strip().strip('"')})
            current = {}
    return out


def package_lock(text: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict) or not meta.get("version"):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        if name:
            out.append({"name": name, "ecosystem": "npm", "version": meta["version"]})
    if not out:
        for name, meta in (data.get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append({"name": name, "ecosystem": "npm", "version": meta["version"]})
    return out


def go_mod(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        stripped = line.strip().removeprefix("require ")
        match = re.match(r"^([\w.\-/]+)\s+v([\w.\-+]+)", stripped)
        if match and "/" in match.group(1):
            out.append({"name": match.group(1), "ecosystem": "Go", "version": f"v{match.group(2)}"})
    return out


def gemfile_lock(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        match = re.match(r"^\s{4}([\w\-]+) \(([\d][\w.\-]*)\)$", line)
        if match:
            out.append({"name": match.group(1), "ecosystem": "RubyGems", "version": match.group(2)})
    return out


def cargo_lock(text: str) -> list[dict]:
    out, current = [], {}
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            current = {}
        elif line.startswith("name = "):
            current["name"] = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and current.get("name"):
            out.append({"name": current["name"], "ecosystem": "crates.io", "version": line.split("=", 1)[1].strip().strip('"')})
            current = {}
    return out


def pom(text: str) -> list[dict]:
    out = []
    for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.DOTALL):
        group = re.search(r"<groupId>(.*?)</groupId>", block)
        artifact = re.search(r"<artifactId>(.*?)</artifactId>", block)
        version = re.search(r"<version>(.*?)</version>", block)
        if group and artifact and version and "${" not in version.group(1):
            out.append({
                "name": f"{group.group(1).strip()}:{artifact.group(1).strip()}",
                "ecosystem": "Maven",
                "version": version.group(1).strip(),
            })
    return out


def sbom(text: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for component in data.get("components", []) or []:
        parsed = _from_purl(component.get("purl", ""))
        if parsed:
            out.append(parsed)
        elif component.get("name") and component.get("version"):
            out.append({"name": component["name"], "ecosystem": "", "version": component["version"]})
    for package in data.get("packages", []) or []:
        for ref in package.get("externalRefs", []) or []:
            parsed = _from_purl(ref.get("referenceLocator", ""))
            if parsed:
                out.append(parsed)
    return out


HANDLERS = [
    (lambda p: p.name in ("package-lock.json", "npm-shrinkwrap.json"), package_lock, "npm lockfile"),
    (lambda p: p.name == "poetry.lock", poetry_lock, "poetry.lock"),
    (lambda p: p.name in ("go.mod", "go.sum"), go_mod, "go.mod"),
    (lambda p: p.name == "Gemfile.lock", gemfile_lock, "Gemfile.lock"),
    (lambda p: p.name == "Cargo.lock", cargo_lock, "Cargo.lock"),
    (lambda p: p.name == "pom.xml", pom, "Maven pom.xml"),
    (lambda p: p.name.startswith("requirements"), requirements, "requirements.txt"),
    (lambda p: p.suffix == ".json", sbom, "SBOM"),
    (lambda p: p.suffix in (".txt", ".in"), requirements, "requirements.txt"),
]


def parse_manifest(path: str | Path) -> tuple[list[dict], str]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    for matches, handler, label in HANDLERS:
        if not matches(path):
            continue
        try:
            components = handler(text)
        except (json.JSONDecodeError, ValueError):
            continue
        if components:
            seen, unique = set(), []
            for component in components:
                key = (component.get("ecosystem", ""), component["name"], component.get("version", ""))
                if key not in seen:
                    seen.add(key)
                    unique.append(component)
            return unique, label
    return [], "unrecognised"

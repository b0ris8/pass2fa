#!/usr/bin/env python3
"""Пересборка assets/simple-icons.tsv.z из npm-пакета simple-icons (CC0).
   npm pack simple-icons && tar xzf simple-icons-*.tgz && python3 tools/gen-simple-icons.py package"""
import json, re, sys, zlib
pkg = sys.argv[1] if len(sys.argv) > 1 else "package"
d = json.load(open(f"{pkg}/data/simple-icons.json"))
lines = []
for e in d:
    s = e["slug"]
    m = re.search(r'<path d="([^"]+)"', open(f"{pkg}/icons/{s}.svg").read())
    if not m:
        continue
    al = e.get("aliases") or {}
    aka = list(al.get("aka", [])) + list((al.get("loc") or {}).values()) + [x.get("title", "") for x in (al.get("dup") or [])]
    keys = sorted({re.sub(r"[^a-z0-9]", "", x.lower()) for x in [e["title"], s] + aka if x})
    lines.append("\t".join([s, e["hex"], " ".join(keys), m.group(1)]))
open("assets/simple-icons.tsv.z", "wb").write(zlib.compress("\n".join(lines).encode(), 9))
print(len(lines), "icons")

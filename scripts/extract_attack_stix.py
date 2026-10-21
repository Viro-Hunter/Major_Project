#!/usr/bin/env python3
"""Extract the official MITRE ATT&CK STIX 2.1 objects for the techniques this project maps.

    python scripts/extract_attack_stix.py            # downloads enterprise-attack.json (~55 MB) once

Writes data/attack_patterns.stix21.json: a STIX 2.1 bundle with MITRE's own attack-pattern
objects (original ids, names, descriptions, kill-chain phases, external references), the
MITRE identity and its marking definition, so exports reference ATT&CK natively.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUT = ROOT / "data" / "attack_patterns.stix21.json"
EXTRA = {"T1056"}  # used by the evaluation scenarios (keylogger) though no detection rule produces it yet


def main(path: str | None = None) -> int:
    lookup = json.loads((ROOT / "data" / "attack_technique_lookup.json").read_text())
    wanted = {p["technique_id"] for p in lookup["patterns"]} | EXTRA
    raw = Path(path).read_text() if path else urllib.request.urlopen(SOURCE, timeout=120).read().decode()
    objects = json.loads(raw)["objects"]
    keep, refs = [], set()
    for o in objects:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ext in wanted:
            keep.append(o)
            refs.add(o.get("created_by_ref"))
            refs.update(o.get("object_marking_refs", []))
    keep += [o for o in objects if o.get("id") in refs]
    bundle = {"type": "bundle", "id": "bundle--6f0b1c4e-1d1c-4f63-9d5e-6c2b3a7d8e91", "objects": keep}
    OUT.write_text(json.dumps(bundle, indent=2))
    print(f"{len(keep)} objects -> {OUT.relative_to(ROOT)}: " + ", ".join(sorted(
        next(r['external_id'] for r in o['external_references'] if r.get('source_name') == 'mitre-attack')
        for o in keep if o['type'] == 'attack-pattern')))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else None))

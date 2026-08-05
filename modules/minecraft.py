import argparse
import base64
import bisect
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional
from urllib import error, request
from urllib.parse import urlparse
try:
    from rich.console import Console
    from rich.table import Table
    from rich.rule import Rule
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False
try:
    from Crypto.Cipher import AES
except Exception:
    AES = None
try:
    from magika import Magika
except Exception:
    Magika = None

from .models import *

def _trace_minecraft_data_flow(
    text: str,
    rel: str,
    obfuscated_values: List[str],
) -> List[BehaviorFinding]:
    """Trace Minecraft session API calls through variable assignments to
    network/write sinks within a single file.

    Detects the pattern:
      1. MC session/username/uuid/token API call  (source)
      2. Variable assignment chains
      3. Network I/O write or socket send            (sink)

    Returns behavior findings when a source-to-sink path is detected."""
    out: List[BehaviorFinding] = []
    low = text.lower()

    # Source markers: Minecraft session/token/identity access
    source_patterns = [
        (r'method_1548\(\)', 'minecraft_session_access'),
        (r'method_1674\(\)', 'minecraft_access_token_access'),
        (r'method_1676\(\)', 'minecraft_username_access'),
        (r'method_44717\(\)', 'minecraft_uuid_access'),
        (r'getSession\(\)', 'minecraft_session_access'),
        (r'getAccessToken\(\)', 'minecraft_access_token_access'),
        (r'getName\(\)', 'minecraft_username_access'),
        (r'getUsername\(\)', 'minecraft_username_access'),
        (r'getUuid\(\)', 'minecraft_uuid_access'),
        (r'getProfileId\(\)', 'minecraft_uuid_access'),
        (r'GameProfile\.getId\(\)', 'minecraft_uuid_access'),
        (r'Session\.getUuid\(\)', 'minecraft_uuid_access'),
        (r'func_148254_d\(\)', 'minecraft_access_token_access'),
        (r'func_111285_a\(\)', 'minecraft_username_access'),
        # Yarn 1.21+ obfuscated accessors seen in decompiled client mods
        (r'method_23317\(\)', 'minecraft_player_x_access'),
        (r'method_23318\(\)', 'minecraft_player_y_access'),
        (r'method_23321\(\)', 'minecraft_player_z_access'),
        (r'method_5477\(\)', 'minecraft_player_name_access'),
        (r'method_1558\(\)', 'minecraft_server_entry_access'),
    ]

    # Sink markers: network I/O, exfiltration primitives
    sink_patterns = [
        r'HttpURLConnection',
        r'setRequestMethod\("POST"\)',
        r'getOutputStream\(\)',
        r'\.write\(',
        r'writeBytes\(',
        r'OutputStream',
        r'DataOutputStream',
        r'Socket\(',
        r'SSLSocket',
        r'\.send\(',
        r'HttpClient\.send',
        r'OkHttpClient',
        r'newCall\(',
        r'URL\.openConnection',
        r'writeUtffde\(',
        r'prefire\(',
        r'sendByteArray\(',
        r'doPost\(',
        r'postBytes\(',
    ]

    # Also check decoded values for sink indicators
    sink_in_obf = any(
        any(tok in v.lower() for tok in ['write', 'send', 'post', 'socket', 'outputstream', 'http', 'prefire', '/shard'])
        for v in obfuscated_values
    )

    import re as _re
    has_source = any(_re.search(pat, text) for pat, _ in source_patterns)
    has_sink = any(_re.search(pat, text) for pat in sink_patterns) or sink_in_obf

    if not has_source or not has_sink:
        return out

    # Collect which source types are present
    source_hits: set[str] = set()
    for pat, behavior_id in source_patterns:
        if _re.search(pat, text):
            source_hits.add(behavior_id)

    # Collect which sink types are present
    sink_hits: list[str] = []
    for pat in sink_patterns:
        m = _re.search(pat, text)
        if m:
            sink_hits.append(m.group(0) if hasattr(m, 'group') else pat)
            if len(sink_hits) >= 4:
                break

    # Check for specific data flow: variable flows from session getter to write
    data_flow_via_var = False
    # Pattern: something = .getSession() -> ... -> .write(something)
    if _re.search(r'\w+\s*=\s*\w+\.getSession\(\)', text):
        data_flow_via_var = True
    if _re.search(r'\w+\s*=\s*\w+\.getAccessToken\(\)', text):
        data_flow_via_var = True
    if _re.search(r'new\s+JSONObject.*\.put\("accessToken"', text):
        data_flow_via_var = True

    # Check for JSON payload construction with token fields
    json_token_payload = bool(
        _re.search(r'"(?:accessToken|accesstoken|access_token|mcInfo|ssid|sessionId)"', text, _re.IGNORECASE)
    )

    # Check for exfil destination resolution
    has_c2_resolve = bool(
        'getDomain()' in text
        or 'getdomain()' in text
        or 'sltnnt.ru' in ("\n".join(obfuscated_values)).lower()
        or 'polygon' in ("\n".join(obfuscated_values)).lower()
    )

    # Emit findings based on confidence
    if 'minecraft_access_token_access' in source_hits and (data_flow_via_var or json_token_payload):
        exfil_detail = ""
        if has_c2_resolve:
            exfil_detail = " with C2 domain resolution"
        if json_token_payload:
            exfil_detail += " — JSON payload built from token fields"
        if data_flow_via_var:
            exfil_detail += " — variable flows from session getter to network sink"
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getAccessToken()") if "getAccessToken()" in text else find_line(text, "method_1674()"),
                behavior="dataflow_token_to_network_sink",
                evidence=f"Minecraft access token retrieved and flows to network/write sink(s){exfil_detail}. Sinks: {', '.join(sink_hits[:3])}",
            )
        )

    if 'minecraft_username_access' in source_hits and data_flow_via_var:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getName()") if "getName()" in text else find_line(text, "getUsername()"),
                behavior="dataflow_username_to_network_sink",
                evidence="Minecraft username flows to network sink(s) — identity collection for exfiltration",
            )
        )

    if 'minecraft_uuid_access' in source_hits and data_flow_via_var:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getUuid()") if "getUuid()" in text else find_line(text, "method_44717()"),
                behavior="dataflow_uuid_to_network_sink",
                evidence="Minecraft UUID flows to network sink(s) — identity collection for exfiltration",
            )
        )

    if any(
        src in source_hits
        for src in ("minecraft_player_x_access", "minecraft_player_y_access", "minecraft_player_z_access")
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "method_23317()") if "method_23317()" in text else find_line(text, "HttpURLConnection"),
                behavior="dataflow_coordinates_to_network_sink",
                evidence="Player coordinate accessors (Yarn method_23317/23318/23321) present alongside network/write sink(s) — coordinate collection for exfiltration",
            )
        )

    return out



_MODULE_SUPER_CALL_RE = re.compile(
    r'super\s*\(\s*"(?P<name>[^"]+)"\s*,\s*"(?P<desc>[^"]*)"\s*,\s*\w+\s*,\s*(?P<cat>[A-Za-z_.]+)\s*\s*\)',
    re.DOTALL,
)
_GENERIC_SUPER_NAME_DESC_RE = re.compile(
    r'super\s*\(\s*"(?P<name>[^"]+)"(?:\s*,\s*"(?P<desc>[^"]*)")?',
    re.DOTALL,
)
_ADDMODULE_CALL_RE = re.compile(r'addModule\s*\(\s*(?P<cls>[A-Za-z_$][\w$.]*)\s*\.class\s*\)')
_CATEGORY_CALL_RE = re.compile(
    r'(?:setCategory|category\s*=|Category\.)\s*\(?\s*(?:Category\.)?(?P<cat>[A-Za-z_]+)',
    re.IGNORECASE,
)
_CLASS_DECL_RE = re.compile(
    r'\bclass\s+(?P<cls>[A-Za-z_$][\w$]*)\s+(?:extends|implements)\s+(?P<base>[A-Za-z_$][\w$]*)',
)
_REGISTRY_NEW_RE = re.compile(r'\bnew\s+(?P<cls>[A-Za-z_$][\w$]*)\s*\(')
_REGISTRY_FIELD_RE = re.compile(
    r'\b(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?P<type>[A-Za-z_$][\w$]*)\s+\w+\s*=\s*new\s+(?P<cls>[A-Za-z_$][\w$]*)\s*\('
)
_CHEAT_NAME_TOKENS = (
    "aura", "killaura", "triggerbot", "aimbot", "autoclicker", "autoarmor",
    "autototem", "autosoup", "bedaura", "bowaimbot", "crystal", "critical",
    "velocity", "antikb", "antiknockback", "reach", "hitbox", "timer", "speed",
    "flight", "elytrafly", "fly", "jesus", "nofall", "step", "phase", "noclip",
    "blink", "freecam", "xray", "esp", "tracer", "nametag", "fullbright",
    "scaffold", "nuker", "cheststealer", "inventorymove", "fastplace",
    "fastbreak", "fastuse", "safewalk", "baritone", "surround", "burrow",
    "packetmine", "airjump", "spider", "noslow", "derp", "bunnyhop",
)


def _module_class_score(class_name: str, rel: str, text: str) -> int:
    hay = f"{class_name} {rel}".replace("_", "").replace("-", "").lower()
    score = sum(3 for token in _CHEAT_NAME_TOKENS if token in hay)
    if re.search(r'\b(?:extends|implements)\s+(?:Module|Hack|Feature|ToggleModule|Mod)\b', text):
        score += 3
    if re.search(r'\b(?:Category|setCategory|addModule|register|modules|hacks)\b', text, re.IGNORECASE):
        score += 1
    return score


def _humanize_module_name(class_name: str) -> str:
    name = re.sub(r'(?:Module|Hack|Feature|Mod)$', '', class_name)
    name = re.sub(r'(?<!^)(?=[A-Z])', ' ', name).replace("_", " ").strip()
    return name or class_name


def _extract_module_info(class_name: str, rel: str, text: str) -> dict:
    sm = _MODULE_SUPER_CALL_RE.search(text)
    if sm:
        name = sm.group("name")
        desc = sm.group("desc")
        category = sm.group("cat").rsplit(".", 1)[-1].upper()
    else:
        gm = _GENERIC_SUPER_NAME_DESC_RE.search(text)
        name = gm.group("name") if gm else _humanize_module_name(class_name)
        desc = (gm.group("desc") or "") if gm else ""
        cm = _CATEGORY_CALL_RE.search(text)
        category = cm.group("cat").upper() if cm else "OTHER"
    if not desc:
        desc = _humanize_module_name(class_name)
    return {"name": name, "description": desc, "category": category, "file": rel}


def _add_module_candidate(out: dict, seen_modules: set[str], simple_to_rel: dict[str, list[str]], texts: dict[str, str], class_name: str) -> bool:
    if class_name in seen_modules:
        return False
    candidates = [r for r in simple_to_rel.get(class_name, []) if not _is_known_library_relpath(r)]
    if not candidates:
        return False
    best_rel = candidates[0]
    best_text = texts.get(best_rel, "")
    best_score = _module_class_score(class_name, best_rel, best_text)
    for rel in candidates[1:]:
        text = texts.get(rel, "")
        score = _module_class_score(class_name, rel, text)
        if score > best_score:
            best_rel, best_text, best_score = rel, text, score
    if best_score <= 0 and "super(" not in best_text:
        return False
    seen_modules.add(class_name)
    out["modules"].append(_extract_module_info(class_name, best_rel, best_text))
    return True


def _registry_class_names(text: str) -> set[str]:
    names = {m.group("cls") for m in _REGISTRY_NEW_RE.finditer(text)}
    names.update(m.group("cls") for m in _REGISTRY_FIELD_RE.finditer(text))
    return {n for n in names if n not in {"String", "File", "URL", "Thread", "ArrayList", "HashMap"}}


def detect_minecraft_modules(root: Path) -> dict:
    """Detect Minecraft utility/cheat client modules by scanning for module
    registration patterns (addModule(XX.class)) and cross-referencing with
    module source files to extract names, descriptions, and categories.

    Returns a dict with 'detected' bool and 'modules' list of {name, description, category, file}.
    """
    out: dict = {"detected": False, "module_count": 0, "modules": []}
    idx = _build_source_index(root)
    texts: dict[str, str] = idx["texts"]
    simple_to_rel: dict[str, list[str]] = idx["simple_to_rel"]

    # Step 1: Find the module manager (file with multiple addModule() calls)
    best_mm_rel = ""
    best_mm_count = 0
    for rel, text in texts.items():
        if _is_known_library_relpath(rel):
            continue
        count = len(_ADDMODULE_CALL_RE.findall(text))
        if count > best_mm_count:
            best_mm_count = count
            best_mm_rel = rel

    if best_mm_count < 4:
        # No addModule() style modules found; skip to Phase 2 (Wurst) detection
        seen_modules: set[str] = set()
    else:
        seen_modules: set[str] = set()
        mm_text = texts.get(best_mm_rel, "")

        # Step 2: Extract class names from addModule() calls
        registered_classes: set[str] = set()
        for m in _ADDMODULE_CALL_RE.finditer(mm_text):
            cls_full = m.group("cls")
            simple_name = cls_full.rsplit(".", 1)[-1]
            registered_classes.add(simple_name)

        # Step 3: For each registered class, find its source file and extract super() call
        for simple_name in sorted(registered_classes):
            if simple_name in seen_modules:
                continue
            candidates = [
                r for r in simple_to_rel.get(simple_name, [])
                if not _is_known_library_relpath(r)
            ]
            if not candidates:
                continue
            module_text = ""
            for c in candidates:
                t = texts.get(c, "")
                if 'super(' in t or 'extends M' in t or 'extends Module' in t:
                    module_text = t
                    break
            if not module_text:
                module_text = texts.get(candidates[0], "")

            sm = _MODULE_SUPER_CALL_RE.search(module_text)
            if sm:
                name = sm.group("name")
                desc = sm.group("desc")
                cat_raw = sm.group("cat")
                category = cat_raw.rsplit(".", 1)[-1]
                seen_modules.add(simple_name)
                out["modules"].append({
                    "name": name,
                    "description": desc,
                    "category": category.upper(),
                    "file": candidates[0] if candidates else simple_name,
                })

    out["module_count"] = len(out["modules"])
    out["detected"] = out["module_count"] >= 4

    # Phase 2: generic hack/module registries.
    # Many clients keep a HackList/ModuleManager-style file full of new Foo()
    # entries. Once one entry looks like a cheat module, enumerate the list.
    if out["module_count"] < 4:
        for rel, text in texts.items():
            if _is_known_library_relpath(rel):
                continue
            registry_classes = _registry_class_names(text)
            if len(registry_classes) < 4:
                continue
            plausible = 0
            for cls_name in registry_classes:
                for candidate in simple_to_rel.get(cls_name, []):
                    candidate_text = texts.get(candidate, "")
                    if _module_class_score(cls_name, candidate, candidate_text) > 0:
                        plausible += 1
                        break
            if plausible == 0:
                continue
            for cls_name in sorted(registry_classes):
                _add_module_candidate(out, seen_modules, simple_to_rel, texts, cls_name)

    # Phase 3: direct class-name sweep for clients without a clear registry.
    if out["module_count"] < 4:
        for rel, text in texts.items():
            if _is_known_library_relpath(rel):
                continue
            cm = _CLASS_DECL_RE.search(text)
            if not cm:
                continue
            cls_name = cm.group("cls")
            if _module_class_score(cls_name, rel, text) >= 3:
                _add_module_candidate(out, seen_modules, simple_to_rel, texts, cls_name)

    out["module_count"] = len(out["modules"])
    out["detected"] = out["module_count"] >= 4

    # Also detect module categories present
    cats: dict[str, int] = {}
    for m in out["modules"]:
        cats[m["category"]] = cats.get(m["category"], 0) + 1
    out["categories"] = dict(sorted(cats.items()))

    return out
__all__ = [name for name in globals() if not name.startswith("__")]

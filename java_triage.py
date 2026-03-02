#!/usr/bin/env python3
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
import zipfile
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional
from urllib import error, request
try:
    from rich.console import Console
    from rich.table import Table
    from rich.rule import Rule
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False

BANNER = r"""     __              ______    _              
 __ / /__ __  _____ /_  __/___(_)__ ____ ____ 
/ // / _ `/ |/ / _ `// / / __/ / _ `/ _ `/ -_)
\___/\_,_/|___/\_,_//_/ /_/ /_/\_,_/\_, /\__/ 
            github.com/cev-api      /___/      
    
    """


LOAD_CALL_RE = re.compile(
    r"(?:\b\w+\.)?load\(\s*new\s+int\[\]\s*\{(?P<d1>.*?)\}\s*,\s*new\s+int\[\]\s*\{(?P<d2>.*?)\}\s*,\s*(?P<k1>\d+)\s*,\s*(?P<k2>\d+)\s*\)",
    re.DOTALL,
)
# Match standard Java string literals and avoid crossing line boundaries.
STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\\r\n]){16,})"')
STRING_ANY_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\\r\n]){4,})"')
STRING_DECRYPT_CALL_RE = re.compile(
    r"(?P<call>(?:\b[\w$.]*StringDecrypt\s*\.\s*)?decrypt\s*\(\s*new\s+byte\s*\[\s*\]\s*\{(?P<bytes>.*?)\}\s*\))",
    re.DOTALL,
)
NEW_BYTE_ARRAY_LITERAL_RE = re.compile(r"new\s+byte\s*\[\s*\]\s*\{(?P<body>.*?)\}", re.DOTALL)
JAVA_BYTE_TOKEN_RE = re.compile(r"(?:\(\s*byte\s*\)\s*)?(-?\d+)")

METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected|static|final|synchronized|native|abstract|strictfp|default|\s)+"
    r"(?:<[\w\s,? extends super]+>\s*)?"
    r"[\w$\[\]<>.,?\s]+\s+([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^{]+)?\{\s*$"
)

URL_RE = re.compile(r"^https?://", re.IGNORECASE)
HEX_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{8,}$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{80,}$")
BASE32_RE = re.compile(r"^[A-Z2-7=]{16,}$")
HEX_BLOB_RE = re.compile(r"^(?:[A-Fa-f0-9]{2}){8,}$")
RESOURCE_STREAM_RE = re.compile(r'getResourceAsStream\(\s*"([^"]+)"\s*\)')
CREATE_TEMP_RE = re.compile(r'createTempFile\(\s*"([^"]*)"\s*,\s*([^)]+)\)')
COMMAND_LITERAL_RE = re.compile(
    r"(?:\bcmd\.exe\b|\bpowershell(?:\.exe)?\b|\brundll32\b|\bregsvr32\b|\bmshta\b|\bwmic\b|\bcertutil\b|\bcmstp\b|/c\b|-enc\b)",
    re.IGNORECASE,
)
WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:\\")
SUSPICIOUS_STRING_KEYWORDS = (
    "webhook",
    "discord",
    "telegram",
    "api.telegram.org",
    "proguard",
    "allatori",
    "stringer",
    "zelix",
    "dasho",
    "api_key",
    "authorization",
    "bearer ",
    "token",
    "exfil",
    "pastebin",
    "ngrok",
    "defender",
    "uac",
    "elevate",
    "download",
)
DISCORD_WEBHOOK_RE = re.compile(
    r"^https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(?P<id>\d{17,20})/(?P<token>[A-Za-z0-9._-]{20,})$",
    re.IGNORECASE,
)
DISCORD_BOT_TOKEN_RE = re.compile(
    r"\b(?:mfa\.[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,8}\.[A-Za-z0-9_-]{20,})\b"
)
TELEGRAM_BOT_TOKEN_RE = re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,60}\b")
GENERIC_WEBHOOK_URL_RE = re.compile(
    r"^https?://[^\s\"'<>]+/(?:api/)?(?:v\d+/)?(?:webhook|webhooks|hooks?)/[^\s\"'<>]+$",
    re.IGNORECASE,
)
DISCORD_SNOWFLAKE_RE = re.compile(r"^\d{17,20}$")
DISCORD_SNOWFLAKE_ANY_RE = re.compile(r"\b\d{17,20}\b")
DISCORD_ID_CONTEXT_RE = re.compile(
    r"(?:\bguild(?:_id)?\b|\bserver(?:_id)?\b|\bchannel(?:_id)?\b|\buser(?:_id)?\b|\brole(?:_id)?\b|\bapplication(?:_id)?\b|\bdiscord\b)",
    re.IGNORECASE,
)
HTTP_HOST_RE = re.compile(r'https?://([^/:\s"\'<>]+)', re.IGNORECASE)
ASSESSMENT_PREFIX = "assessment_"
BEHAVIOR_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

BEHAVIOR_SEVERITY_MAP = {
    "assessment_suspicious_possible_credential_exfiltration": "high",
    "assessment_needs_review_access_token_read_without_destination": "medium",
    "assessment_benign_fake_player_clone": "low",
    "assessment_benign_self_name_filtering": "low",
    "assessment_benign_session_override_for_alt_switching": "low",
    "assessment_benign_token_use_local_profilekey_setup": "low",
    "assessment_benign_token_getter_passthrough": "low",
    "assessment_benign_token_use_minecraft_auth_chain": "low",
    "uac_bypass_cmstp": "high",
    "defender_tampering": "high",
    "command_execution_capability": "high",
    "credential_exfiltration_post": "high",
    "possible_access_token_exfiltration": "high",
    "remote_urlclassloader_usage": "high",
    "possible_minecraft_session_file_exfiltration": "high",
    "dropper_elevation_helper": "high",
    "second_stage_jar_unpack": "high",
    "embedded_native_payload_loader": "high",
    "sandbox_escape_primitive_usage": "high",
    "dynamic_urlclassloader_usage": "medium",
    "obfuscator_or_packer_marker": "medium",
    "binary_payload_download": "medium",
    "dynamic_class_execution": "medium",
    "stealth_relaunch": "medium",
    "jnic_obfuscator_native_stub_usage": "medium",
    "windows_arch_payload_slicing": "medium",
    "native_code_execution_capability": "medium",
    "minecraft_session_file_access": "medium",
    "custom_decompression_runtime_internals": "medium",
    "windows_amd64_payload_range": "info",
    "windows_aarch64_payload_range": "info",
    "telemetry_or_beaconing": "low",
    "minecraft_gameprofile_access": "low",
    "minecraft_session_access": "low",
    "minecraft_username_access": "low",
    "minecraft_uuid_access": "low",
    "minecraft_access_token_access": "medium",
    "token_field_getter_passthrough": "low",
    "profile_use_fake_player_clone": "low",
    "profile_use_self_name_filtering": "low",
    "session_profile_override": "medium",
    "username_or_session_switching": "medium",
    "mixed_token_destinations_review": "medium",
    "token_sent_to_minecraft_auth_chain": "low",
    "token_use_profile_key_or_user_api_setup": "low",
    "remote_config_rpc_with_signature": "medium",
    "obfuscated_short_classname_cluster": "low",
}

MINECRAFT_AUTH_HOSTS = {
    "login.live.com",
    "auth.xboxlive.com",
    "user.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "api.minecraftservices.com",
}

AUTO_DECRYPT_TRIGGER_MIN_CALLS = 1
AUTO_DECRYPT_TRIGGER_MIN_FILE_RATIO = 0.0
AUTO_DECRYPT_TRIGGER_MIN_FILES_WITH_CALLS = 1
MAJOR_ENCRYPTED_MIN_CALLS = 200
MAJOR_ENCRYPTED_MIN_FILE_RATIO = 0.20
MAJOR_ENCRYPTED_MIN_FILES_WITH_CALLS = 5


@dataclass
class Finding:
    file: str
    line: int
    function: str
    decoded: str
    category: str
    note: str = ""


@dataclass
class BehaviorFinding:
    file: str
    line: int
    behavior: str
    evidence: str


@dataclass
class ArtifactFinding:
    path: str
    filename: str
    size: int
    sha256: str
    artifact_type: str
    evidence: str


@dataclass
class DecryptProfile:
    key_arrays: List[List[int]]
    xor_consts: List[int]
    add_consts: List[int]
    sub_consts: List[int]


def parse_int_list(raw: str) -> List[int]:
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return [int(p) for p in parts]


def _to_signed_byte(n: int) -> int:
    n = int(n)
    n &= 0xFF
    return n - 256 if n >= 128 else n


def parse_java_byte_list(raw: str) -> List[int]:
    vals: List[int] = []
    for m in JAVA_BYTE_TOKEN_RE.finditer(raw):
        vals.append(_to_signed_byte(int(m.group(1))))
    return vals


def _java_string_escape(s: str) -> str:
    out = []
    for ch in s:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 32 <= code <= 126:
            out.append(ch)
        else:
            out.append(f"\\u{code:04x}")
    return "".join(out)


def _extract_candidate_consts(text: str, op: str) -> List[int]:
    vals = set()
    pattern = re.compile(rf"\{re.escape(op)}\s*(?:\(\s*byte\s*\)\s*)?(-?\d+)")
    for m in pattern.finditer(text):
        v = int(m.group(1))
        if -255 <= v <= 255:
            vals.add(v & 0xFF)
    return sorted(vals)


def build_decrypt_profile(root: Path) -> Optional[DecryptProfile]:
    keys: List[List[int]] = []
    xor_consts: List[int] = []
    add_consts: List[int] = []
    sub_consts: List[int] = []

    decrypt_files = [p for p in root.rglob("*StringDecrypt*.java") if p.is_file()]
    if not decrypt_files:
        return None

    for p in decrypt_files:
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in NEW_BYTE_ARRAY_LITERAL_RE.finditer(text):
            arr = parse_java_byte_list(m.group("body"))
            if 2 <= len(arr) <= 64:
                keys.append(arr)

        xor_consts.extend(_extract_candidate_consts(text, "^"))
        add_consts.extend(_extract_candidate_consts(text, "+"))
        sub_consts.extend(_extract_candidate_consts(text, "-"))

    key_unique = []
    seen_keys = set()
    for k in keys:
        t = tuple(k)
        if t in seen_keys:
            continue
        seen_keys.add(t)
        key_unique.append(k)

    xor_unique = sorted(set(xor_consts))
    add_unique = sorted(set(add_consts))
    sub_unique = sorted(set(sub_consts))
    return DecryptProfile(
        key_arrays=key_unique,
        xor_consts=xor_unique,
        add_consts=add_unique,
        sub_consts=sub_unique,
    )


def _score_plaintext(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for ch in s if ch == "\n" or ch == "\r" or ch == "\t" or 32 <= ord(ch) <= 126)
    ratio = printable / len(s)
    alpha = sum(1 for ch in s if ch.isalpha()) / len(s)
    common = ["http", "post", "get", "authorization", "content-type", "json", "token", "hwid", "user-agent", "accept"]
    low = s.lower()
    bonus = 0.0
    for tok in common:
        if tok in low:
            bonus += 0.2
    return ratio * 1.6 + alpha * 0.4 + bonus


def _looks_meaningful_text(s: str) -> bool:
    if not s:
        return False
    ascii_printable = sum(1 for ch in s if ch in "\t\r\n" or 32 <= ord(ch) <= 126)
    ratio = ascii_printable / len(s)
    if ratio < 0.95:
        return False
    stripped = s.strip()
    if not stripped:
        return False
    if len(stripped) <= 3:
        allowed_short = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OK", "ID", "API"}
        return stripped.upper() in allowed_short
    letters = sum(1 for ch in stripped if ch.isalpha())
    digits = sum(1 for ch in stripped if ch.isdigit())
    symbols = len(stripped) - letters - digits - sum(1 for ch in stripped if ch.isspace())
    if letters == 0:
        return False
    if letters < 2 and len(stripped) >= 5:
        return False
    if symbols > max(4, len(stripped) // 2):
        return False
    return True


def _bytes_to_text(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except Exception:
        return raw.decode("latin-1", errors="replace")


def _decode_len_seed_xor_stream(raw: bytes, seed_magic: int, mul_const: int) -> bytes:
    key = (len(raw) ^ seed_magic) & 0xFF
    out = bytearray(len(raw))
    for i, b in enumerate(raw):
        key = ((key * mul_const) >> 16) & 0xFF
        out[i] = (b ^ key ^ (i >> 1)) & 0xFF
        key ^= i
    return bytes(out)


def _candidate_decodes_for_byte_array(vals: List[int], profile: Optional[DecryptProfile]) -> List[tuple[str, str]]:
    if not vals:
        return []
    raw = bytes(v & 0xFF for v in vals)
    out: List[tuple[str, str]] = []
    seen = set()

    def add_candidate(b: bytes, why: str) -> None:
        t = _bytes_to_text(b)
        key = (t, why)
        if key in seen:
            return
        seen.add(key)
        out.append((t, why))

    add_candidate(raw, "byte_array_raw")
    # Deterministic length-seeded XOR stream family (common in commodity Java obfuscators).
    add_candidate(
        _decode_len_seed_xor_stream(raw, seed_magic=1313161813, mul_const=73244475),
        "byte_array_len_seed_xor_stream magic=1313161813 mul=73244475",
    )

    for key in range(1, 256):
        dec = bytes((b ^ key) & 0xFF for b in raw)
        add_candidate(dec, f"byte_array_xor_single key=0x{key:02X}")

    if profile:
        for c in profile.xor_consts:
            dec = bytes((b ^ c) & 0xFF for b in raw)
            add_candidate(dec, f"byte_array_xor_const key=0x{c:02X}")
        for c in profile.add_consts:
            dec = bytes((b + c) & 0xFF for b in raw)
            add_candidate(dec, f"byte_array_add_const n={c}")
        for c in profile.sub_consts:
            dec = bytes((b - c) & 0xFF for b in raw)
            add_candidate(dec, f"byte_array_sub_const n={c}")
        for arr in profile.key_arrays:
            if not arr:
                continue
            dec = bytes(((b ^ (arr[i % len(arr)] & 0xFF)) & 0xFF) for i, b in enumerate(raw))
            add_candidate(dec, f"byte_array_xor_keyarray len={len(arr)}")

    return out


def decode_stringdecrypt_bytes(vals: List[int], profile: Optional[DecryptProfile]) -> tuple[str, str]:
    best = ""
    best_note = ""
    best_score = 0.0
    for text, note in _candidate_decodes_for_byte_array(vals, profile):
        score = _score_plaintext(text)
        if score > best_score:
            best_score = score
            best = text
            best_note = note
    if best and best_score >= 1.50 and _looks_meaningful_text(best):
        return best, best_note
    return "", ""


def decode_stringdecrypt_bytes_fallback(vals: List[int], profile: Optional[DecryptProfile]) -> tuple[str, str]:
    best = ""
    best_note = ""
    best_score = 0.0
    for text, note in _candidate_decodes_for_byte_array(vals, profile):
        score = _score_plaintext(text)
        if score > best_score:
            best_score = score
            best = text
            best_note = note
    if not best:
        return "", ""
    # Lower-confidence fallback for standard scan mode to avoid dropping all encrypted literals.
    ascii_printable = sum(1 for ch in best if ch in "\t\r\n" or 32 <= ord(ch) <= 126)
    ratio = ascii_printable / len(best) if best else 0.0
    if ratio < 0.75:
        return "", ""
    if "\x00" in best:
        return "", ""
    if best_score < 1.10:
        return "", ""
    return best, f"{best_note} forced_low_confidence"


def decode_stringdecrypt_bytes_force(vals: List[int], profile: Optional[DecryptProfile]) -> tuple[str, str]:
    best = ""
    best_note = ""
    best_score = -1.0
    for text, note in _candidate_decodes_for_byte_array(vals, profile):
        score = _score_plaintext(text)
        if score > best_score:
            best_score = score
            best = text
            best_note = note
    if not best:
        return "", ""
    if "\x00" in best:
        best = best.replace("\x00", "")
    if not best:
        return "", ""
    return best, f"{best_note} forced_any"


def decode_obf(d1: List[int], d2: List[int], k1: int, k2: int) -> str:
    length = len(d1) + len(d2)
    data = [0] * length

    for i, v in enumerate(d1):
        data[i * 2] = v
    for i, v in enumerate(d2):
        data[i * 2 + 1] = v

    sbox = [0] * 256
    for i in range(256):
        sbox[i] = (i * 53 + 97) % 256

    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i

    state = k2
    out = []

    for idx, value in enumerate(data):
        state = (state * 37 + idx * 13) % 256
        mask = (k2 + state + idx * 11) % 256

        if idx > 0:
            value ^= data[idx - 1]
        else:
            value ^= k2

        shift = (idx * 5 + k1) % 8
        rotated = ((value >> shift) | (value << (8 - shift))) & 0xFF
        substituted = inv_sbox[rotated]
        ch = chr((substituted ^ mask ^ k1) & 0xFFFF)
        out.append(ch)

    return "".join(out)


def build_line_starts(text: str) -> List[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def offset_to_line(line_starts: List[int], offset: int) -> int:
    return bisect.bisect_right(line_starts, offset)


def find_method_declarations(lines: List[str]) -> List[tuple[int, str]]:
    decls = []
    for idx, line in enumerate(lines, start=1):
        m = METHOD_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        if name in {"if", "for", "while", "switch", "catch", "return", "new"}:
            continue
        decls.append((idx, name))
    return decls


def nearest_method(decls: List[tuple[int, str]], line: int) -> str:
    method = "<unknown>"
    for decl_line, decl_name in decls:
        if decl_line <= line:
            method = decl_name
        else:
            break
    return method


def classify(decoded: str) -> str:
    d = decoded.strip()
    low = d.lower()
    discord_kind, _ = detect_discord_indicator(d)
    if discord_kind:
        return "discord_indicator"
    endpoint_kind, _ = detect_external_endpoint_indicator(d)
    if endpoint_kind:
        return "comms_indicator"
    if URL_RE.match(d):
        return "url"
    if d in {"Content-Type", "application/json"}:
        return "http_header"
    if "jsonrpc" in low or "eth_call" in low:
        return "rpc_template"
    if HEX_ADDR_RE.match(d):
        return "hex_or_contract"
    if BASE64_RE.match(d):
        return "base64_blob"
    if any(k in low for k in ["token", "uuid", "username", "minecraft", "access"]):
        return "credential_or_identity_field"
    if any(k in low for k in ["rsa", "sha256", "signature"]):
        return "crypto_primitive"
    if any(k in low for k in ["initialize", "main"]):
        return "dynamic_execution"
    if d.startswith("/"):
        return "path"
    return "string"


def base64_note(decoded: str) -> str:
    try:
        raw = base64.b64decode(decoded, validate=True)
        preview = raw[:8].hex()
        return f"base64_decoded_bytes={len(raw)} preview_hex={preview}"
    except Exception:
        return ""


def _mostly_printable(raw: bytes) -> bool:
    if not raw:
        return False
    ok = 0
    for b in raw:
        if b in (9, 10, 13) or 32 <= b <= 126:
            ok += 1
    return (ok / len(raw)) >= 0.85


def _to_printable(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def _maybe_xor_recover(raw: bytes) -> tuple[str, str]:
    # Simple single-byte XOR brute force for petty obfuscation.
    best_score = 0.0
    best = b""
    best_key = -1
    for key in range(1, 256):
        dec = bytes(b ^ key for b in raw)
        score = sum(1 for c in dec if c in (9, 10, 13) or 32 <= c <= 126) / len(dec)
        if score > best_score:
            best_score = score
            best = dec
            best_key = key
    text = _to_printable(best) if best else ""
    low = text.lower()
    interesting = any(k in low for k in ["http", "json", "token", "cmd", "powershell", "defender", "discord", "telegram", "webhook", "api"])
    if best and best_score >= 0.92 and interesting:
        return text, f"xor_single_byte_key=0x{best_key:02X}"
    return "", ""


def decode_encoded_literal(s: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    candidate = s.strip()
    compact = "".join(candidate.split())
    if len(candidate) < 16:
        return out

    if BASE64_RE.match(compact):
        try:
            raw = base64.b64decode(compact, validate=True)
            if _mostly_printable(raw):
                out.append(("base64_decoded", _to_printable(raw), f"decoded_bytes={len(raw)}"))
            else:
                x, note = _maybe_xor_recover(raw)
                if x:
                    out.append(("base64_xor_recovered", x, note))
                else:
                    ent = 0.0
                    if raw:
                        freq = [0] * 256
                        for b in raw:
                            freq[b] += 1
                        for c in freq:
                            if c:
                                p = c / len(raw)
                                ent -= p * math.log2(p)
                    out.append(
                        (
                            "base64_decoded_binary",
                            f"<binary {len(raw)} bytes>",
                            f"decoded_bytes={len(raw)} entropy={ent:.3f} hex_preview={raw[:16].hex().upper()}",
                        )
                    )
        except Exception:
            pass

    if BASE32_RE.match(compact):
        try:
            raw = base64.b32decode(compact, casefold=True)
            if _mostly_printable(raw):
                out.append(("base32_decoded", _to_printable(raw), f"decoded_bytes={len(raw)}"))
            else:
                x, note = _maybe_xor_recover(raw)
                if x:
                    out.append(("base32_xor_recovered", x, note))
                else:
                    ent = 0.0
                    if raw:
                        freq = [0] * 256
                        for b in raw:
                            freq[b] += 1
                        for c in freq:
                            if c:
                                p = c / len(raw)
                                ent -= p * math.log2(p)
                    out.append(
                        (
                            "base32_decoded_binary",
                            f"<binary {len(raw)} bytes>",
                            f"decoded_bytes={len(raw)} entropy={ent:.3f} hex_preview={raw[:16].hex().upper()}",
                        )
                    )
        except Exception:
            pass

    if HEX_BLOB_RE.match(compact):
        try:
            raw = bytes.fromhex(compact)
            if _mostly_printable(raw):
                out.append(("hex_decoded", _to_printable(raw), f"decoded_bytes={len(raw)}"))
            else:
                x, note = _maybe_xor_recover(raw)
                if x:
                    out.append(("hex_xor_recovered", x, note))
                else:
                    ent = 0.0
                    if raw:
                        freq = [0] * 256
                        for b in raw:
                            freq[b] += 1
                        for c in freq:
                            if c:
                                p = c / len(raw)
                                ent -= p * math.log2(p)
                    out.append(
                        (
                            "hex_decoded_binary",
                            f"<binary {len(raw)} bytes>",
                            f"decoded_bytes={len(raw)} entropy={ent:.3f} hex_preview={raw[:16].hex().upper()}",
                        )
                    )
        except Exception:
            pass

    return out


def decode_encoded_fragments(s: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    seen = set()
    # Decode whole string first
    for item in decode_encoded_literal(s):
        if item not in seen:
            seen.add(item)
            out.append(item)
    # Then decode composite pieces (e.g., URL|BASE64, JSON fields, multiline blobs)
    parts = re.split(r"[|,\s;]+", s.strip())
    for part in parts:
        part = part.strip()
        if len(part) < 16:
            continue
        for item in decode_encoded_literal(part):
            if item not in seen:
                seen.add(item)
                out.append(item)
    return out


def _unescape_java_literal(raw: str) -> str:
    try:
        return bytes(raw, "utf-8").decode("unicode_escape")
    except Exception:
        return raw


def detect_discord_indicator(decoded: str) -> tuple[str, str]:
    d = decoded.strip()
    low = d.lower()

    wm = DISCORD_WEBHOOK_RE.match(d)
    if wm:
        return "discord_webhook_url", f"webhook_id={wm.group('id')}"

    tm = DISCORD_BOT_TOKEN_RE.search(d)
    if tm:
        token = tm.group(0)
        masked = token[:6] + "..." + token[-6:] if len(token) > 16 else "<masked>"
        if low.startswith("bot "):
            return "discord_bot_authorization_header", f"token={masked}"
        return "discord_bot_token", f"token={masked}"

    if DISCORD_SNOWFLAKE_RE.match(d):
        return "discord_snowflake_id", "snowflake_numeric_id"

    if DISCORD_ID_CONTEXT_RE.search(d) and DISCORD_SNOWFLAKE_ANY_RE.search(d):
        return "discord_contextual_id", "contextual_snowflake_in_literal"

    if "discord.com/api/webhooks/" in low or "discordapp.com/api/webhooks/" in low:
        return "discord_webhook_path", "webhook_pattern_fragment"

    return "", ""


def detect_external_endpoint_indicator(decoded: str) -> tuple[str, str]:
    d = decoded.strip()
    low = d.lower()

    tm = TELEGRAM_BOT_TOKEN_RE.search(d)
    if tm:
        token = tm.group(0)
        masked = token[:6] + "..." + token[-6:] if len(token) > 16 else "<masked>"
        return "telegram_bot_token", f"token={masked}"

    if "api.telegram.org/bot" in low:
        return "telegram_bot_api_path", "telegram_bot_api_pattern"

    if low.startswith("bot ") and "telegram" in low:
        return "telegram_authorization_header", "telegram_bot_header_like_literal"

    if URL_RE.match(d):
        if GENERIC_WEBHOOK_URL_RE.match(d):
            return "generic_webhook_url", "generic_webhook_pattern"
        if any(x in low for x in ("slack.com/api/", "hooks.slack.com/", "api.telegram.org/bot")):
            return "third_party_webhook_or_bot_api", "known_non_discord_endpoint"

    if any(x in low for x in ("webhook", "hooks.slack.com", "api.telegram.org/bot", "slack.com/api/")):
        return "webhook_or_bot_api_fragment", "non_discord_endpoint_fragment"

    return "", ""


def classify_stringdecrypt_decoded(decoded: str, decode_note: str) -> str:
    low_note = (decode_note or "").lower()
    if "xor" in low_note or "len_seed_xor_stream" in low_note:
        return "xor_decrypted_string"
    return "decrypted_string"


def scan_string_literals(text: str, rel: str, starts: List[int], decls: List[tuple[int, str]], max_hits: int = 40) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    generic_hits = 0

    for m in STRING_ANY_LITERAL_RE.finditer(text):
        decoded = _unescape_java_literal(m.group(1)).strip()
        if len(decoded) < 4:
            continue

        low = decoded.lower()
        compact = "".join(decoded.split())
        signal = ""
        category = ""
        discord_kind, discord_note = detect_discord_indicator(decoded)
        endpoint_kind, endpoint_note = detect_external_endpoint_indicator(decoded)

        if (not discord_kind) and (not endpoint_kind) and generic_hits >= max_hits:
            continue

        if discord_kind:
            category = "discord_indicator"
            signal = discord_kind
        elif endpoint_kind:
            category = "comms_indicator"
            signal = endpoint_kind

        elif URL_RE.match(decoded):
            category = "url"
            signal = "literal_url"
        elif HEX_ADDR_RE.match(decoded) and len(decoded) == 42:
            category = "hex_or_contract"
            signal = "literal_contract_address"
        elif COMMAND_LITERAL_RE.search(decoded):
            category = "dynamic_execution"
            signal = "literal_command_or_lolbin"
        elif (
            decoded.startswith("/")
            or WINDOWS_PATH_RE.match(decoded)
            or "\\appdata\\" in low
            or "/tmp/" in low
            or decoded.endswith((".dll", ".exe", ".jar", ".dat", ".bin", ".ps1", ".bat", ".cmd"))
        ):
            category = "path"
            signal = "literal_path_or_payload_name"
        elif len(compact) >= 80 and BASE64_RE.match(compact):
            category = "base64_blob"
            signal = "literal_base64_blob"
        elif len(compact) >= 32 and HEX_BLOB_RE.match(compact):
            category = "string"
            signal = "literal_hex_blob"
        elif any(k in low for k in SUSPICIOUS_STRING_KEYWORDS):
            category = "credential_or_identity_field" if any(k in low for k in ("token", "authorization", "api_key", "bearer ")) else "string"
            signal = "literal_keyword_hit"
        else:
            continue

        line = offset_to_line(starts, m.start())
        function = nearest_method(decls, line)
        combined_note = " ".join([n for n in [discord_note, endpoint_note] if n]).strip()
        extra_note = f" {combined_note}" if combined_note else ""
        key = (line, decoded, category, signal, combined_note)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Finding(
                file=rel,
                line=line,
                function=function,
                decoded=decoded,
                category=category,
                note=f"source=string_scanner signal={signal}{extra_note}",
            )
        )
        if not discord_kind and not endpoint_kind:
            generic_hits += 1
    return out


def scan_all_string_literals(
    text: str,
    rel: str,
    starts: List[int],
    decls: List[tuple[int, str]],
    max_hits: int = 300,
) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    hits = 0
    for m in STRING_ANY_LITERAL_RE.finditer(text):
        if hits >= max_hits:
            break
        decoded = _unescape_java_literal(m.group(1)).strip()
        if len(decoded) < 4:
            continue
        key = decoded
        if key in seen:
            continue
        seen.add(key)
        line = offset_to_line(starts, m.start())
        function = nearest_method(decls, line)
        out.append(
            Finding(
                file=rel,
                line=line,
                function=function,
                decoded=decoded,
                category="string",
                note="source=string_literal_fullscan",
            )
        )
        hits += 1
    return out


def scan_stringdecrypt_calls(
    text: str,
    rel: str,
    starts: List[int],
    decls: List[tuple[int, str]],
    profile: Optional[DecryptProfile],
    max_hits: int = 120,
) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    hits = 0
    unresolved_total = 0
    unresolved_markers = 0
    unresolved_marker_cap = 5
    for m in STRING_DECRYPT_CALL_RE.finditer(text):
        if hits >= max_hits:
            break
        vals = parse_java_byte_list(m.group("bytes"))
        if not vals:
            continue
        decoded, note = decode_stringdecrypt_bytes(vals, profile)
        line = offset_to_line(starts, m.start())
        function = nearest_method(decls, line)
        if not decoded:
            decoded, note = decode_stringdecrypt_bytes_fallback(vals, profile)
        if not decoded:
            decoded, note = decode_stringdecrypt_bytes_force(vals, profile)
        if not decoded:
            unresolved_total += 1
            if unresolved_markers < unresolved_marker_cap:
                out.append(
                    Finding(
                        file=rel,
                        line=line,
                        function=function,
                        decoded="<encrypted StringDecrypt byte[] literal (unresolved)>",
                        category="encrypted_or_unresolved",
                        note="source=stringdecrypt_scanner signal=unresolved_byte_array_decrypt",
                    )
                )
                unresolved_markers += 1
                hits += 1
            continue
        category = classify_stringdecrypt_decoded(decoded, note)
        key = (line, decoded, category)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Finding(
                file=rel,
                line=line,
                function=function,
                decoded=decoded,
                category=category,
                note=f"source=stringdecrypt_scanner signal=byte_array_decrypt {note}".strip(),
            )
        )
        hits += 1
    if unresolved_total > unresolved_marker_cap:
        out.append(
            Finding(
                file=rel,
                line=1,
                function="<file>",
                decoded=f"<{unresolved_total} encrypted StringDecrypt byte[] literals unresolved>",
                category="encrypted_or_unresolved",
                note="source=stringdecrypt_scanner signal=unresolved_summary",
            )
        )
    return out


def deobfuscate_stringdecrypt_calls_in_file(path: Path, profile: Optional[DecryptProfile]) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    changed = 0
    unresolved = 0
    xor_changed = 0
    other_changed = 0
    parts: List[str] = []
    last = 0

    for m in STRING_DECRYPT_CALL_RE.finditer(text):
        parts.append(text[last : m.start("call")])
        vals = parse_java_byte_list(m.group("bytes"))
        decoded, _note = decode_stringdecrypt_bytes(vals, profile)
        if not decoded:
            decoded, _note = decode_stringdecrypt_bytes_fallback(vals, profile)
        if not decoded:
            decoded, _note = decode_stringdecrypt_bytes_force(vals, profile)
        if decoded:
            parts.append(f"\"{_java_string_escape(decoded)}\"")
            changed += 1
            low_note = (_note or "").lower()
            if "xor" in low_note or "len_seed_xor_stream" in low_note:
                xor_changed += 1
            else:
                other_changed += 1
        else:
            parts.append(m.group("call"))
            unresolved += 1
        last = m.end("call")
    parts.append(text[last:])
    if changed > 0:
        path.write_text("".join(parts), encoding="utf-8")
    return {
        "changed": changed,
        "unresolved": unresolved,
        "xor_changed": xor_changed,
        "other_changed": other_changed,
    }


def deobfuscate_load_calls_in_file(path: Path) -> tuple[int, int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    changed = 0
    unresolved = 0
    parts: List[str] = []
    last = 0

    for m in LOAD_CALL_RE.finditer(text):
        parts.append(text[last : m.start(0)])
        try:
            d1 = parse_int_list(m.group("d1"))
            d2 = parse_int_list(m.group("d2"))
            k1 = int(m.group("k1"))
            k2 = int(m.group("k2"))
            decoded = decode_obf(d1, d2, k1, k2)
        except Exception:
            decoded = ""
        if decoded:
            parts.append(f"\"{_java_string_escape(decoded)}\"")
            changed += 1
        else:
            parts.append(m.group(0))
            unresolved += 1
        last = m.end(0)
    parts.append(text[last:])
    if changed > 0:
        path.write_text("".join(parts), encoding="utf-8")
    return changed, unresolved


def deobfuscate_codebase(root: Path, profile: Optional[DecryptProfile], enabled_progress: bool, progress_console=None) -> dict:
    files = list(iter_java_files(root))
    file_changes = 0
    total_replaced = 0
    total_unresolved = 0
    calls_seen = 0
    files_with_calls = 0
    load_calls_seen = 0
    load_replaced = 0
    load_unresolved = 0
    stringdecrypt_xor_replaced = 0
    stringdecrypt_other_replaced = 0

    max_passes = 3
    pass_count = 0
    use_rich_progress = bool(enabled_progress and RICH_AVAILABLE and progress_console is not None)

    def run_passes(progress_task=None, progress_obj=None) -> None:
        nonlocal calls_seen, load_calls_seen, files_with_calls
        nonlocal file_changes, total_replaced, total_unresolved
        nonlocal load_replaced, load_unresolved, pass_count
        nonlocal stringdecrypt_xor_replaced, stringdecrypt_other_replaced
        for pass_idx in range(1, max_passes + 1):
            pass_count = pass_idx
            pass_changes = 0
            for idx, p in enumerate(files, start=1):
                text = p.read_text(encoding="utf-8", errors="replace")
                if pass_idx == 1:
                    c = len(list(STRING_DECRYPT_CALL_RE.finditer(text)))
                    lc = len(list(LOAD_CALL_RE.finditer(text)))
                    calls_seen += c
                    load_calls_seen += lc
                    if c > 0 or lc > 0:
                        files_with_calls += 1

                s_stats = deobfuscate_stringdecrypt_calls_in_file(p, profile)
                l_changed, l_unresolved = deobfuscate_load_calls_in_file(p)
                changed = int(s_stats.get("changed", 0))
                unresolved = int(s_stats.get("unresolved", 0))
                stringdecrypt_xor_replaced += int(s_stats.get("xor_changed", 0))
                stringdecrypt_other_replaced += int(s_stats.get("other_changed", 0))
                changed_total = changed + l_changed
                if changed_total > 0:
                    file_changes += 1
                    pass_changes += changed_total
                total_replaced += changed
                total_unresolved += unresolved
                load_replaced += l_changed
                load_unresolved += l_unresolved

                if progress_task is not None and progress_obj is not None:
                    progress_obj.advance(progress_task)
                elif enabled_progress and (idx == 1 or idx % 40 == 0 or idx == len(files)):
                    progress(
                        enabled_progress,
                        f"deobf pass{pass_idx} file {idx}/{len(files)} replaced={total_replaced + load_replaced} unresolved={total_unresolved + load_unresolved}",
                        progress_console,
                    )
            if pass_changes == 0:
                break

    if use_rich_progress:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]Deobfuscating Java files"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=progress_console,
            transient=False,
        ) as prog:
            task = prog.add_task("deobf", total=len(files) * max_passes)
            run_passes(task, prog)
            prog.update(task, completed=len(files) * max_passes)
    else:
        run_passes()

    return {
        "java_files": len(files),
        "calls_seen": calls_seen,
        "replaced": total_replaced,
        "unresolved": total_unresolved,
        "stringdecrypt_xor_replaced": stringdecrypt_xor_replaced,
        "stringdecrypt_other_replaced": stringdecrypt_other_replaced,
        "load_calls_seen": load_calls_seen,
        "load_replaced": load_replaced,
        "load_unresolved": load_unresolved,
        "files_changed": file_changes,
        "files_with_calls": files_with_calls,
        "passes_run": pass_count,
    }


def iter_java_files(root: Path) -> Iterable[Path]:
    yield from root.rglob("*.java")


def assess_auto_decrypt_need(root: Path) -> dict:
    files = list(iter_java_files(root))
    java_files = len(files)
    stringdecrypt_calls = 0
    load_calls = 0
    files_with_calls = 0

    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        sd_calls = sum(1 for _ in STRING_DECRYPT_CALL_RE.finditer(text))
        load_sd_calls = sum(1 for _ in LOAD_CALL_RE.finditer(text))
        if sd_calls or load_sd_calls:
            files_with_calls += 1
            stringdecrypt_calls += sd_calls
            load_calls += load_sd_calls

    total_obf_calls = stringdecrypt_calls + load_calls
    files_ratio = float(files_with_calls) / max(1, java_files)
    enabled = bool(
        total_obf_calls >= AUTO_DECRYPT_TRIGGER_MIN_CALLS
        or (
            files_with_calls >= AUTO_DECRYPT_TRIGGER_MIN_FILES_WITH_CALLS
            and files_ratio >= AUTO_DECRYPT_TRIGGER_MIN_FILE_RATIO
        )
    )
    reason = "no_obfuscated_calls"
    if java_files == 0:
        reason = "no_java_files"
    elif enabled:
        reason = "obfuscated_calls_detected"

    return {
        "enabled": enabled,
        "reason": reason,
        "java_files": java_files,
        "files_with_calls": files_with_calls,
        "files_with_calls_ratio": files_ratio,
        "stringdecrypt_calls": stringdecrypt_calls,
        "load_calls": load_calls,
        "total_obfuscated_calls": total_obf_calls,
        "thresholds": {
            "min_calls": AUTO_DECRYPT_TRIGGER_MIN_CALLS,
            "min_file_ratio": AUTO_DECRYPT_TRIGGER_MIN_FILE_RATIO,
            "min_files_with_calls": AUTO_DECRYPT_TRIGGER_MIN_FILES_WITH_CALLS,
        },
    }


def find_line(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def _extract_window_slice_info(text: str) -> dict:
    out: dict[str, tuple[int, int]] = {}
    lines = text.splitlines()
    current = ""
    start = None
    end = None

    def flush() -> None:
        nonlocal current, start, end
        if current and start is not None and end is not None:
            out[current] = (start, end)
        current = ""
        start = None
        end = None

    for line in lines:
        low = line.lower()
        if "contains(\"win\")" in low and "if" in low:
            flush()
            if "aarch64" in low:
                current = "win_aarch64"
            elif "amd64" in low or "x86_64" in low:
                current = "win_amd64"
            else:
                current = ""
            continue

        if not current:
            continue

        m2 = re.search(r"var2\s*=\s*(\d+)L\s*;", line)
        if m2:
            start = int(m2.group(1))
        m4 = re.search(r"var4\s*=\s*(\d+)L\s*;", line)
        if m4:
            end = int(m4.group(1))
            flush()

    flush()
    return out


def _extract_native_methods(text: str, contains_any: List[str]) -> List[str]:
    methods = []
    for m in re.finditer(r"\bnative\s+[^{;=]+\s+([A-Za-z_$][\w$]*)\s*\(", text):
        name = m.group(1)
        low = name.lower()
        if any(tok in low for tok in contains_any):
            methods.append(name)
    return sorted(set(methods))


def _contains_any(text: str, needles: List[str]) -> bool:
    return any(n in text for n in needles)


def _extract_http_hosts(text: str) -> set[str]:
    # Ignore URLs inside comments to reduce host classification false positives.
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    hosts: set[str] = set()
    for m in HTTP_HOST_RE.finditer(text):
        hosts.add(m.group(1).lower())
    return hosts


def scan_behavior(path: Path, root: Path) -> List[BehaviorFinding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    low = text.lower()
    rel = str(path.relative_to(root))
    rel_low = rel.replace("\\", "/").lower()
    is_vendor_lib = rel_low.startswith("com/sun/jna/") or rel_low.startswith("org/json/")
    out: List[BehaviorFinding] = []

    if "ProcessBuilder" in text and "javaw.exe" in text and "--jw" in text and "System.exit(0)" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "ProcessBuilder"),
                behavior="stealth_relaunch",
                evidence="Respawns itself with javaw.exe and exits current process",
            )
        )

    if "JarInputStream" in text and "getNextJarEntry" in text and "transferTo" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "JarInputStream"),
                behavior="second_stage_jar_unpack",
                evidence="Downloads bytes and unpacks jar entries in memory",
            )
        )

    if "loadClass(" in text and "getDeclaredConstructor().newInstance()" in text and "getMethod(" in text and ".invoke(" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "loadClass("),
                behavior="dynamic_class_execution",
                evidence="Loads class and invokes method reflectively",
            )
        )

    if "URLClassLoader" in text:
        hosts = _extract_http_hosts(text)
        if hosts:
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "URLClassLoader"),
                    behavior="remote_urlclassloader_usage",
                    evidence="URLClassLoader is present alongside remote host URLs: " + ", ".join(sorted(hosts)),
                )
            )
        else:
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "URLClassLoader"),
                    behavior="dynamic_urlclassloader_usage",
                    evidence="Uses URLClassLoader to dynamically load classes/resources",
                )
            )

    if "HttpClient.newHttpClient()" in text and "BodyHandlers.ofByteArray()" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "BodyHandlers.ofByteArray()"),
                behavior="binary_payload_download",
                evidence="Performs HTTP GET and downloads raw bytes",
            )
        )

    if any(k in low for k in ["proguard", "allatori", "stringer", "zelix", "dasho", "yguard", "r8"]):
        out.append(
            BehaviorFinding(
                file=rel,
                line=1,
                behavior="obfuscator_or_packer_marker",
                evidence="Contains explicit obfuscator/packer marker strings (e.g., ProGuard/Allatori/Stringer/Zelix/DashO/R8)",
            )
        )

    has_get_game_profile = _contains_any(text, ["method_7334()", "getGameProfile()"])
    has_get_session = _contains_any(text, ["method_1548()", "getSession()", "getUser()"])
    has_get_access_token = _contains_any(text, ["method_1674()", "getAccessToken()"])
    has_fake_player_clone = False
    has_self_name_filtering = False
    has_session_profile_override = False
    has_username_or_session_switching = False
    has_token_sent_to_trusted_chain = False
    has_mixed_token_destinations = False
    has_possible_token_exfiltration = False
    has_credential_exfil_post = False
    has_internal_profile_key_usage = False
    has_token_getter_passthrough = False

    if has_get_game_profile:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getGameProfile()") if "getGameProfile()" in text else find_line(text, "method_7334()"),
                behavior="minecraft_gameprofile_access",
                evidence="Reads player GameProfile (method_7334/getGameProfile)",
            )
        )

    if has_get_session:
        session_line = find_line(text, "getSession()")
        if session_line == 1 and "getSession()" not in text:
            session_line = find_line(text, "getUser()")
        if session_line == 1 and "getUser()" not in text:
            session_line = find_line(text, "method_1548()")
        out.append(
            BehaviorFinding(
                file=rel,
                line=session_line,
                behavior="minecraft_session_access",
                evidence="Accesses Minecraft session/user object (method_1548/getSession/getUser)",
            )
        )

    if "method_1676()" in text or ".getName()" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "method_1676()") if "method_1676()" in text else find_line(text, ".getName()"),
                behavior="minecraft_username_access",
                evidence="Reads Minecraft session username (method_1676/getName)",
            )
        )

    if "method_44717()" in text or ".getProfileId()" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "method_44717()") if "method_44717()" in text else find_line(text, ".getProfileId()"),
                behavior="minecraft_uuid_access",
                evidence="Reads Minecraft session UUID (method_44717/getProfileId)",
            )
        )

    if has_get_access_token:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getAccessToken()") if "getAccessToken()" in text else find_line(text, "method_1674()"),
                behavior="minecraft_access_token_access",
                evidence="Reads Minecraft session access token (method_1674/getAccessToken)",
            )
        )
        if "private final String mcAccessToken;" in text and "return mcAccessToken;" in text:
            has_token_getter_passthrough = True
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "return mcAccessToken;"),
                    behavior="token_field_getter_passthrough",
                    evidence="Access token is returned as a plain DTO/profile field accessor",
                )
            )

    if "extends RemotePlayer" in text and "super(" in text and "getGameProfile()" in text:
        has_fake_player_clone = True
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "super("),
                behavior="profile_use_fake_player_clone",
                evidence="Uses local GameProfile when constructing a fake/remote player clone",
            )
        )

    if "getGameProfile().name()" in text and "names.remove(selfName)" in text:
        has_self_name_filtering = True
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getGameProfile().name()"),
                behavior="profile_use_self_name_filtering",
                evidence="Reads own GameProfile name and removes it from scanned player set",
            )
        )

    if (
        'method = "getGameProfile()Lcom/mojang/authlib/GameProfile;"' in text
        and "new GameProfile(" in text
        and ".getProfileId()" in text
        and ".getName()" in text
    ):
        has_session_profile_override = True
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, 'method = "getGameProfile()Lcom/mojang/authlib/GameProfile;"'),
                behavior="session_profile_override",
                evidence="Intercepts getGameProfile and returns profile id/name derived from the active replacement session",
            )
        )

    if "setWurstSession(" in text and "wurstSession" in text:
        has_username_or_session_switching = True

    if "setWurstSession(" in text and "new User(" in text:
        has_username_or_session_switching = True
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "setWurstSession("),
                behavior="username_or_session_switching",
                evidence="Constructs replacement User session and switches the active client identity",
            )
        )

    token_markers = [
        "method_1674()",
        "getAccessToken()",
        "session.getAccessToken()",
        "mcAccessToken",
        "access_token",
    ]
    has_token_material = _contains_any(text, token_markers)
    has_auth_header = "Authorization" in text and "Bearer " in text
    if has_token_material and has_auth_header:
        hosts = _extract_http_hosts(text)
        trusted_hosts = {h for h in hosts if h in MINECRAFT_AUTH_HOSTS}
        untrusted_hosts = hosts - MINECRAFT_AUTH_HOSTS
        if trusted_hosts and not untrusted_hosts:
            has_token_sent_to_trusted_chain = True
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "Authorization"),
                    behavior="token_sent_to_minecraft_auth_chain",
                    evidence="Bearer token appears limited to trusted Microsoft/Minecraft auth hosts: "
                    + ", ".join(sorted(trusted_hosts)),
                )
            )
        elif trusted_hosts and untrusted_hosts:
            has_mixed_token_destinations = True
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "Authorization"),
                    behavior="mixed_token_destinations_review",
                    evidence="Bearer token usage touches trusted and non-trusted hosts; trusted="
                    + ",".join(sorted(trusted_hosts))
                    + " untrusted="
                    + ",".join(sorted(untrusted_hosts)),
                )
            )
        elif untrusted_hosts:
            has_possible_token_exfiltration = True
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "Authorization"),
                    behavior="possible_access_token_exfiltration",
                    evidence="Bearer token usage appears on non-Microsoft/Minecraft hosts: "
                    + ", ".join(sorted(untrusted_hosts)),
                )
            )

    if has_get_access_token and ("createUserApiService(" in text or "ProfileKeyPairManager.create(" in text):
        has_internal_profile_key_usage = True
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "createUserApiService(") if "createUserApiService(" in text else find_line(text, "ProfileKeyPairManager.create("),
                behavior="token_use_profile_key_or_user_api_setup",
                evidence="Uses access token for local profile-key/user-api initialization rather than outbound exfiltration flow",
            )
        )

    if "System.getenv(" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "System.getenv("),
                behavior="environment_variable_access",
                evidence="Reads environment variables via System.getenv",
            )
        )

    if "System.load(" in text or "System.loadLibrary(" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "System.load(") if "System.load(" in text else find_line(text, "System.loadLibrary("),
                behavior="native_code_execution_capability",
                evidence="Loads native code via System.load/System.loadLibrary",
            )
        )

    if any(k in text for k in ["com.sun.jna", "jnr.ffi", "sun.misc.Unsafe", "jdk.internal.misc.Unsafe"]):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "com.sun.jna") if "com.sun.jna" in text else find_line(text, "Unsafe"),
                behavior="sandbox_escape_primitive_usage",
                evidence="Contains JNA/Unsafe style primitive often used to bridge outside normal JVM safety boundaries",
            )
        )

    mc_session_files = ["session.json", "launcher_accounts.json", ".minecraft"]
    # Limit detection to explicit string literals to avoid import-only or comment noise.
    string_literals = [m.group(1).lower() for m in STRING_ANY_LITERAL_RE.finditer(text)]
    lit_ref_hit = any(any(tok in lit for tok in mc_session_files) for lit in string_literals)
    # Require likely file I/O usage hints to classify as file access.
    fileio_markers = [
        "new File(",
        "Paths.get(",
        "Files.read",
        "FileInputStream(",
        "FileReader(",
        "Files.newBufferedReader(",
        "Files.newInputStream(",
        "Scanner(",
        "Files.lines(",
    ]
    has_fileio = any(marker in text for marker in fileio_markers)
    if lit_ref_hit and has_fileio:
        # Choose the earliest referenced token for accurate line reporting.
        chosen_token = None
        for tok in mc_session_files:
            if any(tok in lit for lit in string_literals):
                chosen_token = tok
                break
        chosen_token = chosen_token or "session.json"
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, chosen_token),
                behavior="minecraft_session_file_access",
                evidence="References local Minecraft session/account storage paths (session.json/launcher_accounts.json/.minecraft)",
            )
        )
        if _extract_http_hosts(text) or ("HttpClient" in text and "send(" in text):
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, chosen_token),
                    behavior="possible_minecraft_session_file_exfiltration",
                    evidence="Session/account file reference appears in file that also contains outbound HTTP activity",
                )
            )

    if "payload.addProperty" in text and "client.send(req" in text:
        has_credential_exfil_post = True
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "payload.addProperty"),
                behavior="credential_exfiltration_post",
                evidence="Builds JSON payload from session fields and sends HTTP POST",
            )
        )

    if ("$jnicLoader" in text or "$jnicClinit" in text or "JNICLoader.init()" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "JNICLoader.init()") if "JNICLoader.init()" in text else find_line(text, "$jnicLoader"),
                behavior="jnic_obfuscator_native_stub_usage",
                evidence="Contains JNIC-linked native stub wiring ($jnicLoader/$jnicClinit or JNICLoader.init())",
            )
        )

    if (
        "getResourceAsStream(" in text
        and "File.createTempFile(" in text
        and ("System.load(" in text or "System.loadLibrary(" in text)
        and (".dat" in text or ".bin" in text)
    ):
        refs = [m.group(1) for m in RESOURCE_STREAM_RE.finditer(text)]
        ref_note = f" resource={refs[0]}" if refs else ""
        temp_m = CREATE_TEMP_RE.search(text)
        temp_note = ""
        if temp_m:
            prefix = temp_m.group(1)
            suffix = temp_m.group(2).strip()
            temp_note = f" temp_create=File.createTempFile(prefix={prefix!r}, suffix={suffix})"
        load_note = ""
        if "getAbsolutePath()" in text and "System.load(" in text:
            load_note = " load_target=temp_file_absolute_path"
        del_note = " delete_on_exit=true" if "deleteOnExit()" in text else ""
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getResourceAsStream("),
                behavior="embedded_native_payload_loader",
                evidence=f"Reads embedded binary resource, writes temp native file, and dynamically loads it{ref_note}{temp_note}{load_note}{del_note}",
            )
        )

    if (
        "System.getProperty(\"os.name\")" in text
        and "System.getProperty(\"os.arch\")" in text
        and ("contains(\"win\")" in text or "windows" in text.lower())
        and ("amd64" in text.lower() or "x86_64" in text.lower() or "aarch64" in text.lower())
        and ("skip(" in text or "read(" in text)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "System.getProperty(\"os.name\")"),
                behavior="windows_arch_payload_slicing",
                evidence="Selects payload bytes by Windows architecture and extracts a platform-specific segment",
            )
        )
        slice_info = _extract_window_slice_info(text)
        amd64 = slice_info.get("win_amd64")
        if amd64:
            start, end = amd64
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "amd64"),
                    behavior="windows_amd64_payload_range",
                    evidence=f"offset_start={start} offset_end={end} length={end - start}",
                )
            )
        aarch64 = slice_info.get("win_aarch64")
        if aarch64:
            start, end = aarch64
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "aarch64"),
                    behavior="windows_aarch64_payload_range",
                    evidence=f"offset_start={start} offset_end={end} length={end - start}",
                )
            )

    if "cmstp" in low and ("elevate" in low or "simulatepressenter" in low or "runcmstp" in low):
        cmstp_methods = _extract_native_methods(text, ["cmstp", "elevat", "simulatepressenter"])
        method_note = f" native_methods={','.join(cmstp_methods)}" if cmstp_methods else ""
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "CMSTP"),
                behavior="uac_bypass_cmstp",
                evidence=f"Contains CMSTP-based elevation/UAC bypass primitives{method_note}",
            )
        )

    if "defender" in low and "exclusion" in low:
        def_methods = _extract_native_methods(text, ["defender", "exclusion"])
        method_note = f" native_methods={','.join(def_methods)}" if def_methods else ""
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "Defender"),
                behavior="defender_tampering",
                evidence=f"Contains logic to modify Defender exclusion settings{method_note}",
            )
        )

    if (
        "HttpClient" in text
        and ("jsonrpc" in low or "eth_call" in low or "rpc" in low)
        and ("verify" in low or "signature" in low or "rsa" in low)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "HttpClient"),
                behavior="remote_config_rpc_with_signature",
                evidence="Uses HTTP/RPC flow with signature/crypto checks to validate remote config",
            )
        )

    if "telemetry" in low and ("init" in low or "send" in low):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "Telemetry"),
                behavior="telemetry_or_beaconing",
                evidence="Contains telemetry initialization or transport routines",
            )
        )

    if (not is_vendor_lib) and ("Runtime.getRuntime().exec(" in text or "ProcessBuilder(" in text or "doSystem(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "doSystem(") if "doSystem(" in text else find_line(text, "ProcessBuilder("),
                behavior="command_execution_capability",
                evidence="Contains command execution primitives",
            )
        )

    if ("download" in low and "todisk" in low) or ("elevate(" in text and "getCurrentJar(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "download"),
                behavior="dropper_elevation_helper",
                evidence="Contains helper logic for dropping files to disk and elevation workflow",
            )
        )

    # Context-aware assessment layer for Minecraft-related findings.
    if has_fake_player_clone:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "super("),
                behavior="assessment_benign_fake_player_clone",
                evidence="Benign context: GameProfile is used to build a local fake-player clone entity, not for credential exfiltration",
            )
        )

    if has_self_name_filtering:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getGameProfile().name()"),
                behavior="assessment_benign_self_name_filtering",
                evidence="Benign context: own username is removed from scanned player sets to avoid self-matches",
            )
        )

    if has_session_profile_override and has_username_or_session_switching:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, 'method = "getGameProfile()Lcom/mojang/authlib/GameProfile;"'),
                behavior="assessment_benign_session_override_for_alt_switching",
                evidence="Benign context: profile override is tied to explicit local session switching (alt/account management behavior)",
            )
        )

    if has_internal_profile_key_usage and not has_possible_token_exfiltration:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "createUserApiService(") if "createUserApiService(" in text else find_line(text, "ProfileKeyPairManager.create("),
                behavior="assessment_benign_token_use_local_profilekey_setup",
                evidence="Benign context: token is consumed by Minecraft auth/profile-key services for local session functionality",
            )
        )

    if has_token_getter_passthrough and not has_possible_token_exfiltration:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "return mcAccessToken;"),
                behavior="assessment_benign_token_getter_passthrough",
                evidence="Benign context: token access is a local data-holder getter with no outbound network sink in this file",
            )
        )

    if has_token_sent_to_trusted_chain and not has_possible_token_exfiltration and not has_mixed_token_destinations:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "Authorization"),
                behavior="assessment_benign_token_use_minecraft_auth_chain",
                evidence="Benign context: bearer token usage appears limited to Microsoft/Minecraft auth endpoints",
            )
        )

    if has_get_access_token and not has_token_getter_passthrough and not has_internal_profile_key_usage and not has_token_sent_to_trusted_chain and not has_possible_token_exfiltration:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getAccessToken()") if "getAccessToken()" in text else find_line(text, "method_1674()"),
                behavior="assessment_needs_review_access_token_read_without_destination",
                evidence="Access token is read but destination flow is not fully visible in this file; review call graph before labeling malicious",
            )
        )

    if has_possible_token_exfiltration or has_credential_exfil_post:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "Authorization") if "Authorization" in text else find_line(text, "payload.addProperty"),
                behavior="assessment_suspicious_possible_credential_exfiltration",
                evidence="Potential exfiltration signal: token/credential material appears to be prepared for outbound transmission",
            )
        )

    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_entropy(path: Path) -> float:
    counts = [0] * 256
    total = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            for b in chunk:
                counts[b] += 1
    if total == 0:
        return 0.0
    ent = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        ent -= p * math.log2(p)
    return ent


def head_hex(path: Path, size: int = 16) -> str:
    with path.open("rb") as f:
        data = f.read(size)
    return data.hex().upper()


def archive_signature_status(path: Path) -> str:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = [n.upper() for n in zf.namelist()]
        has_sig = any(n.startswith("META-INF/") and (n.endswith(".SF") or n.endswith(".RSA") or n.endswith(".DSA")) for n in names)
        return "signed" if has_sig else "unsigned_or_no_publisher_signature"
    except Exception:
        return "unknown"


def _human_size(num_bytes: int) -> str:
    units = ["bytes", "KB", "MB", "GB", "TB"]
    size = float(max(0, num_bytes))
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def _fmt_dt(ts: float | None) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _hash_file(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_command(args: List[str]) -> str:
    try:
        cp = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
    except Exception:
        return ""
    out = (cp.stdout or "").strip()
    err = (cp.stderr or "").strip()
    return out if out else err


def _compute_ssdeep(path: Path) -> str:
    if not shutil.which("ssdeep"):
        return ""
    out = _run_command(["ssdeep", str(path)])
    if not out:
        return ""
    for line in out.splitlines():
        s = line.strip()
        if ":" in s and "," in s and not s.lower().startswith("ssdeep"):
            return s.split(",", 1)[0].strip()
    return ""


def _compute_tlsh(path: Path) -> str:
    if not shutil.which("tlsh"):
        return ""
    out = _run_command(["tlsh", "-f", str(path)])
    if not out:
        return ""
    m = re.search(r"\bT[0-9A-F]{30,}\b", out, flags=re.IGNORECASE)
    return m.group(0).upper() if m else ""


def _compute_trid(path: Path) -> str:
    if not shutil.which("trid"):
        return ""
    out = _run_command(["trid", str(path)])
    if not out:
        return ""
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    score_lines = [ln for ln in lines if "%" in ln]
    if score_lines:
        return "   ".join(score_lines[:3])
    return lines[-1] if lines else ""


def _compute_magika(path: Path) -> str:
    try:
        from magika import Magika  # type: ignore
    except Exception:
        return ""
    try:
        m = Magika()
        result = m.identify_path(path)
        for candidate in [
            getattr(result, "output", None),
            getattr(result, "prediction", None),
            result,
        ]:
            if candidate is None:
                continue
            for attr in ["label", "ct_label", "group", "value", "name"]:
                v = getattr(candidate, attr, None)
                if isinstance(v, str) and v.strip():
                    return v.strip().upper()
        return ""
    except Exception:
        return ""


def _compute_vhash(path: Path) -> str:
    # Optional external tool support only; no synthetic placeholder.
    if not shutil.which("vhash"):
        return ""
    out = _run_command(["vhash", str(path)])
    if not out:
        return ""
    m = re.search(r"\b[a-fA-F0-9]{16,64}\b", out)
    return m.group(0).lower() if m else out.splitlines()[-1].strip()


def _find_primary_jar(root: Path) -> Path | None:
    jars = [p for p in root.rglob("*.jar") if p.is_file()]
    if not jars:
        return None
    return max(jars, key=lambda p: p.stat().st_size)


def _classify_bundle_type(ext: str) -> str:
    low = ext.lower()
    if low == ".json":
        return "JSON"
    if low == ".xml":
        return "XML"
    return "UNKNOWN"


def _read_manifest_from_dir(root: Path) -> str:
    candidates = [root / "META-INF" / "MANIFEST.MF"]
    for p in root.rglob("MANIFEST.MF"):
        if p not in candidates:
            candidates.append(p)
        if len(candidates) >= 5:
            break
    for c in candidates:
        if c.exists() and c.is_file():
            return c.read_text(encoding="utf-8", errors="replace").strip()
    return ""


def _read_manifest_from_jar(jar_path: Path) -> str:
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            raw = zf.read("META-INF/MANIFEST.MF")
        return raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _archive_metadata_from_jar(jar_path: Path) -> dict:
    out = {
        "contained_directories": 0,
        "max_directory_depth": 0,
        "contained_files": 0,
        "latest_content_modification": "",
        "earliest_content_modification": "",
        "contained_files_by_type": {},
    }
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            infos = zf.infolist()
        dirs = [i for i in infos if i.is_dir()]
        files = [i for i in infos if not i.is_dir()]
        out["contained_directories"] = len(dirs)
        out["contained_files"] = len(files)
        depths = [i.filename.strip("/").count("/") + 1 for i in infos if i.filename.strip("/")]
        out["max_directory_depth"] = max(depths) if depths else 0
        if files:
            dt_values = [datetime(*i.date_time) for i in files]
            out["earliest_content_modification"] = min(dt_values).strftime("%Y-%m-%d %H:%M:%S")
            out["latest_content_modification"] = max(dt_values).strftime("%Y-%m-%d %H:%M:%S")
        type_counts: dict[str, int] = {}
        text_exts = {".mf", ".properties", ".txt", ".cfg", ".ini", ".java", ".xml", ".json", ".yml", ".yaml", ".pro"}
        for i in files:
            ext = Path(i.filename).suffix.lower()
            t = "xml" if ext == ".xml" else ("ascii" if ext in text_exts else "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        out["contained_files_by_type"] = dict(sorted(type_counts.items(), key=lambda x: (-x[1], x[0])))
    except Exception:
        pass
    return out


def collect_target_metadata(root: Path) -> dict:
    primary_jar = _find_primary_jar(root)
    total_size = 0
    earliest_ts = None
    latest_ts = None
    file_count = 0
    dir_count = 0
    by_ext: dict[str, int] = {}
    by_type: dict[str, int] = {}

    for p in root.rglob("*"):
        if p.is_dir():
            dir_count += 1
            continue
        if not p.is_file():
            continue
        st = p.stat()
        file_count += 1
        total_size += st.st_size
        mt = st.st_mtime
        earliest_ts = mt if earliest_ts is None else min(earliest_ts, mt)
        latest_ts = mt if latest_ts is None else max(latest_ts, mt)
        ext = p.suffix[1:].upper() if p.suffix else "NOEXT"
        by_ext[ext] = by_ext.get(ext, 0) + 1
        t = _classify_bundle_type(p.suffix)
        by_type[t] = by_type.get(t, 0) + 1

    by_type["DIRECTORY"] = dir_count
    by_type = dict(sorted(by_type.items(), key=lambda x: (-x[1], x[0])))
    by_ext = dict(sorted(by_ext.items(), key=lambda x: (-x[1], x[0])))

    basic = {
        "subject": str(primary_jar.relative_to(root)) if primary_jar else str(root),
        "md5": "",
        "sha1": "",
        "sha256": "",
        "file_type": "JAR" if primary_jar else "DIRECTORY",
        "compressed": "jar" if primary_jar else "",
        "magic": "Zip archive data (JAR)" if primary_jar else "Directory bundle",
        "file_size_text": "",
        "file_size_bytes": 0,
    }

    if primary_jar:
        sz = primary_jar.stat().st_size
        basic["md5"] = _hash_file(primary_jar, "md5")
        basic["sha1"] = _hash_file(primary_jar, "sha1")
        basic["sha256"] = _hash_file(primary_jar, "sha256")
        ssdeep = _compute_ssdeep(primary_jar)
        if ssdeep:
            basic["ssdeep"] = ssdeep
        tlsh = _compute_tlsh(primary_jar)
        if tlsh:
            basic["tlsh"] = tlsh
        trid = _compute_trid(primary_jar)
        if trid:
            basic["trid"] = trid
        magika = _compute_magika(primary_jar)
        if magika:
            basic["magika"] = magika
        vhash = _compute_vhash(primary_jar)
        if vhash:
            basic["vhash"] = vhash
        basic["file_size_text"] = _human_size(sz)
        basic["file_size_bytes"] = sz
    else:
        basic["file_size_text"] = _human_size(total_size)
        basic["file_size_bytes"] = total_size

    manifest = _read_manifest_from_jar(primary_jar) if primary_jar else _read_manifest_from_dir(root)
    if primary_jar:
        archive_meta = _archive_metadata_from_jar(primary_jar)
    else:
        archive_meta = {
            "contained_directories": dir_count,
            "max_directory_depth": max((len(p.relative_to(root).parts) for p in root.rglob("*")), default=0),
            "contained_files": file_count,
            "latest_content_modification": _fmt_dt(latest_ts),
            "earliest_content_modification": _fmt_dt(earliest_ts),
            "contained_files_by_type": {
                "xml": by_type.get("XML", 0),
                "ascii": file_count - by_type.get("XML", 0),
            },
        }

    jar_info = {
        "manifest": manifest,
        "archive_metadata": archive_meta,
    }

    bundle_info = {
        "contained_files": file_count,
        "uncompressed_size_text": _human_size(total_size),
        "uncompressed_size_bytes": total_size,
        "earliest_content_modification": _fmt_dt(earliest_ts),
        "latest_content_modification": _fmt_dt(latest_ts),
        "contained_files_by_type": by_type,
        "contained_files_by_extension": by_ext,
    }

    return {
        "basic_properties": basic,
        "jar_info": jar_info,
        "bundle_info": bundle_info,
    }


def discover_structural_behaviors(root: Path) -> List[BehaviorFinding]:
    out: List[BehaviorFinding] = []
    for d in root.rglob("*"):
        if not d.is_dir():
            continue
        java_files = list(d.glob("*.java"))
        if len(java_files) < 4:
            continue
        names = [p.stem for p in java_files]
        short_names = [n for n in names if len(n) <= 2]
        if len(short_names) >= 5:
            rel = str(d.relative_to(root))
            sample = ",".join(sorted(short_names)[:8])
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=1,
                    behavior="obfuscated_short_classname_cluster",
                    evidence=f"Many short/non-semantic class names detected count={len(short_names)} sample={sample}",
                )
            )

            text_map = {}
            for jf in java_files:
                text_map[jf.name] = jf.read_text(encoding="utf-8", errors="replace")
            has_loader = any("extends InputStream" in t and "System.load(" in t for t in text_map.values())
            has_range = any((">>> 11" in t and "short[]" in t) for t in text_map.values())
            has_window = any(("copy" in t.lower() and "byte[]" in t and "IOException" in t) for t in text_map.values())
            if has_loader and has_range and has_window:
                out.append(
                    BehaviorFinding(
                        file=rel,
                        line=1,
                        behavior="custom_decompression_runtime_internals",
                        evidence="Package appears to contain custom range-coder/LZ-style decompression helpers used by a native payload loader",
                    )
                )
    return out


def discover_artifacts(root: Path) -> List[ArtifactFinding]:
    out: List[ArtifactFinding] = []
    candidates: List[Path] = []
    referenced_resources = set()
    native_load_present = False
    temp_drop_present = False

    java_files = list(iter_java_files(root))
    for j in java_files:
        text = j.read_text(encoding="utf-8", errors="replace")
        if "System.load(" in text or "System.loadLibrary(" in text:
            native_load_present = True
        if "File.createTempFile(" in text:
            temp_drop_present = True
        for m in RESOURCE_STREAM_RE.finditer(text):
            raw = m.group(1).lstrip("/\\")
            parts = [p for p in re.split(r"[\\/]+", raw) if p]
            if parts:
                referenced_resources.add("/".join(parts).lower())

    candidates.extend(root.rglob("*.jar.*"))
    candidates.extend(root.rglob("*.dat"))
    candidates.extend(root.rglob("*.bin"))

    seen = set()
    for p in candidates:
        if not p.is_file():
            continue
        rp = str(p.resolve())
        if rp in seen:
            continue
        seen.add(rp)

        rel = str(p.relative_to(root))
        artifact_type = "unknown_artifact"
        evidence = "Suspicious artifact discovered"
        low = rel.lower()
        low_norm = low.replace("\\", "/")
        referenced = low_norm in referenced_resources

        if ".jar." in low:
            artifact_type = "renamed_archive_or_payload"
            sig = archive_signature_status(p)
            evidence = (
                f"Archive with non-standard extra extension (potential staging/evasion); "
                f"publisher_signature={sig}; entropy={file_entropy(p):.3f}; header_hex={head_hex(p)}"
            )
        elif referenced and p.suffix.lower() in {".dat", ".bin"} and native_load_present:
            artifact_type = "packed_native_payload_container"
            evidence = (
                f"Embedded opaque resource is referenced and native loading behavior is present; "
                f"entropy={file_entropy(p):.3f}; header_hex={head_hex(p)}"
            )
        elif referenced:
            artifact_type = "embedded_resource_artifact"
            evidence = "File is referenced via getResourceAsStream and may be unpacked at runtime"
        elif p.suffix.lower() in {".dat", ".bin"} and p.stat().st_size >= 128 * 1024:
            artifact_type = "large_opaque_blob"
            evidence = f"Large opaque blob often used for packed second-stage payloads; entropy={file_entropy(p):.3f}; header_hex={head_hex(p)}"

        out.append(
            ArtifactFinding(
                path=rel,
                filename=p.name,
                size=p.stat().st_size,
                sha256=sha256_file(p),
                artifact_type=artifact_type,
                evidence=evidence,
            )
        )

    if native_load_present and temp_drop_present:
        out.append(
            ArtifactFinding(
                path="<runtime-temp-native-module>",
                filename="lib* (temp)",
                size=-1,
                sha256="",
                artifact_type="inferred_runtime_drop_and_execute",
                evidence="Code indicates extraction of embedded bytes to temp file followed by native load/execute",
            )
        )

    return sorted(out, key=lambda x: x.path)


def decode_abi_string(hex_result: str) -> str:
    data = hex_result[2:] if hex_result.startswith("0x") else hex_result
    if len(data) < 128:
        return ""
    strlen = int(data[64:128], 16)
    payload_hex = data[128 : 128 + strlen * 2]
    chars = []
    for i in range(0, len(payload_hex), 2):
        b = int(payload_hex[i : i + 2], 16)
        if b != 0:
            chars.append(chr(b))
    return "".join(chars)


def resolve_runtime_c2(findings: List[Finding], timeout: int = 12) -> dict:
    rpc_urls = [f.decoded for f in findings if f.category == "url" and "/eth" in f.decoded]
    addresses = [f.decoded for f in findings if f.category == "hex_or_contract" and len(f.decoded) == 42]
    selectors = [f.decoded for f in findings if f.category == "hex_or_contract" and len(f.decoded) == 10]
    out = {
        "attempted": False,
        "resolved": False,
        "rpc_used": "",
        "decoded_response": "",
        "decoded_response_layers": [],
        "c2_base_url": "",
        "exfil_endpoint": "",
        "payload_endpoint": "",
        "error": "",
    }
    if not rpc_urls or not addresses or not selectors:
        out["error"] = "missing rpc url / contract / selector indicators"
        return out

    body = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": addresses[0], "data": selectors[0]}, "latest"],
        "id": 1,
    }
    payload = json.dumps(body).encode("utf-8")
    out["attempted"] = True

    for rpc in rpc_urls:
        try:
            req = request.Request(
                rpc,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            result_hex = data.get("result", "")
            if not isinstance(result_hex, str) or not result_hex.startswith("0x"):
                continue
            decoded = decode_abi_string(result_hex)
            if not decoded:
                continue
            out["resolved"] = True
            out["rpc_used"] = rpc
            out["decoded_response"] = decoded
            layered = decode_encoded_fragments(decoded.strip())
            out["decoded_response_layers"] = [
                {"category": cat, "decoded": dec, "note": note} for cat, dec, note in layered
            ]
            c2_url = decoded.split("|", 1)[0].strip()
            out["c2_base_url"] = c2_url
            out["exfil_endpoint"] = f"{c2_url}/api/delivery/handler"
            out["payload_endpoint"] = f"{c2_url}/files/jar/module"
            return out
        except Exception as exc:
            out["error"] = str(exc)
            continue
    if not out["resolved"] and not out["error"]:
        out["error"] = "unable to decode runtime c2 response"
    return out


def scan_file(
    path: Path,
    root: Path,
    decrypt_profile: Optional[DecryptProfile] = None,
    include_all_literals: bool = False,
) -> List[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    decls = find_method_declarations(lines)
    starts = build_line_starts(text)
    rel = str(path.relative_to(root))
    rel_low = rel.replace("\\", "/").lower()
    is_vendor_lib = rel_low.startswith("com/sun/jna/") or rel_low.startswith("org/json/")

    findings: List[Finding] = []
    for m in LOAD_CALL_RE.finditer(text):
        try:
            d1 = parse_int_list(m.group("d1"))
            d2 = parse_int_list(m.group("d2"))
            k1 = int(m.group("k1"))
            k2 = int(m.group("k2"))
            decoded_raw = decode_obf(d1, d2, k1, k2)
        except Exception as exc:
            decoded_raw = f"<decode_error: {exc}>"

        line = offset_to_line(starts, m.start())
        function = nearest_method(decls, line)
        if decoded_raw.startswith("<decode_error:"):
            decoded = decoded_raw
            category = "encrypted_or_unresolved"
            note = "source=load_scanner signal=decode_error"
        elif _looks_meaningful_text(decoded_raw):
            decoded = decoded_raw
            category = classify(decoded)
            note = base64_note(decoded) if category == "base64_blob" else ""
        else:
            decoded = "<load(...) literal decode appears encrypted/unresolved>"
            category = "encrypted_or_unresolved"
            note = "source=load_scanner signal=low_confidence_decode"
        findings.append(
            Finding(
                file=rel,
                line=line,
                function=function,
                decoded=decoded,
                category=category,
                note=note,
            )
        )

    if not is_vendor_lib:
        if include_all_literals:
            findings.extend(scan_all_string_literals(text, rel, starts, decls))
        seen = set()
        literal_hits = 0
        for m in STRING_LITERAL_RE.finditer(text):
            if literal_hits >= 30:
                break
            raw_literal = m.group(1)
            for category, decoded_text, note in decode_encoded_literal(raw_literal):
                key = (category, decoded_text)
                if key in seen:
                    continue
                seen.add(key)
                line = offset_to_line(starts, m.start())
                function = nearest_method(decls, line)
                findings.append(
                    Finding(
                        file=rel,
                        line=line,
                        function=function,
                        decoded=decoded_text,
                        category=category,
                        note=note,
                    )
                )
                literal_hits += 1
                if literal_hits >= 30:
                    break
        findings.extend(scan_stringdecrypt_calls(text, rel, starts, decls, decrypt_profile))
        findings.extend(scan_string_literals(text, rel, starts, decls))
    return findings


def summarize_assessments(behaviors: List[BehaviorFinding]) -> dict:
    grouped = {"benign": [], "needs_review": [], "suspicious": []}
    for b in behaviors:
        if not b.behavior.startswith(ASSESSMENT_PREFIX):
            continue
        if b.behavior.startswith("assessment_benign_"):
            grouped["benign"].append(b)
        elif b.behavior.startswith("assessment_needs_review_"):
            grouped["needs_review"].append(b)
        elif b.behavior.startswith("assessment_suspicious_"):
            grouped["suspicious"].append(b)

    return {
        "counts": {k: len(v) for k, v in grouped.items()},
        "findings": {
            k: [x.__dict__ for x in sorted(v, key=lambda y: (y.file, y.line, y.behavior))]
            for k, v in grouped.items()
        },
    }


def behavior_severity(behavior: str) -> str:
    sev = BEHAVIOR_SEVERITY_MAP.get(behavior)
    if sev:
        return sev
    if behavior.startswith("assessment_suspicious_"):
        return "high"
    if behavior.startswith("assessment_needs_review_"):
        return "medium"
    if behavior.startswith("assessment_benign_"):
        return "low"
    return "info"


def summarize(findings: List[Finding], behaviors: List[BehaviorFinding], artifacts: List[ArtifactFinding]) -> dict:
    by_category: dict[str, int] = {}
    unique = set()
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
        unique.add(f.decoded)

    high_risk = [
        f
        for f in findings
        if f.category in {"url", "credential_or_identity_field", "dynamic_execution", "rpc_template", "path"}
    ]
    behavior_severity_counts = {k: 0 for k in ["critical", "high", "medium", "low", "info"]}
    for b in behaviors:
        behavior_severity_counts[behavior_severity(b.behavior)] += 1

    assessment_summary = summarize_assessments(behaviors)
    xor_decrypted_count = by_category.get("xor_decrypted_string", 0)
    decrypted_string_count = by_category.get("decrypted_string", 0)
    return {
        "total_findings": len(findings),
        "unique_decoded_strings": len(unique),
        "category_counts": dict(sorted(by_category.items(), key=lambda x: (-x[1], x[0]))),
        "xor_decrypted_count": xor_decrypted_count,
        "decrypted_string_count": decrypted_string_count,
        "high_risk_count": len(high_risk),
        "behavior_findings": len(behaviors),
        "high_risk_behavior_count": behavior_severity_counts["critical"] + behavior_severity_counts["high"],
        "behavior_severity_counts": behavior_severity_counts,
        "artifact_findings": len(artifacts),
        "assessment_counts": assessment_summary["counts"],
    }


def render_text(
    findings: List[Finding], behaviors: List[BehaviorFinding], artifacts: List[ArtifactFinding], summary: dict, runtime_c2: dict, target_metadata: dict
) -> str:
    out = []
    basic = target_metadata.get("basic_properties", {})
    jar_info = target_metadata.get("jar_info", {})
    bundle_info = target_metadata.get("bundle_info", {})

    out.append("== Basic Properties ==")
    out.append(f"Subject: {basic.get('subject', '')}")
    out.append(f"MD5: {basic.get('md5', '')}")
    out.append(f"SHA-1: {basic.get('sha1', '')}")
    out.append(f"SHA-256: {basic.get('sha256', '')}")
    if basic.get("vhash"):
        out.append(f"Vhash: {basic.get('vhash', '')}")
    if basic.get("ssdeep"):
        out.append(f"SSDEEP: {basic.get('ssdeep', '')}")
    if basic.get("tlsh"):
        out.append(f"TLSH: {basic.get('tlsh', '')}")
    out.append(f"File type: {basic.get('file_type', '')}")
    out.append(f"Compressed: {basic.get('compressed', '')}")
    out.append(f"Magic: {basic.get('magic', '')}")
    if basic.get("trid"):
        out.append(f"TrID: {basic.get('trid', '')}")
    if basic.get("magika"):
        out.append(f"Magika: {basic.get('magika', '')}")
    out.append(f"File size: {basic.get('file_size_text', '')} ({basic.get('file_size_bytes', 0)} bytes)")

    out.append("")
    out.append("== JAR Info ==")
    out.append("Manifest:")
    manifest = jar_info.get("manifest", "")
    out.append(manifest if manifest else "<not found>")
    am = jar_info.get("archive_metadata", {})
    out.append("Archive Metadata:")
    out.append(f"Contained Directories: {am.get('contained_directories', 0)}")
    out.append(f"Max. Directory Depth: {am.get('max_directory_depth', 0)}")
    out.append(f"Contained Files: {am.get('contained_files', 0)}")
    out.append(f"Latest Content Modification: {am.get('latest_content_modification', '')}")
    out.append(f"Earliest Content Modification: {am.get('earliest_content_modification', '')}")
    out.append("Contained Files By Type:")
    for k, v in am.get("contained_files_by_type", {}).items():
        out.append(f"- {k}: {v}")

    out.append("")
    out.append("== Bundle Info ==")
    out.append(f"Contained Files: {bundle_info.get('contained_files', 0)}")
    out.append(
        f"Uncompressed Size: {bundle_info.get('uncompressed_size_text', '')} ({bundle_info.get('uncompressed_size_bytes', 0)} bytes)"
    )
    out.append(f"Earliest Content Modification: {bundle_info.get('earliest_content_modification', '')}")
    out.append(f"Latest Content Modification: {bundle_info.get('latest_content_modification', '')}")
    out.append("Contained Files By Type:")
    for k, v in bundle_info.get("contained_files_by_type", {}).items():
        out.append(f"- {k}: {v}")
    out.append("Contained Files By Extension:")
    for k, v in bundle_info.get("contained_files_by_extension", {}).items():
        out.append(f"- {k}: {v}")

    out.append("")
    out.append("== Decode + String Findings ==")
    for f in sorted(findings, key=lambda x: (x.file, x.line, x.decoded)):
        note = f" [{f.note}]" if f.note else ""
        out.append(f"[{f.category}] {f.file}:{f.line} ({f.function}) -> {f.decoded}{note}")

    out.append("")
    out.append("== Assessment Findings ==")
    assessment = summarize_assessments(behaviors)
    for label in ["benign", "needs_review", "suspicious"]:
        entries = assessment["findings"][label]
        out.append(f"{label}: {len(entries)}")
        for item in entries:
            out.append(f"- [{item['behavior']}] {item['file']}:{item['line']} -> {item['evidence']}")

    out.append("")
    out.append("== Behavioral Findings ==")
    if behaviors:
        for b in sorted(behaviors, key=lambda x: (x.file, x.line, x.behavior)):
            sev = behavior_severity(b.behavior)
            out.append(f"[{sev}] [{b.behavior}] {b.file}:{b.line} -> {b.evidence}")
    else:
        out.append("None detected")

    out.append("")
    out.append("== Artifact Findings ==")
    if artifacts:
        for a in artifacts:
            size_text = str(a.size) if a.size >= 0 else "unknown"
            hash_text = a.sha256 if a.sha256 else "<unknown>"
            out.append(f"[{a.artifact_type}] {a.path} filename={a.filename} size={size_text} sha256={hash_text} -> {a.evidence}")
    else:
        out.append("None detected")

    out.append("")
    out.append("== Runtime C2 Resolution ==")
    if runtime_c2.get("attempted"):
        if runtime_c2.get("resolved"):
            out.append(f"Resolved: yes via {runtime_c2.get('rpc_used')}")
            out.append(f"C2 base URL: {runtime_c2.get('c2_base_url')}")
            out.append(f"Exfil endpoint: {runtime_c2.get('exfil_endpoint')}")
            out.append(f"Payload endpoint: {runtime_c2.get('payload_endpoint')}")
            out.append(f"Raw decoded response: {runtime_c2.get('decoded_response')}")
            layers = runtime_c2.get("decoded_response_layers") or []
            for idx, layer in enumerate(layers, start=1):
                note = f" [{layer.get('note')}]" if layer.get("note") else ""
                out.append(f"Layer {idx} ({layer.get('category')}): {layer.get('decoded')}{note}")
        else:
            out.append("Resolved: no")
            out.append(f"Error: {runtime_c2.get('error')}")
    else:
        out.append("Skipped")

    out.append("")
    out.append("== Summary ==")
    out.append(f"Total findings: {summary['total_findings']}")
    out.append(f"Unique decoded strings: {summary['unique_decoded_strings']}")
    out.append(f"XOR decrypted strings: {summary.get('xor_decrypted_count', 0)}")
    out.append(f"Other decrypted strings: {summary.get('decrypted_string_count', 0)}")
    out.append(f"High-risk findings: {summary['high_risk_count']}")
    out.append(f"Behavior findings: {summary['behavior_findings']}")
    out.append(f"High-risk behaviors: {summary['high_risk_behavior_count']}")
    out.append(f"Artifact findings: {summary['artifact_findings']}")
    out.append("Assessment counts:")
    for key, count in summary.get("assessment_counts", {}).items():
        out.append(f"- {key}: {count}")
    out.append("Category counts:")
    for cat, count in summary["category_counts"].items():
        out.append(f"- {cat}: {count}")
    out.append("Behavior severity counts:")
    for sev, count in summary["behavior_severity_counts"].items():
        out.append(f"- {sev}: {count}")
    return "\n".join(out)


def resolve_target(raw_target: str) -> Path:
    # On Windows shells users often pass "/" expecting "current folder".
    # Keep that behavior explicit to avoid scanning an entire drive root.
    if raw_target in {"/", "\\", "cwd"}:
        return Path.cwd().resolve()
    return Path(raw_target).resolve()


def progress(enabled: bool, message: str, console=None) -> None:
    if enabled:
        if RICH_AVAILABLE and console is not None:
            console.print(f"[progress] {message}", style="bold cyan", highlight=False)
        else:
            print(f"[progress] {message}", file=sys.stderr, flush=True)


def print_banner(console=None, to_stderr: bool = False) -> None:
    width = 120
    if RICH_AVAILABLE and console is not None:
        width = max(40, console.size.width)
    else:
        width = max(40, shutil.get_terminal_size((120, 20)).columns)
    centered = "\n".join(line.center(width) for line in BANNER.splitlines())
    if RICH_AVAILABLE and console is not None:
        console.print(centered, style="bold cyan", markup=False, highlight=False)
    else:
        stream = sys.stderr if to_stderr else sys.stdout
        print(centered, file=stream)


def render_rich(
    console,
    findings: List[Finding],
    behaviors: List[BehaviorFinding],
    artifacts: List[ArtifactFinding],
    summary: dict,
    runtime_c2: dict,
    target_metadata: dict,
) -> None:
    def short(s: str, n: int = 220) -> str:
        return s if len(s) <= n else s[: n - 1] + "…"

    assessment = summarize_assessments(behaviors)
    basic = target_metadata.get("basic_properties", {})
    jar_info = target_metadata.get("jar_info", {})
    bundle_info = target_metadata.get("bundle_info", {})

    console.print(Rule("[bold blue]Basic Properties"))
    bt = Table(show_header=False, box=box.SIMPLE)
    bt.add_row("Subject", str(basic.get("subject", "")))
    bt.add_row("MD5", str(basic.get("md5", "")))
    bt.add_row("SHA-1", str(basic.get("sha1", "")))
    bt.add_row("SHA-256", str(basic.get("sha256", "")))
    if basic.get("vhash"):
        bt.add_row("Vhash", str(basic.get("vhash", "")))
    if basic.get("ssdeep"):
        bt.add_row("SSDEEP", str(basic.get("ssdeep", "")))
    if basic.get("tlsh"):
        bt.add_row("TLSH", str(basic.get("tlsh", "")))
    bt.add_row("File type", str(basic.get("file_type", "")))
    bt.add_row("Compressed", str(basic.get("compressed", "")))
    bt.add_row("Magic", str(basic.get("magic", "")))
    if basic.get("trid"):
        bt.add_row("TrID", str(basic.get("trid", "")))
    if basic.get("magika"):
        bt.add_row("Magika", str(basic.get("magika", "")))
    bt.add_row("File size", f"{basic.get('file_size_text', '')} ({basic.get('file_size_bytes', 0)} bytes)")
    console.print(bt)

    console.print(Rule("[bold blue]JAR Info"))
    mt = Table(show_header=False, box=box.SIMPLE)
    mt.add_row("Manifest", short(jar_info.get("manifest", "") or "<not found>", 800))
    am = jar_info.get("archive_metadata", {})
    mt.add_row("Contained Directories", str(am.get("contained_directories", 0)))
    mt.add_row("Max. Directory Depth", str(am.get("max_directory_depth", 0)))
    mt.add_row("Contained Files", str(am.get("contained_files", 0)))
    mt.add_row("Latest Content Modification", str(am.get("latest_content_modification", "")))
    mt.add_row("Earliest Content Modification", str(am.get("earliest_content_modification", "")))
    console.print(mt)
    am_types = am.get("contained_files_by_type", {})
    if am_types:
        amt = Table(title="Archive Types", show_header=True)
        amt.add_column("Type")
        amt.add_column("Count", justify="right")
        for k, v in am_types.items():
            amt.add_row(str(k), str(v))
        console.print(amt)

    console.print(Rule("[bold blue]Bundle Info"))
    bmt = Table(show_header=False, box=box.SIMPLE)
    bmt.add_row("Contained Files", str(bundle_info.get("contained_files", 0)))
    bmt.add_row(
        "Uncompressed Size",
        f"{bundle_info.get('uncompressed_size_text', '')} ({bundle_info.get('uncompressed_size_bytes', 0)} bytes)",
    )
    bmt.add_row("Earliest Content Modification", str(bundle_info.get("earliest_content_modification", "")))
    bmt.add_row("Latest Content Modification", str(bundle_info.get("latest_content_modification", "")))
    console.print(bmt)
    b_types = bundle_info.get("contained_files_by_type", {})
    if b_types:
        btt = Table(title="Bundle Types", show_header=True)
        btt.add_column("Type")
        btt.add_column("Count", justify="right")
        for k, v in b_types.items():
            btt.add_row(str(k), str(v))
        console.print(btt)
    b_ext = bundle_info.get("contained_files_by_extension", {})
    if b_ext:
        bet = Table(title="Bundle Extensions", show_header=True)
        bet.add_column("Extension")
        bet.add_column("Count", justify="right")
        for k, v in b_ext.items():
            bet.add_row(str(k), str(v))
        console.print(bet)

    console.print(Rule("[bold blue]Decode + String Findings"))
    if findings:
        t = Table(show_lines=False, expand=True)
        t.add_column("Category", style="magenta", max_width=22, no_wrap=True, overflow="ellipsis")
        t.add_column("Location", style="cyan", overflow="fold")
        t.add_column("Function", style="green")
        t.add_column("Decoded", style="white", overflow="fold")
        for f in sorted(findings, key=lambda x: (x.file, x.line, x.decoded)):
            decoded = f.decoded if not f.note else f"{f.decoded} [{f.note}]"
            t.add_row(f.category, f"{f.file}:{f.line}", f.function, decoded)
        console.print(t)
    else:
        console.print("[dim]None detected[/dim]")

    console.print(Rule("[bold blue]Assessment Findings"))
    at = Table(show_lines=False, box=box.SIMPLE, expand=True)
    at.add_column("Category", style="green")
    at.add_column("Location", style="cyan", overflow="fold")
    at.add_column("Assessment", style="yellow")
    at.add_column("Evidence", style="white")
    has_assessment_rows = False
    for label in ["benign", "needs_review", "suspicious"]:
        for item in assessment["findings"][label]:
            has_assessment_rows = True
            at.add_row(label, f"{item['file']}:{item['line']}", item["behavior"], short(item["evidence"]))
    if has_assessment_rows:
        console.print(at)
    else:
        console.print("[dim]None detected[/dim]")

    console.print(Rule("[bold blue]Behavioral Findings"))
    if behaviors:
        t = Table(show_lines=False, box=box.SIMPLE, expand=True)
        t.add_column("Risk", style="red")
        t.add_column("Behavior", style="yellow")
        t.add_column("Location", style="cyan", overflow="fold")
        t.add_column("Evidence", style="white", overflow="fold")
        for b in sorted(behaviors, key=lambda x: (x.file, x.line, x.behavior)):
            t.add_row(behavior_severity(b.behavior), b.behavior, f"{b.file}:{b.line}", short(b.evidence))
        console.print(t)
    else:
        console.print("[dim]None detected[/dim]")

    console.print(Rule("[bold blue]Artifact Findings"))
    if artifacts:
        t = Table(show_lines=False, box=box.SIMPLE, expand=True)
        t.add_column("Type", style="red")
        t.add_column("Path", style="cyan")
        t.add_column("Filename", style="green")
        t.add_column("Size", justify="right")
        t.add_column("SHA256", style="white")
        t.add_column("Evidence", style="white", overflow="fold")
        for a in artifacts:
            size_text = str(a.size) if a.size >= 0 else "unknown"
            hash_text = a.sha256 if a.sha256 else "<unknown>"
            t.add_row(a.artifact_type, a.path, a.filename, size_text, short(hash_text, 18), short(a.evidence))
        console.print(t)
    else:
        console.print("[dim]None detected[/dim]")

    console.print(Rule("[bold blue]Runtime C2 Resolution"))
    if runtime_c2.get("attempted"):
        if runtime_c2.get("resolved"):
            console.print(f"[green]Resolved:[/green] yes via {runtime_c2.get('rpc_used')}")
            console.print(f"C2 base URL: {runtime_c2.get('c2_base_url')}")
            console.print(f"Exfil endpoint: {runtime_c2.get('exfil_endpoint')}")
            console.print(f"Payload endpoint: {runtime_c2.get('payload_endpoint')}")
            console.print(f"Raw decoded response: {runtime_c2.get('decoded_response')}")
            layers = runtime_c2.get("decoded_response_layers") or []
            for idx, layer in enumerate(layers, start=1):
                note = f" note={layer.get('note')}" if layer.get("note") else ""
                console.print(f"Layer {idx} ({layer.get('category')}): {layer.get('decoded')}{note}", markup=False)
        else:
            console.print("[red]Resolved:[/red] no")
            console.print(f"Error: {runtime_c2.get('error')}")
    else:
        console.print("[dim]Skipped[/dim]")

    console.print(Rule("[bold blue]Summary"))
    s = Table(show_header=False, box=None)
    s.add_row("Total findings", str(summary["total_findings"]))
    s.add_row("Unique decoded strings", str(summary["unique_decoded_strings"]))
    s.add_row("XOR decrypted strings", str(summary.get("xor_decrypted_count", 0)))
    s.add_row("Other decrypted strings", str(summary.get("decrypted_string_count", 0)))
    s.add_row("High-risk findings", str(summary["high_risk_count"]))
    s.add_row("Behavior findings", str(summary["behavior_findings"]))
    s.add_row("High-risk behaviors", str(summary["high_risk_behavior_count"]))
    s.add_row("Artifact findings", str(summary["artifact_findings"]))
    for k in ["benign", "needs_review", "suspicious"]:
        s.add_row(f"Assessment {k}", str(summary.get("assessment_counts", {}).get(k, 0)))
    console.print(s)
    if summary["category_counts"]:
        c = Table(title="Category Counts", show_header=True)
        c.add_column("Category", style="magenta")
        c.add_column("Count", justify="right")
        for cat, count in summary["category_counts"].items():
            c.add_row(cat, str(count))
        console.print(c)
    if summary["behavior_severity_counts"]:
        b = Table(title="Behavior Severity Counts", show_header=True)
        b.add_column("Severity", style="red")
        b.add_column("Count", justify="right")
        for sev, count in summary["behavior_severity_counts"].items():
            b.add_row(sev, str(count))
        console.print(b)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Java Triage: recursively parse Java files, decode load(new int[]{...}) obfuscation, scan suspicious strings, and summarize findings."
    )
    p.add_argument("target", nargs="?", default=".", help="Folder to scan (default: current directory)")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    p.add_argument("--out", help="Write output to file")
    p.add_argument("--no-progress", action="store_true", help="Disable progress messages")
    p.add_argument("--no-network", action="store_true", help="Disable runtime C2 resolution over network")
    p.add_argument(
        "--rich-width",
        type=int,
        default=120,
        help="Preferred Rich console width for final report/progress rendering",
    )
    p.add_argument(
        "--decrypt-codebase-in-place",
        action="store_true",
        help="Rewrite StringDecrypt.decrypt(new byte[]{...}) calls in the target tree with decoded string literals",
    )
    p.add_argument(
        "--decrypt-codebase-out",
        help="Copy target tree to this directory, rewrite encrypted StringDecrypt byte-array calls there, then scan that output tree",
    )
    p.add_argument(
        "--no-rescan-after-decrypt",
        action="store_true",
        help="When decrypt mode is used, perform rewrite only and skip the follow-up triage scan",
    )
    p.add_argument(
        "--no-auto-decrypt",
        action="store_true",
        help="Disable opportunistic default auto-decrypt behavior (threshold-based probe + copy/rewrite)",
    )
    args = p.parse_args()

    root = resolve_target(args.target)
    show_progress = not args.no_progress
    pref_width = max(80, int(args.rich_width))
    progress_console = Console(stderr=False, width=pref_width) if RICH_AVAILABLE else None
    report_console = Console(width=pref_width) if RICH_AVAILABLE else None
    rich_progress_mode = bool(RICH_AVAILABLE and progress_console is not None and show_progress)
    phase_logs = show_progress and not rich_progress_mode
    progress(phase_logs, f"target resolved to: {root}", progress_console)

    if not root.exists():
        print(f"error: target does not exist: {root}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"error: target is not a directory: {root}", file=sys.stderr)
        return 2

    if not args.json:
        if rich_progress_mode:
            print_banner(progress_console, to_stderr=False)
        else:
            print_banner(None, to_stderr=True)

    if args.decrypt_codebase_in_place and args.decrypt_codebase_out:
        print("error: use only one of --decrypt-codebase-in-place or --decrypt-codebase-out", file=sys.stderr)
        return 2

    user_decrypt_mode = bool(args.decrypt_codebase_in_place or args.decrypt_codebase_out)
    auto_decrypt_requested = (not user_decrypt_mode) and (not args.no_auto_decrypt)
    auto_decrypt_probe = None
    auto_decrypt_mode = False
    if auto_decrypt_requested:
        progress(phase_logs, "evaluating auto-decrypt need", progress_console)
        auto_decrypt_probe = assess_auto_decrypt_need(root)
        if auto_decrypt_probe["enabled"]:
            auto_decrypt_mode = True
            progress(
                phase_logs,
                "auto-decrypt enabled: "
                f"java_files={auto_decrypt_probe['java_files']} "
                f"obfuscated_calls={auto_decrypt_probe['total_obfuscated_calls']} "
                f"files_with_calls={auto_decrypt_probe['files_with_calls']} "
                f"ratio={auto_decrypt_probe['files_with_calls_ratio']:.2%}",
                progress_console,
            )
        else:
            progress(
                phase_logs,
                "auto-decrypt skipped: "
                f"reason={auto_decrypt_probe['reason']} "
                f"java_files={auto_decrypt_probe['java_files']} "
                f"obfuscated_calls={auto_decrypt_probe['total_obfuscated_calls']} "
                f"files_with_calls={auto_decrypt_probe['files_with_calls']} "
                f"ratio={auto_decrypt_probe['files_with_calls_ratio']:.2%}",
                progress_console,
            )
    decrypt_mode = user_decrypt_mode or auto_decrypt_mode
    scan_root = root
    deobf_stats = None

    if args.decrypt_codebase_out:
        out_root = Path(args.decrypt_codebase_out).resolve()
        if out_root.exists():
            print(f"error: decrypt output already exists: {out_root}", file=sys.stderr)
            return 2
        progress(phase_logs, f"copying target to decrypt output: {out_root}", progress_console)
        shutil.copytree(root, out_root)
        scan_root = out_root
    elif auto_decrypt_mode:
        base_out = Path.cwd() / f"{root.name}_deobfuscated"
        out_root = base_out
        if out_root.exists():
            idx = 2
            while True:
                candidate = Path.cwd() / f"{root.name}_deobfuscated_{idx}"
                if not candidate.exists():
                    out_root = candidate
                    break
                idx += 1
        progress(phase_logs, f"default auto-decrypt: copying target to {out_root}", progress_console)
        shutil.copytree(root, out_root)
        scan_root = out_root

    decrypt_profile = None
    if decrypt_mode:
        progress(phase_logs, "building StringDecrypt profile", progress_console)
        decrypt_profile = build_decrypt_profile(scan_root)
        progress(phase_logs, "rewriting encrypted StringDecrypt byte-array calls", progress_console)
        deobf_stats = deobfuscate_codebase(scan_root, decrypt_profile, show_progress, progress_console)
        files_total = max(1, int(deobf_stats.get("java_files", 0)))
        files_ratio = float(deobf_stats.get("files_with_calls", 0)) / files_total
        total_obf_calls = int(deobf_stats.get("calls_seen", 0)) + int(deobf_stats.get("load_calls_seen", 0))
        majorly_encrypted = bool(
            total_obf_calls >= MAJOR_ENCRYPTED_MIN_CALLS
            or (
                int(deobf_stats.get("files_with_calls", 0)) >= MAJOR_ENCRYPTED_MIN_FILES_WITH_CALLS
                and files_ratio >= MAJOR_ENCRYPTED_MIN_FILE_RATIO
            )
        )
        deobf_stats["majorly_encrypted"] = majorly_encrypted
        deobf_stats["scan_mode"] = "post_decryption_only"
        deobf_stats["auto_decrypt_default"] = auto_decrypt_requested
        deobf_stats["auto_decrypt_selected"] = auto_decrypt_mode
        if auto_decrypt_probe is not None:
            deobf_stats["auto_decrypt_probe"] = auto_decrypt_probe
        deobf_stats["source_root"] = str(root)
        deobf_stats["scan_root"] = str(scan_root)
        progress(
            phase_logs,
            f"deobf complete: stringdecrypt_calls={deobf_stats.get('calls_seen', 0)} stringdecrypt_replaced={deobf_stats.get('replaced', 0)} "
            f"stringdecrypt_unresolved={deobf_stats.get('unresolved', 0)} load_calls={deobf_stats.get('load_calls_seen', 0)} "
            f"load_replaced={deobf_stats.get('load_replaced', 0)} load_unresolved={deobf_stats.get('load_unresolved', 0)}",
            progress_console,
        )
        progress(phase_logs, "pre-decryption scan skipped; scanning post-decryption tree", progress_console)
        if args.no_rescan_after_decrypt:
            if args.json:
                payload = {"root": str(scan_root), "deobfuscation": deobf_stats}
                out_text = json.dumps(payload, indent=2)
            else:
                out_text = (
                    "== Deobfuscation ==\n"
                    f"Root: {scan_root}\n"
                    f"Java files scanned: {deobf_stats.get('java_files', 0)}\n"
                    f"StringDecrypt calls found: {deobf_stats.get('calls_seen', 0)}\n"
                    f"StringDecrypt calls replaced: {deobf_stats.get('replaced', 0)}\n"
                    f"StringDecrypt calls unresolved: {deobf_stats.get('unresolved', 0)}\n"
                    f"load(...) calls found: {deobf_stats.get('load_calls_seen', 0)}\n"
                    f"load(...) calls replaced: {deobf_stats.get('load_replaced', 0)}\n"
                    f"load(...) calls unresolved: {deobf_stats.get('load_unresolved', 0)}\n"
                    f"Files changed: {deobf_stats.get('files_changed', 0)}"
                )
            if args.out:
                Path(args.out).write_text(out_text, encoding="utf-8")
            else:
                print(out_text)
            progress(show_progress, "done", progress_console)
            return 0

    if decrypt_profile is None:
        decrypt_profile = build_decrypt_profile(scan_root)

    progress(phase_logs, "collecting target metadata", progress_console)
    target_metadata = collect_target_metadata(scan_root)
    progress(phase_logs, "discovering Java files", progress_console)
    files = list(iter_java_files(scan_root))
    progress(phase_logs, f"found {len(files)} Java file(s)", progress_console)

    all_findings: List[Finding] = []
    behavior_findings: List[BehaviorFinding] = []
    if rich_progress_mode:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]Scanning Java files"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=progress_console,
            transient=False,
        ) as prog:
            task = prog.add_task("scan", total=len(files))
            for file_path in files:
                all_findings.extend(scan_file(file_path, scan_root, decrypt_profile, include_all_literals=decrypt_mode))
                behavior_findings.extend(scan_behavior(file_path, scan_root))
                prog.advance(task)
    else:
        for idx, file_path in enumerate(files, start=1):
            if show_progress and (idx == 1 or idx % 50 == 0 or idx == len(files)):
                progress(show_progress, f"scanning file {idx}/{len(files)}", progress_console)
            all_findings.extend(scan_file(file_path, scan_root, decrypt_profile, include_all_literals=decrypt_mode))
            behavior_findings.extend(scan_behavior(file_path, scan_root))

    behavior_findings.extend(discover_structural_behaviors(scan_root))
    behavior_findings = sorted(
        {(b.file, b.line, b.behavior, b.evidence): b for b in behavior_findings}.values(),
        key=lambda x: (x.file, x.line, x.behavior),
    )

    progress(phase_logs, f"collected {len(all_findings)} decode/string finding(s)", progress_console)
    progress(phase_logs, f"detected {len(behavior_findings)} behavior indicator(s)", progress_console)
    progress(phase_logs, "discovering suspicious artifacts", progress_console)
    artifact_findings = discover_artifacts(scan_root)
    progress(phase_logs, f"detected {len(artifact_findings)} artifact indicator(s)", progress_console)
    runtime_c2 = {"attempted": False, "resolved": False}
    if not args.no_network:
        progress(phase_logs, "resolving runtime C2 from on-chain config", progress_console)
        runtime_c2 = resolve_runtime_c2(all_findings)
        if runtime_c2.get("resolved"):
            progress(phase_logs, f"runtime C2 resolved: {runtime_c2.get('c2_base_url')}", progress_console)
        else:
            progress(phase_logs, f"runtime C2 unresolved: {runtime_c2.get('error', 'unknown error')}", progress_console)

    progress(phase_logs, "building summary", progress_console)

    summary = summarize(all_findings, behavior_findings, artifact_findings)
    if deobf_stats:
        summary["xor_decrypted_count"] = int(deobf_stats.get("stringdecrypt_xor_replaced", 0))
        summary["decrypted_string_count"] = int(
            deobf_stats.get("stringdecrypt_other_replaced", 0)
        ) + int(deobf_stats.get("load_replaced", 0))

    if args.json:
        payload = {
            "root": str(scan_root),
            "target_metadata": target_metadata,
            "scan_mode": "post_decryption_only" if decrypt_mode else "standard",
            "deobfuscation": deobf_stats if deobf_stats else {},
            "summary": summary,
            "assessment_summary": summarize_assessments(behavior_findings),
            "runtime_c2": runtime_c2,
            "findings": [f.__dict__ for f in sorted(all_findings, key=lambda x: (x.file, x.line, x.decoded))],
            "behavior_findings": [
                {**b.__dict__, "severity": behavior_severity(b.behavior)}
                for b in sorted(behavior_findings, key=lambda x: (x.file, x.line, x.behavior))
            ],
            "artifact_findings": [a.__dict__ for a in artifact_findings],
        }
        output = json.dumps(payload, indent=2)
    else:
        width = max(40, shutil.get_terminal_size((120, 20)).columns)
        centered_banner = "\n".join(line.center(width) for line in BANNER.splitlines())
        output = render_text(all_findings, behavior_findings, artifact_findings, summary, runtime_c2, target_metadata)
        output = f"{centered_banner}\n\n{output}"

    if args.out:
        progress(phase_logs, f"writing output to {Path(args.out)}", progress_console)
        Path(args.out).write_text(output, encoding="utf-8")
        progress(show_progress, "done", progress_console)
    else:
        progress(phase_logs, "printing output", progress_console)
        if RICH_AVAILABLE and report_console is not None and rich_progress_mode:
            # Clear scan-phase output so the final report is shown on a clean screen.
            report_console.clear()
            if os.name == "nt":
                os.system("cls")
        if args.json or not RICH_AVAILABLE:
            print(output)
        else:
            print_banner(report_console, to_stderr=False)
            render_rich(report_console, all_findings, behavior_findings, artifact_findings, summary, runtime_c2, target_metadata)
        progress(show_progress, "done", progress_console)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

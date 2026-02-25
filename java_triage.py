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
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List
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
DISCORD_SNOWFLAKE_RE = re.compile(r"^\d{17,20}$")
DISCORD_SNOWFLAKE_ANY_RE = re.compile(r"\b\d{17,20}\b")
DISCORD_ID_CONTEXT_RE = re.compile(
    r"(?:\bguild(?:_id)?\b|\bserver(?:_id)?\b|\bchannel(?:_id)?\b|\buser(?:_id)?\b|\brole(?:_id)?\b|\bapplication(?:_id)?\b|\bdiscord\b)",
    re.IGNORECASE,
)
HTTP_HOST_RE = re.compile(r'https?://([^/:\s"\'<>]+)', re.IGNORECASE)
ASSESSMENT_PREFIX = "assessment_"

MINECRAFT_AUTH_HOSTS = {
    "login.live.com",
    "auth.xboxlive.com",
    "user.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "api.minecraftservices.com",
}


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


def parse_int_list(raw: str) -> List[int]:
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return [int(p) for p in parts]


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
    interesting = any(k in low for k in ["http", "json", "token", "cmd", "powershell", "defender", "discord", "api"])
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

        if (not discord_kind) and generic_hits >= max_hits:
            continue

        if discord_kind:
            category = "discord_indicator"
            signal = discord_kind

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
        extra_note = f" {discord_note}" if discord_note else ""
        key = (line, decoded, category, signal, discord_note)
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
        if not discord_kind:
            generic_hits += 1
    return out


def iter_java_files(root: Path) -> Iterable[Path]:
    yield from root.rglob("*.java")


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

    if "HttpClient.newHttpClient()" in text and "BodyHandlers.ofByteArray()" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "BodyHandlers.ofByteArray()"),
                behavior="binary_payload_download",
                evidence="Performs HTTP GET and downloads raw bytes",
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

    low = text.lower()
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


def scan_file(path: Path, root: Path) -> List[Finding]:
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
            decoded = decode_obf(d1, d2, k1, k2)
        except Exception as exc:
            decoded = f"<decode_error: {exc}>"

        line = offset_to_line(starts, m.start())
        function = nearest_method(decls, line)
        category = classify(decoded)
        note = base64_note(decoded) if category == "base64_blob" else ""
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

    assessment_summary = summarize_assessments(behaviors)
    return {
        "total_findings": len(findings),
        "unique_decoded_strings": len(unique),
        "category_counts": dict(sorted(by_category.items(), key=lambda x: (-x[1], x[0]))),
        "high_risk_count": len(high_risk),
        "behavior_findings": len(behaviors),
        "artifact_findings": len(artifacts),
        "assessment_counts": assessment_summary["counts"],
    }


def render_text(
    findings: List[Finding], behaviors: List[BehaviorFinding], artifacts: List[ArtifactFinding], summary: dict, runtime_c2: dict
) -> str:
    out = []
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
            out.append(f"[{b.behavior}] {b.file}:{b.line} -> {b.evidence}")
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
    out.append(f"High-risk findings: {summary['high_risk_count']}")
    out.append(f"Behavior findings: {summary['behavior_findings']}")
    out.append(f"Artifact findings: {summary['artifact_findings']}")
    out.append("Assessment counts:")
    for key, count in summary.get("assessment_counts", {}).items():
        out.append(f"- {key}: {count}")
    out.append("Category counts:")
    for cat, count in summary["category_counts"].items():
        out.append(f"- {cat}: {count}")
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
) -> None:
    def short(s: str, n: int = 220) -> str:
        return s if len(s) <= n else s[: n - 1] + "…"

    assessment = summarize_assessments(behaviors)

    console.print(Rule("[bold blue]Decode + String Findings"))
    if findings:
        t = Table(show_lines=False, expand=True)
        t.add_column("Category", style="magenta")
        t.add_column("Location", style="cyan")
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
    at.add_column("Location", style="cyan")
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
        t.add_column("Behavior", style="yellow")
        t.add_column("Location", style="cyan")
        t.add_column("Evidence", style="white", overflow="fold")
        for b in sorted(behaviors, key=lambda x: (x.file, x.line, x.behavior)):
            t.add_row(b.behavior, f"{b.file}:{b.line}", short(b.evidence))
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
    s.add_row("High-risk findings", str(summary["high_risk_count"]))
    s.add_row("Behavior findings", str(summary["behavior_findings"]))
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
    args = p.parse_args()

    root = resolve_target(args.target)
    show_progress = not args.no_progress
    pref_width = max(80, int(args.rich_width))
    progress_console = Console(stderr=False, width=pref_width) if RICH_AVAILABLE else None
    report_console = Console(width=pref_width) if RICH_AVAILABLE else None
    rich_progress_mode = bool(RICH_AVAILABLE and progress_console is not None and show_progress)
    phase_logs = show_progress and not rich_progress_mode
    progress(show_progress, f"target resolved to: {root}", progress_console)

    if not root.exists():
        print(f"error: target does not exist: {root}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"error: target is not a directory: {root}", file=sys.stderr)
        return 2

    progress(phase_logs, "discovering Java files", progress_console)
    if not args.json:
        if rich_progress_mode:
            print_banner(progress_console, to_stderr=False)
        else:
            print_banner(None, to_stderr=True)
    files = list(iter_java_files(root))
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
            transient=True,
        ) as prog:
            task = prog.add_task("scan", total=len(files))
            for file_path in files:
                all_findings.extend(scan_file(file_path, root))
                behavior_findings.extend(scan_behavior(file_path, root))
                prog.advance(task)
    else:
        for idx, file_path in enumerate(files, start=1):
            if show_progress and (idx == 1 or idx % 50 == 0 or idx == len(files)):
                progress(show_progress, f"scanning file {idx}/{len(files)}", progress_console)
            all_findings.extend(scan_file(file_path, root))
            behavior_findings.extend(scan_behavior(file_path, root))

    behavior_findings.extend(discover_structural_behaviors(root))
    behavior_findings = sorted(
        {(b.file, b.line, b.behavior, b.evidence): b for b in behavior_findings}.values(),
        key=lambda x: (x.file, x.line, x.behavior),
    )

    progress(phase_logs, f"collected {len(all_findings)} decode/string finding(s)", progress_console)
    progress(phase_logs, f"detected {len(behavior_findings)} behavior indicator(s)", progress_console)
    progress(phase_logs, "discovering suspicious artifacts", progress_console)
    artifact_findings = discover_artifacts(root)
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

    if args.json:
        payload = {
            "root": str(root),
            "summary": summary,
            "assessment_summary": summarize_assessments(behavior_findings),
            "runtime_c2": runtime_c2,
            "findings": [f.__dict__ for f in sorted(all_findings, key=lambda x: (x.file, x.line, x.decoded))],
            "behavior_findings": [b.__dict__ for b in sorted(behavior_findings, key=lambda x: (x.file, x.line, x.behavior))],
            "artifact_findings": [a.__dict__ for a in artifact_findings],
        }
        output = json.dumps(payload, indent=2)
    else:
        width = max(40, shutil.get_terminal_size((120, 20)).columns)
        centered_banner = "\n".join(line.center(width) for line in BANNER.splitlines())
        output = render_text(all_findings, behavior_findings, artifact_findings, summary, runtime_c2)
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
            render_rich(report_console, all_findings, behavior_findings, artifact_findings, summary, runtime_c2)
        progress(show_progress, "done", progress_console)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

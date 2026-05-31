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

BANNER = r"""                                                 
     ██  █████  ██    ██  █████  ████████ ██████  ██  █████   ██████  ███████ 
     ██ ██   ██ ██    ██ ██   ██    ██    ██   ██ ██ ██   ██ ██       ██      
     ██ ███████ ██    ██ ███████    ██    ██████  ██ ███████ ██   ███ █████   
██   ██ ██   ██  ██  ██  ██   ██    ██    ██   ██ ██ ██   ██ ██    ██ ██      
 █████  ██   ██   ████   ██   ██    ██    ██   ██ ██ ██   ██  ██████  ███████ 
https://github.com/cev-api/Java-Triage

"""


LOAD_CALL_RE = re.compile(
    r"(?:\b\w+\.)?load\(\s*new\s+int\[\]\s*\{(?P<d1>.*?)\}\s*,\s*new\s+int\[\]\s*\{(?P<d2>.*?)\}\s*,\s*(?P<k1>\d+)\s*,\s*(?P<k2>\d+)\s*\)",
    re.DOTALL,
)
# Match standard Java string literals and avoid crossing line boundaries.
STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\\r\n]){16,})"')
STRING_ANY_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\\r\n]){4,})"')
STRING_SHORT_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\\r\n]){1,64})"')
SPLIT_STRING_ARRAY_RE = re.compile(
    r"String\[\]\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*new\s+String\[\]\s*\{(?P<body>.*?)\};",
    re.DOTALL,
)
STRING_DECRYPT_CALL_RE = re.compile(
    r"(?P<call>(?:\b[\w$.]*StringDecrypt\s*\.\s*)?decrypt\s*\(\s*new\s+byte\s*\[\s*\]\s*\{(?P<bytes>.*?)\}\s*\))",
    re.DOTALL,
)
NEW_BYTE_ARRAY_LITERAL_RE = re.compile(r"new\s+byte\s*\[\s*\]\s*\{(?P<body>.*?)\}", re.DOTALL)
NEW_CHAR_ARRAY_LITERAL_RE = re.compile(r"new\s+char\s*\[\s*\]\s*\{(?P<body>.*?)\}", re.DOTALL)
STRINGBUILDER_REVERSE_RE = re.compile(
    r'new\s+StringBuilder\(\s*"(?P<lit>(?:\\.|[^"\\\r\n]){4,})"\s*\)\.reverse\(\)\.toString\(\)',
    re.DOTALL,
)
JAVA_BYTE_TOKEN_RE = re.compile(r"(?:\(\s*byte\s*\)\s*)?(-?\d+)")
JAVA_CHAR_TOKEN_RE = re.compile(r"(?:\(\s*char\s*\)\s*)?(-?\d+)")

METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected|static|final|synchronized|native|abstract|strictfp|default|\s)+"
    r"(?:<[\w\s,? extends super]+>\s*)?"
    r"[\w$\[\]<>.,?\s]+\s+([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^{]+)?\{\s*$"
)

URL_RE = re.compile(r"^https?://", re.IGNORECASE)
HEX_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{8,}$")
ETH_SELECTOR_RE = re.compile(r"^0x[a-fA-F0-9]{8}$")
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
    "dqw4w9wgxcq",
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
DISCORD_ENCRYPTED_TOKEN_MARKER_RE = re.compile(r"dQw4w9WgXcQ:(?P<payload>[A-Za-z0-9+/=]+)")
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
    "assessment_suspicious_remote_mod_dropper": "high",
    "assessment_suspicious_embedded_mod_dropper": "high",
    "assessment_suspicious_discord_token_stealer": "high",
    "assessment_suspicious_multi_credential_infostealer": "critical",
    "assessment_needs_review_remote_mod_downloader": "medium",
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
    "credential_handoff_to_dynamic_stage": "critical",
    "staged_remote_jar_execution": "critical",
    "blockchain_backed_c2_bootstrap": "high",
    "possible_access_token_exfiltration": "high",
    "remote_urlclassloader_usage": "high",
    "possible_minecraft_session_file_exfiltration": "high",
    "possible_minecraft_identity_exfiltration": "high",
    "minecraft_mod_folder_remote_dropper": "high",
    "minecraft_mod_folder_embedded_payload_dropper": "high",
    "embedded_resource_encoded_archive_dropper": "high",
    "discord_leveldb_token_theft": "high",
    "discord_token_validation_api": "high",
    "discord_token_exfiltration_bundle": "high",
    "browser_password_database_theft": "high",
    "browser_cookie_database_theft": "high",
    "browser_history_database_collection": "medium",
    "screenshot_capture_collection": "high",
    "chromium_masterkey_decryption_chain": "high",
    "runtime_sqlite_driver_download_and_load": "high",
    "credential_exfiltration_endpoint": "high",
    "decompiler_failure_or_heavy_obfuscation": "high",
    "class_constant_pool_only_scan": "medium",
    "extreme_archive_structure_obfuscation": "high",
    "http_urlconnection_binary_download": "medium",
    "obfuscated_url_reconstruction": "medium",
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
    "minecraft_session_id_access": "medium",
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
    "proof_token_source_to_network_sink": "high",
    "proof_raw_token_logging": "high",
    "proof_reachable_command_token_disclosure_chain": "critical",
    "exposed_local_websocket_command_bridge": "high",
    "capability_token_access": "medium",
    "audio_capture_capability": "high",
    "audio_playback_capability": "low",
}

MINECRAFT_AUTH_HOSTS = {
    "login.live.com",
    "auth.xboxlive.com",
    "user.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "api.minecraftservices.com",
}
VENDOR_HOST_ALLOWLIST = {
    "login.live.com",
    "login.microsoftonline.com",
    "device.auth.xboxlive.com",
    "user.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "api.minecraftservices.com",
    "pc.realms.minecraft.net",
    "pocket.realms.minecraft.net",
    "minecraft.playfabapi.com",
    "api.keygen.sh",
    "discord.com",
    "discordapp.com",
    "github.com",
    "api.github.com",
}
KNOWN_LIBRARY_PREFIXES = {
    "raphimc_minecraftauth": ["net/raphimc/minecraftauth/"],
    "discord_rpc": ["net/arikia/dev/drpc/"],
    "lenni_httpclient": ["net/lenni0451/commons/httpclient/"],
    "lenni_gson": ["net/lenni0451/commons/gson/"],
    "gson": ["com/google/gson/"],
    "java_websocket": ["org/java_websocket/"],
    "slf4j": ["org/slf4j/"],
    "fabric": ["net/fabricmc/", "fabric/"],
    "org_json": ["org/json/"],
    "jna": ["com/sun/jna/"],
}


def _is_known_library_relpath(rel_path: str) -> bool:
    rel_low = str(rel_path or "").replace("\\", "/").lower().lstrip("./")
    for prefixes in KNOWN_LIBRARY_PREFIXES.values():
        if any(rel_low.startswith(prefix.lower()) for prefix in prefixes):
            return True
    return False
RAW_STRING_PATTERNS = [
    ("erawaggin", "Reversed 'niggaware' string", 50),
    ("erawoobmab", "Reversed 'bambooware' string", 50),
    ("DirectPlayerDetector", "Niggaware thread name", 25),
    ("performance-tweaks", "Niggaware mod ID", 25),
    ("Add-MpPreference", "Defender exclusion command", 30),
    ("dev.github.Main", "Silentnet stage2 entry", 30),
    ("Mod init state: M", "Weedhack debug string", 30),
    ("Resource state: S", "Weedhack debug string", 30),
    ("method_1674", "MC accessToken accessor", 20),
    ("method_1675", "MC sessionId accessor", 20),
    ("method_38740", "MC clientId accessor", 15),
    ("method_38741", "MC xuid accessor", 15),
    ("method_35718", "MC accountType accessor", 15),
    ("method_1676", "MC username accessor", 20),
    ("method_1673", "MC UUID accessor", 20),
    ("method_44717", "MC UUID accessor", 20),
    ("func_110432_I", "Legacy MCP getSession accessor", 20),
    ("func_111286_b", "Legacy MCP getSessionID accessor", 20),
    ("func_148254_d", "Legacy MCP raw token accessor", 20),
    ("field_1983", "MC accessToken field", 20),
    ("field_148258_c", "Legacy MCP token field", 20),
    ("field_34961", "MC clientId field", 15),
    ("field_34960", "MC xuid field", 15),
    ("field_1984", "MC accountType field", 15),
    ("field_71449_j", "Legacy MCP Minecraft.session field", 15),
    ("field_1726", "Intermediary MinecraftClient.session field", 15),
    ("net.minecraft.client.User", "Mojmap/NeoForge User class", 15),
    ("net.minecraft.class_320", "Intermediary Session class", 15),
    ("Lnet/minecraft/class_310;method_1551()Lnet/minecraft/class_310;", "Intermediary MinecraftClient.getInstance descriptor", 20),
    ("Lnet/minecraft/class_310;method_1548()Lnet/minecraft/class_320;", "Intermediary MinecraftClient.getSession descriptor", 20),
    ("Lnet/minecraft/class_320;method_1674()Ljava/lang/String;", "Intermediary Session.getAccessToken descriptor", 20),
    ("Lnet/minecraft/class_320;method_1675()Ljava/lang/String;", "Intermediary Session.getSessionId descriptor", 20),
    ("Lnet/minecraft/class_320;field_1983:Ljava/lang/String;", "Intermediary Session.accessToken field descriptor", 20),
    ("Lnet/minecraft/client/session/Session;accessToken:Ljava/lang/String;", "Yarn Session.accessToken field descriptor", 20),
    ("Lnet/minecraft/client/util/Session;accessToken:Ljava/lang/String;", "Yarn legacy Session.accessToken field descriptor", 20),
    ("Lnet/minecraft/client/User;accessToken:Ljava/lang/String;", "Mojmap User.accessToken field descriptor", 20),
    ("Lnet/minecraft/util/Session;field_148258_c:Ljava/lang/String;", "MCP Session.token field descriptor", 20),
    ("eth_call", "Ethereum RPC call", 15),
    ("0x70a08231", "Ethereum balanceOf selector", 15),
    ("Wscript.Shell", "Windows Script Host", 20),
    ("powershell", "PowerShell execution", 15),
    ("RuntimeBroker", "Process masquerading as RuntimeBroker", 20),
]

AUTO_DECRYPT_TRIGGER_MIN_CALLS = 1
AUTO_DECRYPT_TRIGGER_MIN_FILE_RATIO = 0.0
AUTO_DECRYPT_TRIGGER_MIN_FILES_WITH_CALLS = 1
MAJOR_ENCRYPTED_MIN_CALLS = 200
MAJOR_ENCRYPTED_MIN_FILE_RATIO = 0.20
MAJOR_ENCRYPTED_MIN_FILES_WITH_CALLS = 5
OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"
DEEPSEEK_CHAT_COMPLETIONS_URL = "https://api.deepseek.com/v1/chat/completions"
RATTERSCANNER_HASH_URL = "https://api.ratterscanner.com/hash/"
JLAB_STATIC_SCAN_URL = "https://jlab.threat.rip/api/public/static-scan"
JLAB_MAX_UPLOAD_BYTES = 50 * 1024 * 1024
OPENAI_EXEC_SUMMARY_INSTRUCTION = (
    "Parse the JSON and create an executive summary of the result detailing the flow of the malware "
    "or application (if clean) and its capabilities, risks, goal. Keep it technical but understandable "
    "for both layman and professional. Max 500 words. Output must be plain text optimized for terminal "
    "display. Do NOT use markdown headings, bold/italic markers, tables, code fences, horizontal rules, "
    "or backticks. Use short section labels and simple bullet lines prefixed with '- '. Prioritize "
    "confirmed_behavior proof chains over generic suspicious indicators. Explicitly include caveats from "
    "contradiction_notes and avoid overstating automatic exfiltration when only exposure is proven."
)


def _is_sha256_hex(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", (value or "").strip()))


def collect_ratterscanner_hashes(
    target_metadata: dict,
    artifacts: List[Any],
    stage2_analysis: dict | None = None,
    scan_root: Path | None = None,
) -> List[str]:
    out: List[str] = []
    basic = (target_metadata or {}).get("basic_properties", {}) or {}
    s = str(basic.get("sha256", "") or "").strip().lower()
    if _is_sha256_hex(s):
        out.append(s)
    for a in artifacts or []:
        h = str(getattr(a, "sha256", "") or "").strip().lower()
        if _is_sha256_hex(h):
            out.append(h)
    s2 = stage2_analysis or {}
    h2 = str(s2.get("download_sha256", "") or "").strip().lower()
    if _is_sha256_hex(h2):
        out.append(h2)
    if scan_root is not None:
        marker = scan_root / ".java_triage_source_jar_sha256.txt"
        if marker.is_file():
            try:
                m = marker.read_text(encoding="utf-8", errors="replace").strip().lower()
                if _is_sha256_hex(m):
                    out.append(m)
            except Exception:
                pass
    dedup: List[str] = []
    seen: set[str] = set()
    for h in out:
        if h in seen:
            continue
        seen.add(h)
        dedup.append(h)
    return dedup[:50]


def lookup_ratterscanner(hashes: List[str], timeout: int = 20) -> dict:
    valid = [h.strip().lower() for h in hashes if _is_sha256_hex(h)]
    out = {"attempted": False, "error": "", "results": []}
    if not valid:
        return out
    out["attempted"] = True
    try:
        url = RATTERSCANNER_HASH_URL + ",".join(valid)
        req = request.Request(url, method="GET", headers={"User-Agent": "java-triage/1.0"})
        with request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            out["results"] = data.get("results") or []
            return out
        if isinstance(data, dict) and data.get("error"):
            out["error"] = str(data.get("error"))
            return out
        out["error"] = "invalid response format"
        return out
    except Exception as exc:
        out["error"] = _friendly_network_error(exc)
        return out


def _parse_int_header(headers: Any, name: str) -> int | None:
    if headers is None:
        return None
    try:
        raw = str(headers.get(name, "") or "").strip()
    except Exception:
        return None
    if not raw:
        return None
    try:
        return int(raw)
    except Exception:
        return None


def lookup_jlab_static_scan(upload_path: Path, timeout: int = 45) -> dict:
    out = {
        "attempted": False,
        "error": "",
        "status_code": 0,
        "upload_file": "",
        "upload_size": 0,
        "file_name": "",
        "file_size": 0,
        "total_signatures": 0,
        "matched_signatures": 0,
        "signatures": [],
        "retry_after": None,
        "rate_limit_limit": None,
        "rate_limit_remaining": None,
    }
    if not upload_path.is_file():
        out["error"] = "JLab static scan skipped: upload file not found"
        return out
    ext = upload_path.suffix.lower()
    if ext not in {".jar", ".zip"}:
        out["error"] = "JLab static scan skipped: upload must be .jar or .zip"
        return out
    try:
        size = int(upload_path.stat().st_size)
    except Exception:
        out["error"] = "JLab static scan skipped: failed to read upload file size"
        return out
    if size <= 0:
        out["error"] = "JLab static scan skipped: upload file is empty"
        return out
    if size > JLAB_MAX_UPLOAD_BYTES:
        out["error"] = f"JLab static scan skipped: file exceeds 50 MB ({size} bytes)"
        return out

    out["attempted"] = True
    out["upload_file"] = upload_path.name
    out["upload_size"] = size
    boundary = f"----JavaTriageBoundary{int(time.time() * 1000)}"
    mime = "application/java-archive" if ext == ".jar" else "application/zip"
    try:
        file_bytes = upload_path.read_bytes()
        body_prefix = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{upload_path.name}"\r\n'
            f"Content-Type: {mime}\r\n\r\n"
        ).encode("utf-8")
        body_suffix = f"\r\n--{boundary}--\r\n".encode("utf-8")
        payload = body_prefix + file_bytes + body_suffix
        req = request.Request(
            JLAB_STATIC_SCAN_URL,
            method="POST",
            data=payload,
            headers={
                "User-Agent": "java-triage/1.0",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(payload)),
            },
        )
        with request.urlopen(req, timeout=timeout) as resp:
            out["status_code"] = int(getattr(resp, "status", 200) or 200)
            out["retry_after"] = _parse_int_header(resp.headers, "Retry-After")
            out["rate_limit_limit"] = _parse_int_header(resp.headers, "X-RateLimit-Limit")
            out["rate_limit_remaining"] = _parse_int_header(resp.headers, "X-RateLimit-Remaining")
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw) if raw.strip() else {}
        if isinstance(data, dict) and bool(data.get("success")):
            out["file_name"] = str(data.get("fileName", "") or "")
            out["file_size"] = int(data.get("fileSize", 0) or 0)
            out["total_signatures"] = int(data.get("totalSignatures", 0) or 0)
            out["matched_signatures"] = int(data.get("matchedSignatures", 0) or 0)
            sigs = data.get("signatures", [])
            out["signatures"] = sigs if isinstance(sigs, list) else []
            return out
        if isinstance(data, dict) and data.get("error"):
            out["error"] = str(data.get("error", "") or "unknown API error")
            return out
        out["error"] = "invalid response format"
        return out
    except error.HTTPError as exc:
        out["status_code"] = int(getattr(exc, "code", 0) or 0)
        out["retry_after"] = _parse_int_header(exc.headers, "Retry-After")
        out["rate_limit_limit"] = _parse_int_header(exc.headers, "X-RateLimit-Limit")
        out["rate_limit_remaining"] = _parse_int_header(exc.headers, "X-RateLimit-Remaining")
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        message = ""
        if body.strip():
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    message = str(parsed.get("error", "") or "")
                    if out["retry_after"] is None:
                        out["retry_after"] = _parse_int_header(parsed, "retryAfter")
                    if out["rate_limit_limit"] is None:
                        out["rate_limit_limit"] = _parse_int_header(parsed, "limit")
                    if out["rate_limit_remaining"] is None:
                        out["rate_limit_remaining"] = _parse_int_header(parsed, "remaining")
            except Exception:
                message = body.strip()
        if not message:
            message = str(exc)
        if exc.code == 429 and out["retry_after"]:
            out["error"] = f"Rate limit exceeded. Try again in {out['retry_after']}s."
        elif exc.code == 413:
            out["error"] = "File exceeds 50 MB upload limit"
        else:
            out["error"] = message
        return out
    except Exception as exc:
        out["error"] = _friendly_network_error(exc)
        return out


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


def _decode_java_string_literal_fragment(raw: str) -> str:
    try:
        return bytes(raw, "utf-8").decode("unicode_escape")
    except Exception:
        return raw


def _reconstruct_split_string_arrays(text: str) -> List[tuple[str, str, int, int]]:
    out: List[tuple[str, str, int, int]] = []
    for m in SPLIT_STRING_ARRAY_RE.finditer(text):
        body = m.group("body")
        parts_raw = STRING_SHORT_LITERAL_RE.findall(body)
        if len(parts_raw) < 8:
            continue
        parts = [_decode_java_string_literal_fragment(p) for p in parts_raw]
        joined = "".join(parts).strip()
        if len(joined) < 12:
            continue
        line = text.count("\n", 0, m.start()) + 1
        out.append((m.group("name"), joined, line, len(parts)))
    return out


def _extract_printable_byte_array_strings(
    text: str,
    max_arrays: int = 120,
    max_bytes: int = 4096,
) -> List[tuple[str, int, int]]:
    out: List[tuple[str, int, int]] = []
    seen = set()
    for idx, m in enumerate(NEW_BYTE_ARRAY_LITERAL_RE.finditer(text)):
        if idx >= max_arrays:
            break
        vals = parse_java_byte_list(m.group("body"))
        if not vals or len(vals) > max_bytes:
            continue
        raw = bytes((v + 256) % 256 for v in vals)
        if not _mostly_printable(raw):
            continue
        decoded = _to_printable(raw).replace("\x00", "").strip()
        if len(decoded) < 4 or decoded in seen:
            continue
        seen.add(decoded)
        line = text.count("\n", 0, m.start()) + 1
        out.append((decoded, line, len(vals)))
    return out


def _extract_printable_char_array_strings(
    text: str,
    max_arrays: int = 120,
    min_len: int = 4,
    max_len: int = 4096,
) -> List[tuple[str, int, int]]:
    out: List[tuple[str, int, int]] = []
    seen = set()
    for idx, m in enumerate(NEW_CHAR_ARRAY_LITERAL_RE.finditer(text)):
        if idx >= max_arrays:
            break
        vals = []
        for tm in JAVA_CHAR_TOKEN_RE.finditer(m.group("body")):
            try:
                vals.append(int(tm.group(1)))
            except Exception:
                continue
        if not vals or len(vals) < min_len or len(vals) > max_len:
            continue
        chars = []
        printable = 0
        for v in vals:
            v &= 0xFFFF
            try:
                ch = chr(v)
            except Exception:
                ch = ""
            chars.append(ch)
            if ch and (ch == "\t" or ch == "\n" or ch == "\r" or 32 <= ord(ch) <= 126):
                printable += 1
        if printable / max(1, len(chars)) < 0.85:
            continue
        decoded = "".join(chars).replace("\x00", "").strip()
        if len(decoded) < min_len or decoded in seen:
            continue
        seen.add(decoded)
        line = text.count("\n", 0, m.start()) + 1
        out.append((decoded, line, len(vals)))
    return out


def _extract_reversed_stringbuilder_literals(text: str, max_hits: int = 100) -> List[tuple[str, int, int]]:
    out: List[tuple[str, int, int]] = []
    seen = set()
    for idx, m in enumerate(STRINGBUILDER_REVERSE_RE.finditer(text)):
        if idx >= max_hits:
            break
        raw = _decode_java_string_literal_fragment(m.group("lit"))
        decoded = raw[::-1].strip()
        if len(decoded) < 4 or decoded in seen:
            continue
        seen.add(decoded)
        line = text.count("\n", 0, m.start()) + 1
        out.append((decoded, line, len(raw)))
    return out


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
        if discord_kind == "discord_encrypted_token_marker":
            return "credential_or_identity_field"
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


def decode_discord_encrypted_token_marker(decoded: str) -> tuple[str, str]:
    text = decoded.strip()
    m = DISCORD_ENCRYPTED_TOKEN_MARKER_RE.search(text)
    if not m:
        if "dQw4w9WgXcQ:" in text:
            return "discord_encrypted_token_marker", "marker_prefix_present payload_blob_not_in_literal"
        return "", ""
    payload = m.group("payload")
    try:
        blob = base64.b64decode(payload, validate=True)
    except Exception:
        return "discord_encrypted_token_marker", "marker_prefix_present payload_base64=invalid"
    if not blob:
        return "discord_encrypted_token_marker", "marker_prefix_present payload_base64=empty"
    version = blob[:3].decode("ascii", errors="replace") if len(blob) >= 3 else "<short>"
    nonce = blob[3:15].hex().upper() if len(blob) >= 15 else ""
    note = (
        f"marker_prefix_present payload_b64_bytes={len(payload)} decoded_bytes={len(blob)} "
        f"version={version} nonce={nonce or '<missing>'} "
        "decryption_requires_local_master_key"
    )
    return "discord_encrypted_token_marker", note


def detect_discord_indicator(decoded: str) -> tuple[str, str]:
    d = decoded.strip()
    low = d.lower()

    enc_kind, enc_note = decode_discord_encrypted_token_marker(d)
    if enc_kind:
        return enc_kind, enc_note

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
            if discord_kind == "discord_encrypted_token_marker":
                category = "credential_or_identity_field"
                signal = "discord_token_stealer_marker"
            else:
                category = "discord_indicator"
                signal = discord_kind
        elif endpoint_kind:
            category = "comms_indicator"
            signal = endpoint_kind

        elif URL_RE.match(decoded):
            category = "url"
            signal = "literal_url"
        elif ETH_SELECTOR_RE.match(decoded):
            category = "hex_or_contract"
            signal = "literal_eth_method_selector"
        elif HEX_ADDR_RE.match(decoded) and len(decoded) == 42:
            category = "hex_or_contract"
            signal = "literal_contract_address"
        elif "jsonrpc" in low or "eth_call" in low:
            category = "rpc_template"
            signal = "literal_eth_rpc_template"
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
            SpinnerColumn(style="#C000FF"),
            TextColumn("[bold white]Deobfuscating Java files"),
            BarColumn(bar_width=30, complete_style="#C000FF", finished_style="#C000FF", pulse_style="#C000FF"),
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


def iter_class_files(root: Path) -> Iterable[Path]:
    yield from root.rglob("*.class")


def _extract_class_utf8_constants(class_bytes: bytes, max_items: int = 6000) -> List[str]:
    out: List[str] = []
    if len(class_bytes) < 10 or class_bytes[:4] != b"\xCA\xFE\xBA\xBE":
        return out
    off = 8
    try:
        cp_count = int.from_bytes(class_bytes[off : off + 2], "big")
    except Exception:
        return out
    off += 2
    idx = 1
    while idx < cp_count and off < len(class_bytes):
        if len(out) >= max_items:
            break
        tag = class_bytes[off]
        off += 1
        if tag == 1:  # CONSTANT_Utf8
            if off + 2 > len(class_bytes):
                break
            ln = int.from_bytes(class_bytes[off : off + 2], "big")
            off += 2
            if off + ln > len(class_bytes):
                break
            raw = class_bytes[off : off + ln]
            off += ln
            try:
                s = raw.decode("utf-8", errors="replace")
            except Exception:
                s = ""
            if s:
                out.append(s)
        elif tag in {3, 4}:  # int/float
            off += 4
        elif tag in {5, 6}:  # long/double (take two entries)
            off += 8
            idx += 1
        elif tag in {7, 8, 16, 19, 20}:  # class/string/methodtype/module/package
            off += 2
        elif tag in {9, 10, 11, 12, 17, 18}:  # refs/nameandtype/dynamic/invokedynamic
            off += 4
        elif tag == 15:  # method handle
            off += 3
        else:
            break
        idx += 1
    return out


def scan_class_constant_pool(path: Path, root: Path, max_hits: int = 180) -> List[Finding]:
    out: List[Finding] = []
    rel = str(path.relative_to(root))
    seen = set()
    try:
        raw = path.read_bytes()
    except Exception:
        return out
    constants = _extract_class_utf8_constants(raw)
    for decoded in constants:
        if len(out) >= max_hits:
            break
        decoded = decoded.strip()
        if len(decoded) < 4:
            continue
        low = decoded.lower()
        compact = "".join(decoded.split())
        signal = ""
        category = ""
        discord_kind, discord_note = detect_discord_indicator(decoded)
        endpoint_kind, endpoint_note = detect_external_endpoint_indicator(decoded)

        if discord_kind:
            if discord_kind == "discord_encrypted_token_marker":
                category = "credential_or_identity_field"
                signal = "discord_token_stealer_marker"
            else:
                category = "discord_indicator"
                signal = discord_kind
        elif endpoint_kind:
            category = "comms_indicator"
            signal = endpoint_kind
        elif URL_RE.match(decoded):
            category = "url"
            signal = "class_const_url"
        elif ETH_SELECTOR_RE.match(decoded):
            category = "hex_or_contract"
            signal = "class_const_eth_method_selector"
        elif HEX_ADDR_RE.match(decoded) and len(decoded) == 42:
            category = "hex_or_contract"
            signal = "class_const_contract_address"
        elif "jsonrpc" in low or "eth_call" in low:
            category = "rpc_template"
            signal = "class_const_eth_rpc_template"
        elif COMMAND_LITERAL_RE.search(decoded):
            category = "dynamic_execution"
            signal = "class_const_command_or_lolbin"
        elif (
            decoded.startswith("/")
            or WINDOWS_PATH_RE.match(decoded)
            or "\\appdata\\" in low
            or "/tmp/" in low
            or decoded.endswith((".dll", ".exe", ".jar", ".dat", ".bin", ".ps1", ".bat", ".cmd"))
        ):
            category = "path"
            signal = "class_const_path_or_payload_name"
        elif len(compact) >= 80 and BASE64_RE.match(compact):
            category = "base64_blob"
            signal = "class_const_base64_blob"
        elif any(k in low for k in SUSPICIOUS_STRING_KEYWORDS):
            category = "credential_or_identity_field" if any(k in low for k in ("token", "authorization", "api_key", "bearer ")) else "string"
            signal = "class_const_keyword_hit"
        else:
            continue

        combined_note = " ".join([n for n in [discord_note, endpoint_note] if n]).strip()
        extra_note = f" {combined_note}" if combined_note else ""
        key = (decoded, category, signal, combined_note)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Finding(
                file=rel,
                line=1,
                function="<class_const>",
                decoded=decoded,
                category=category,
                note=f"source=class_constant_pool signal={signal}{extra_note}",
            )
        )
    return out


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


def _try_decode_base32_blob(raw_text: str, min_chars: int = 128) -> bytes:
    compact = "".join((raw_text or "").split())
    if len(compact) < min_chars:
        return b""
    no_pad = compact.rstrip("=")
    if not no_pad:
        return b""
    if not re.fullmatch(r"[A-Za-z2-7]+", no_pad):
        return b""
    pad = "=" * ((8 - (len(no_pad) % 8)) % 8)
    try:
        return base64.b32decode((no_pad + pad).upper(), casefold=True)
    except Exception:
        return b""


def _read_referenced_resource(root: Path, raw_ref: str) -> tuple[str, bytes]:
    rel = raw_ref.lstrip("/\\")
    parts = [p for p in re.split(r"[\\/]+", rel) if p and p != "."]
    if not parts:
        return "", b""
    rel_norm = "/".join(parts)
    try:
        candidate = (root / Path(*parts)).resolve()
        root_resolved = root.resolve()
        if not str(candidate).startswith(str(root_resolved)):
            return "", b""
        if not candidate.is_file():
            return "", b""
        return rel_norm, candidate.read_bytes()
    except Exception:
        return "", b""


def _sanitize_label(text: str) -> str:
    out = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())
    return out.strip("._-") or "item"


def _resolve_unique_dir(base_dir: Path) -> Path:
    if not base_dir.exists():
        return base_dir
    idx = 2
    while True:
        candidate = base_dir.parent / f"{base_dir.name}_{idx}"
        if not candidate.exists():
            return candidate
        idx += 1


def _is_generated_droppedjar_path(path: Path) -> bool:
    return any(part.lower().endswith("_droppedjar") for part in path.parts)


def _is_tool_jar_name(name: str) -> bool:
    low = name.lower()
    return (
        low.startswith("cfr-")
        or low == "cfr.jar"
        or low == "fernflower.jar"
        or low.startswith("vineflower-")
    )


def _write_source_jar_metadata(scan_dir: Path, source_jar: Path) -> None:
    try:
        st = source_jar.stat()
        meta = {
            "name": source_jar.name,
            "path": str(source_jar.resolve()),
            "size_bytes": int(st.st_size),
            "size_text": _human_size(int(st.st_size)),
            "md5": _hash_file(source_jar, "md5"),
            "sha1": _hash_file(source_jar, "sha1"),
            "sha256": _hash_file(source_jar, "sha256"),
        }
        scan_dir.mkdir(parents=True, exist_ok=True)
        (scan_dir / ".java_triage_source_jar_metadata.json").write_text(
            json.dumps(meta, indent=2),
            encoding="utf-8",
        )
        (scan_dir / ".java_triage_source_jar_sha256.txt").write_text(meta["sha256"], encoding="utf-8")
    except Exception:
        pass


def _find_cfr_jar(cwd: Path) -> Path | None:
    direct = cwd / "cfr-0.152.jar"
    if direct.is_file():
        return direct
    candidates = sorted(
        [p for p in cwd.glob("cfr*.jar") if p.is_file()],
        key=lambda p: p.name.lower(),
    )
    return candidates[0] if candidates else None


def _decompile_jar_with_cfr(
    jar_path: Path,
    out_dir: Path,
    cfr_path: Path,
    show_progress: bool,
    progress_console=None,
) -> tuple[bool, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cp = _run_subprocess_with_progress(
        ["java", "-jar", str(cfr_path), str(jar_path), "--outputdir", str(out_dir)],
        f"CFR decompiling {jar_path.name}",
        show_progress,
        progress_console,
    )
    if cp.returncode != 0:
        err = (cp.stderr or cp.stdout or "").strip()
        return False, f"CFR failed for {jar_path.name}: {err}" if err else f"CFR failed for {jar_path.name}"
    if not any(out_dir.rglob("*.java")):
        return False, f"CFR produced no Java sources for {jar_path.name}"
    _write_source_jar_metadata(out_dir, jar_path)
    return True, ""


def _run_subprocess_with_progress(
    args: List[str],
    label: str,
    show_progress: bool,
    progress_console=None,
) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", errors="replace", delete=False) as out_f:
        out_name = out_f.name
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", errors="replace", delete=False) as err_f:
        err_name = err_f.name

    try:
        with open(out_name, "w", encoding="utf-8", errors="replace") as out_h, open(
            err_name, "w", encoding="utf-8", errors="replace"
        ) as err_h:
            proc = subprocess.Popen(
                args,
                stdout=out_h,
                stderr=err_h,
                text=True,
            )
            start = time.time()
            if show_progress and RICH_AVAILABLE and progress_console is not None:
                with Progress(
                    SpinnerColumn(style="#C000FF"),
                    TextColumn("[bold white]{task.description}"),
                    BarColumn(bar_width=32, complete_style="#C000FF", finished_style="#C000FF", pulse_style="#C000FF"),
                    TimeElapsedColumn(),
                    console=progress_console,
                    transient=False,
                    refresh_per_second=8,
                ) as prog:
                    task_id = prog.add_task(label, total=None)
                    while proc.poll() is None:
                        time.sleep(0.12)
                        prog.update(task_id, description=f"{label} ({int(time.time() - start)}s)")
            else:
                last = -1
                while proc.poll() is None:
                    if show_progress:
                        elapsed = int(time.time() - start)
                        if elapsed != last and elapsed % 2 == 0:
                            progress(True, f"{label} ({elapsed}s)", progress_console)
                            last = elapsed
                    time.sleep(0.15)
            rc = proc.wait()

        out = Path(out_name).read_text(encoding="utf-8", errors="replace")
        err = Path(err_name).read_text(encoding="utf-8", errors="replace")
        return subprocess.CompletedProcess(args, rc, out, err)
    finally:
        try:
            Path(out_name).unlink(missing_ok=True)
        except Exception:
            pass
        try:
            Path(err_name).unlink(missing_ok=True)
        except Exception:
            pass


def _prefix_rel_path(prefix: str, rel: str) -> str:
    rel_norm = rel.replace("\\", "/")
    return f"{prefix}/{rel_norm}" if prefix else rel_norm


def _apply_prefix_findings(items: List[Finding], prefix: str) -> List[Finding]:
    if not prefix:
        return items
    return [
        Finding(
            file=_prefix_rel_path(prefix, it.file),
            line=it.line,
            function=it.function,
            decoded=it.decoded,
            category=it.category,
            note=it.note,
        )
        for it in items
    ]


def _apply_prefix_behaviors(items: List[BehaviorFinding], prefix: str) -> List[BehaviorFinding]:
    if not prefix:
        return items
    return [
        BehaviorFinding(
            file=_prefix_rel_path(prefix, it.file),
            line=it.line,
            behavior=it.behavior,
            evidence=it.evidence,
        )
        for it in items
    ]


def _apply_prefix_artifacts(items: List[ArtifactFinding], prefix: str) -> List[ArtifactFinding]:
    if not prefix:
        return items
    out: List[ArtifactFinding] = []
    for it in items:
        p = it.path
        if p.startswith("<") and p.endswith(">"):
            p = f"{prefix}/{p}"
        else:
            p = _prefix_rel_path(prefix, p)
        out.append(
            ArtifactFinding(
                path=p,
                filename=it.filename,
                size=it.size,
                sha256=it.sha256,
                artifact_type=it.artifact_type,
                evidence=it.evidence,
            )
        )
    return out


def prepare_nested_dropped_jar_roots(scan_root: Path, show_progress: bool, progress_console=None) -> List[tuple[Path, str]]:
    cfr = _find_cfr_jar(Path.cwd().resolve())
    if cfr is None:
        progress(show_progress, "nested dropped-jar scan skipped: CFR jar not found in cwd", progress_console)
        return []

    jar_candidates = sorted(
        [
            p
            for p in scan_root.rglob("*.jar")
            if p.is_file()
            and not _is_tool_jar_name(p.name)
            and not p.name.lower().endswith("_droppedjar.jar")
            and not _is_generated_droppedjar_path(p.parent)
        ],
        key=lambda p: str(p).lower(),
    )
    if not jar_candidates:
        return []

    out: List[tuple[Path, str]] = []
    for jar_path in jar_candidates:
        rel = str(jar_path.relative_to(scan_root))
        base_name = _sanitize_label(jar_path.stem)
        preferred = Path.cwd().resolve() / f"{base_name}_droppedjar"
        marker_name = ".java_triage_nested_jar_source.txt"
        if preferred.exists() and preferred.is_dir():
            marker = preferred / marker_name
            marker_text = marker.read_text(encoding="utf-8", errors="replace").strip() if marker.is_file() else ""
            if marker_text == str(jar_path.resolve()) and any(preferred.rglob("*.java")):
                progress(show_progress, f"reusing nested dropped-jar scan directory: {preferred}", progress_console)
                out.append((preferred, f"dropped/{preferred.name}"))
                continue
            preferred = _resolve_unique_dir(preferred)

        ok, err = _decompile_jar_with_cfr(jar_path, preferred, cfr, show_progress, progress_console)
        if not ok:
            progress(show_progress, f"nested dropped-jar preparation failed: {err}", progress_console)
            continue
        try:
            (preferred / marker_name).write_text(str(jar_path.resolve()), encoding="utf-8")
        except Exception:
            pass
        out.append((preferred, f"dropped/{preferred.name}"))
        progress(show_progress, f"nested dropped-jar ready: {rel} -> {preferred}", progress_console)
    return out


def prepare_embedded_base32_archive_roots(scan_root: Path, show_progress: bool, progress_console=None) -> List[tuple[Path, str]]:
    cfr = _find_cfr_jar(Path.cwd().resolve())
    if cfr is None:
        progress(show_progress, "embedded archive scan skipped: CFR jar not found in cwd", progress_console)
        return []

    out: List[tuple[Path, str]] = []
    seen_sources: set[str] = set()
    marker_name = ".java_triage_embedded_source.txt"

    for java_path in iter_java_files(scan_root):
        if _is_generated_droppedjar_path(java_path.parent):
            continue
        try:
            text = java_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        refs = [m.group(1) for m in RESOURCE_STREAM_RE.finditer(text)]
        if not refs:
            continue

        for raw_ref in refs:
            rel_ref, raw = _read_referenced_resource(scan_root, raw_ref)
            if not raw:
                continue
            try:
                txt = raw.decode("utf-8", errors="ignore")
            except Exception:
                txt = ""
            decoded = _try_decode_base32_blob(txt)
            if not decoded.startswith(b"PK\x03\x04"):
                continue

            src_id = f"{java_path.resolve()}::{rel_ref}::{hashlib.sha256(decoded).hexdigest()}"
            if src_id in seen_sources:
                continue
            seen_sources.add(src_id)

            res_stem = _sanitize_label(Path(rel_ref).stem)
            if not res_stem:
                res_stem = "embedded_payload"
            base_name = f"{res_stem}_droppedjar"
            out_dir = Path.cwd().resolve() / base_name
            jar_out = Path.cwd().resolve() / f"{base_name}.jar"

            if out_dir.exists() and out_dir.is_dir():
                marker = out_dir / marker_name
                marker_text = marker.read_text(encoding="utf-8", errors="replace").strip() if marker.is_file() else ""
                if marker_text == src_id and any(out_dir.rglob("*.java")):
                    progress(show_progress, f"reusing embedded dropped-jar directory: {out_dir}", progress_console)
                    out.append((out_dir, f"dropped/{out_dir.name}"))
                    continue
                out_dir = _resolve_unique_dir(out_dir)
                jar_out = jar_out.with_name(f"{out_dir.name}.jar")

            try:
                jar_out.write_bytes(decoded)
            except Exception as exc:
                progress(show_progress, f"failed writing decoded embedded jar {jar_out}: {exc}", progress_console)
                continue

            ok, err = _decompile_jar_with_cfr(jar_out, out_dir, cfr, show_progress, progress_console)
            if not ok:
                progress(show_progress, f"embedded dropped-jar preparation failed: {err}", progress_console)
                continue
            try:
                (out_dir / marker_name).write_text(src_id, encoding="utf-8")
            except Exception:
                pass
            progress(show_progress, f"embedded dropped-jar ready: {rel_ref} -> {out_dir}", progress_console)
            out.append((out_dir, f"dropped/{out_dir.name}"))

    return out


def scan_behavior(path: Path, root: Path) -> List[BehaviorFinding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    low = text.lower()
    rel = str(path.relative_to(root))
    rel_low = rel.replace("\\", "/").lower()
    is_vendor_lib = _is_known_library_relpath(rel_low)
    out: List[BehaviorFinding] = []
    reconstructed_urls = [item for item in _reconstruct_split_string_arrays(text) if URL_RE.match(item[1])]
    byte_array_strings = _extract_printable_byte_array_strings(text)
    char_array_strings = _extract_printable_char_array_strings(text)
    reversed_literals = _extract_reversed_stringbuilder_literals(text)
    obfuscated_string_pool = byte_array_strings + char_array_strings + reversed_literals
    obfuscated_values = [s for s, _, _ in obfuscated_string_pool]
    http_hosts = set(_extract_http_hosts(text))
    for _, url, _, _ in reconstructed_urls:
        host = urlparse(url).netloc.lower()
        if host:
            http_hosts.add(host)

    if reconstructed_urls:
        sample_name, sample_url, sample_line, sample_parts = reconstructed_urls[0]
        host_sample = sorted(http_hosts)[:3]
        host_note = f" hosts={','.join(host_sample)}" if host_sample else ""
        out.append(
            BehaviorFinding(
                file=rel,
                line=sample_line,
                behavior="obfuscated_url_reconstruction",
                evidence=(
                    f"Reconstructs URL from split string array name={sample_name} parts={sample_parts}"
                    f"{host_note} sample={sample_url[:120]}"
                ),
            )
        )

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

    if (
        "JarInputStream" in text
        and "getNextJarEntry" in text
        and "loadClass(" in text
        and ".invoke(" in text
        and ("BodyHandlers.ofByteArray()" in text or "HttpClient.newHttpClient()" in text)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "JarInputStream"),
                behavior="staged_remote_jar_execution",
                evidence="Downloads remote JAR bytes, unpacks classes in-memory, and reflectively executes staged entrypoint",
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

    has_urlconnection_download = (
        ("HttpURLConnection" in text or "URLConnection" in text)
        and ("getInputStream(" in text or "openStream(" in text)
        and ("FileOutputStream(" in text or "transferFrom(" in text or "Files.copy(" in text)
    )
    if has_urlconnection_download:
        host_note = f" hosts={','.join(sorted(http_hosts))}" if http_hosts else ""
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "HttpURLConnection") if "HttpURLConnection" in text else find_line(text, "URLConnection"),
                behavior="http_urlconnection_binary_download",
                evidence=f"Uses URLConnection to download remote bytes and write to disk{host_note}",
            )
        )

    writes_to_mods_dir = (
        ('"mods"' in text or "MOD_FOLDER" in text)
        and ("new File(" in text)
        and ("Minecraft.func_71410_x().field_71412_D" in text or "Minecraft.getMinecraft().mcDataDir" in text)
    )
    auto_update_invocation = ("@EventHandler" in text and "preInit(" in text and "checkForUpdates()" in text)
    if has_urlconnection_download and writes_to_mods_dir:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "MOD_FOLDER") if "MOD_FOLDER" in text else find_line(text, '"mods"'),
                behavior="minecraft_mod_folder_remote_dropper",
                evidence="Downloads remote payload and writes into Minecraft mods directory for staged loading",
            )
        )
        if auto_update_invocation:
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "preInit("),
                    behavior="assessment_suspicious_remote_mod_dropper",
                    evidence="Auto-runs on mod init and silently downloads remote JAR into mods folder",
                )
            )
        else:
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "checkForUpdates()"),
                    behavior="assessment_needs_review_remote_mod_downloader",
                    evidence="Remote mod downloader present; verify trust chain and signed update metadata",
                )
            )

    resource_refs = [m.group(1) for m in RESOURCE_STREAM_RE.finditer(text)]
    has_base32_decode_flow = (
        "base32Decode(" in text
        or ("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" in text and "toBinaryString(" in text and "Integer.parseInt(" in text)
    )
    writes_payload_file = "FileOutputStream(" in text and ("writeFile(" in text or ".write(" in text)
    jar_target_literals = [m.group(1) for m in re.finditer(r'"([^"\r\n]*\.jar)"', text, flags=re.IGNORECASE)]
    drops_to_mods = any("mods/" in s.replace("\\", "/").lower() for s in jar_target_literals)
    embedded_archive_hits: List[tuple[str, int]] = []
    for ref in resource_refs[:30]:
        rel_norm, raw = _read_referenced_resource(root, ref)
        if not raw:
            continue
        try:
            txt = raw.decode("utf-8", errors="ignore")
        except Exception:
            txt = ""
        decoded = _try_decode_base32_blob(txt)
        if decoded.startswith(b"PK\x03\x04"):
            embedded_archive_hits.append((rel_norm, len(decoded)))

    if embedded_archive_hits and has_base32_decode_flow and writes_payload_file:
        sample_res, sample_len = embedded_archive_hits[0]
        target_note = f" targets={','.join(sorted(set(jar_target_literals))[:2])}" if jar_target_literals else ""
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getResourceAsStream("),
                behavior="embedded_resource_encoded_archive_dropper",
                evidence=(
                    f"Decodes embedded Base32 resource to ZIP/JAR payload and writes it to disk "
                    f"resource={sample_res} decoded_bytes={sample_len}{target_note}"
                ),
            )
        )
        if drops_to_mods:
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "mods/") if "mods/" in text else find_line(text, ".jar"),
                    behavior="minecraft_mod_folder_embedded_payload_dropper",
                    evidence="Writes decoded embedded archive payload into Minecraft mods directory for staged loading",
                )
            )
            if "@EventHandler" in text and ("init(" in text or "preInit(" in text):
                out.append(
                    BehaviorFinding(
                        file=rel,
                        line=find_line(text, "@EventHandler"),
                        behavior="assessment_suspicious_embedded_mod_dropper",
                        evidence="Mod init handler triggers embedded payload decode+drop into mods folder",
                    )
                )

    has_discord_leveldb_paths = ("Local Storage\\\\leveldb" in text) or ("Local Storage\\leveldb" in text)
    has_discord_token_regex = (
        "Pattern.compile(\"[\\\\w-]{24}\\\\.[\\\\w-]{6}\\\\.[\\\\w-]{25,110}\")" in text
        or "tokenRegex" in text
    )
    has_discord_enc_marker = "dQw4w9WgXcQ:" in text
    if has_discord_leveldb_paths and (has_discord_token_regex or has_discord_enc_marker):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "Local Storage\\leveldb"),
                behavior="discord_leveldb_token_theft",
                evidence="Enumerates Discord/browser LevelDB paths and extracts Discord tokens (plain/encrypted marker forms)",
            )
        )

    if "discord.com/api/v9/users/@me" in low and "Authorization" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "discord.com/api/v9/users/@me"),
                behavior="discord_token_validation_api",
                evidence="Validates harvested Discord tokens by calling Discord /users/@me with Authorization header",
            )
        )

    if (
        ('delivery.add("discord"' in text or 'delivery.addProperty("discord"' in text)
        and ("setRequestMethod(\"POST\")" in text or "setRequestMethod('POST')" in text)
        and ("delivery.toString()" in text or "writeBytes(delivery" in text)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, 'delivery.add("discord"') if 'delivery.add("discord"' in text else find_line(text, "delivery"),
                behavior="discord_token_exfiltration_bundle",
                evidence="Packages Discord token data into outbound JSON delivery payload and posts to remote endpoint",
            )
        )
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, 'delivery.add("discord"') if 'delivery.add("discord"' in text else find_line(text, "delivery"),
                behavior="assessment_suspicious_discord_token_stealer",
                evidence="Discord token theft and outbound exfiltration workflow is present",
            )
        )

    has_password_db_theft = (
        "Login Data" in text
        and "password_value" in text
        and "jdbc:sqlite:" in text
        and ("Utils.decrypt(" in text or "decrypt(" in text)
    )
    if has_password_db_theft:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "Login Data"),
                behavior="browser_password_database_theft",
                evidence="Reads Chromium Login Data SQLite DB and decrypts password_value entries",
            )
        )

    has_cookie_db_theft = (
        ("\\Network\\Cookies" in text or "cookies" in low)
        and "encrypted_value" in text
        and "jdbc:sqlite:" in text
        and ("Utils.decrypt(" in text or "decrypt(" in text)
    )
    if has_cookie_db_theft:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "encrypted_value"),
                behavior="browser_cookie_database_theft",
                evidence="Reads Chromium Cookies SQLite DB and decrypts encrypted_value cookie data",
            )
        )

    has_history_collection = (
        "History" in text
        and "jdbc:sqlite:" in text
        and "SELECT url, title" in text
    )
    if has_history_collection:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "SELECT url, title"),
                behavior="browser_history_database_collection",
                evidence="Reads browser History SQLite DB and extracts visited URL/title records",
            )
        )

    has_screenshot_capture = (
        "new Robot()" in text
        and "createScreenCapture(" in text
        and "Base64.getEncoder().encodeToString(" in text
    )
    if has_screenshot_capture:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "createScreenCapture("),
                behavior="screenshot_capture_collection",
                evidence="Captures full screen via AWT Robot and base64-encodes image for collection/exfiltration",
            )
        )

    has_audio_capture = (
        "TargetDataLine" in text
        or "AudioSystem.getTargetDataLine(" in text
        or "DataLine.Info(TargetDataLine.class" in text
    ) and ".read(" in text
    if has_audio_capture:
        out.append(
            BehaviorFinding(
                file=rel,
                line=(
                    find_line(text, "TargetDataLine")
                    if "TargetDataLine" in text
                    else find_line(text, "AudioSystem.getTargetDataLine(")
                ),
                behavior="audio_capture_capability",
                evidence="Uses TargetDataLine capture APIs and reads audio buffers (microphone capture path)",
            )
        )

    has_audio_playback = (
        ("AudioSystem.getClip(" in text or "Clip.open(" in text)
        and "AudioInputStream" in text
        and not has_audio_capture
    )
    if has_audio_playback:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "AudioSystem.getClip(") if "AudioSystem.getClip(" in text else find_line(text, "Clip.open("),
                behavior="audio_playback_capability",
                evidence="Uses Clip/AudioInputStream playback APIs; this is not microphone capture by itself",
            )
        )

    has_chromium_masterkey_chain = (
        "Crypt32Util.cryptUnprotectData" in text
        and "AES/GCM/NoPadding" in text
        and ("Local State" in text or "encrypted_key" in text)
    )
    if has_chromium_masterkey_chain:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "Crypt32Util.cryptUnprotectData"),
                behavior="chromium_masterkey_decryption_chain",
                evidence="Uses DPAPI + AES/GCM flow to decrypt Chromium-protected credential/token material",
            )
        )

    has_runtime_sqlite_loader = (
        "sqlite-jdbc" in low
        and "repo1.maven.org/maven2/org/xerial/sqlite-jdbc" in low
        and "URLClassLoader" in text
        and "Class.forName(\"org.sqlite.JDBC\"" in text
    )
    if has_runtime_sqlite_loader:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "sqlite-jdbc"),
                behavior="runtime_sqlite_driver_download_and_load",
                evidence="Downloads sqlite-jdbc JAR from Maven and loads it dynamically with URLClassLoader",
            )
        )

    exfil_base_urls = sorted(set(re.findall(r'https?://[^\s"\'<>]+', text)))
    has_delivery_post = (
        "setRequestMethod(\"POST\")" in text
        and ("delivery.toString()" in text or 'delivery.add("minecraft"' in text)
    )
    if has_delivery_post and exfil_base_urls:
        base = exfil_base_urls[0]
        endpoint_notes: List[str] = []
        if "/delivery" in text:
            endpoint_notes.append(f"{base.rstrip('/')}/delivery")
        if "/ssid" in text:
            endpoint_notes.append(f"{base.rstrip('/')}/ssid")
        if not endpoint_notes:
            endpoint_notes.append(base)
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "setRequestMethod(\"POST\")"),
                behavior="credential_exfiltration_endpoint",
                evidence="Credential exfil POST endpoint(s): " + ", ".join(endpoint_notes),
            )
        )

    multi_stealer_markers = 0
    for flag in [
        ('delivery.add("discord"' in text or 'delivery.addProperty("discord"' in text),
        ('delivery.add("passwords"' in text or "grabPassword()" in text),
        ('delivery.addProperty("cookies"' in text or "grabCookies()" in text),
        ('delivery.add("history"' in text or "grabBrowserHistory()" in text),
        ('delivery.addProperty("screenshot"' in text or "takeScreenshot()" in text),
        ('delivery.add("minecraft"' in text or 'mcJson.addProperty("ssid"' in text),
    ]:
        if flag:
            multi_stealer_markers += 1
    if multi_stealer_markers >= 4 and has_delivery_post:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "delivery"),
                behavior="assessment_suspicious_multi_credential_infostealer",
                evidence="Bundles multiple credential/data theft modules (minecraft/discord/passwords/cookies/history/screenshot) for outbound POST exfiltration",
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

    has_get_game_profile = _contains_any(text, [
        "method_7334()",
        "getGameProfile()",
        "getGameProfile("
    ])
    has_get_session = _contains_any(text, [
        "method_1548()",
        "getSession()",
        "getUser()",
        "func_110432_I()",
        "Minecraft.getMinecraft()",
        "Minecraft.func_71410_x()",
        "field_1726",
        "field_71449_j",
        "net.minecraft.client.util.Session",
        "net.minecraft.client.session.Session",
        "net.minecraft.util.Session",
        "net.minecraft.class_320",
        "class_320",
        "net.minecraft.client.User",
        "new Session("
    ])
    has_get_access_token = _contains_any(text, [
        "method_1674()",
        "getAccessToken()",
        "session.getAccessToken()",
        "func_148254_d()",
        "getToken()",
        "field_1983",
        "field_148258_c",
        "accessToken"
    ])
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
    has_username_access_signal = False
    has_uuid_access_signal = False

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

    if (
        "method_1676()" in text
        or ".getName()" in text
        or ".getUsername()" in text
        or "func_111285_a()" in text
        or "username" in text
        or "field_1982" in text
        or "field_74286_b" in text
        or "name" in text
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=(
                    find_line(text, "method_1676()")
                    if "method_1676()" in text
                    else (find_line(text, ".getUsername()") if ".getUsername()" in text else find_line(text, ".getName()"))
                ),
                behavior="minecraft_username_access",
                evidence="Reads Minecraft session username (method_1676/getName/getUsername)",
            )
        )
        has_username_access_signal = True

    # UUID access via multiple mappings: method_44717, getProfileId (mapped), getUuid (Session), getId (GameProfile)
    if (
        "method_44717()" in text
        or "method_1673()" in text
        or ".getProfileId()" in text
        or ".getUuid()" in text
        or ".getUuidOrNull()" in text
        or ".getPlayerID()" in text
        or "func_148255_b()" in text
        or "field_1985" in text
        or "field_148257_b" in text
        or "uuid" in text
        or (".getId()" in text and ("GameProfile" in text or "getGameProfile()" in text))
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=(
                    find_line(text, "method_44717()")
                    if "method_44717()" in text
                    else (
                        find_line(text, ".getProfileId()")
                        if ".getProfileId()" in text
                        else (find_line(text, ".getUuid()") if ".getUuid()" in text else find_line(text, ".getId()"))
                    )
                ),
                behavior="minecraft_uuid_access",
                evidence="Reads Minecraft session UUID (method_44717/getProfileId/getUuid/getId)",
            )
        )
        has_uuid_access_signal = True

    if has_get_access_token:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getAccessToken()") if "getAccessToken()" in text else find_line(text, "method_1674()"),
                behavior="minecraft_access_token_access",
                evidence="Reads Minecraft session access token (method_1674/getAccessToken)",
            )
        )
    # Session ID access (older flows); track separately
    if (
        ".getSessionId()" in text
        or "session.getSessionId()" in text
        or ".getSessionID()" in text
        or "method_1675()" in text
        or "func_111286_b()" in text
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, ".getSessionId()"),
                behavior="minecraft_session_id_access",
                evidence="Reads Minecraft session ID (getSessionId)",
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
        "func_148254_d()",
        "getAccessToken()",
        "getToken()",
        "method_1675()",
        "func_111286_b()",
        "getSessionId()",
        "getSessionID()",
        "session.getAccessToken()",
        "field_1983",
        "field_148258_c",
        "method_38740()",
        "getClientId()",
        "field_34961",
        "method_38741()",
        "getXuid()",
        "field_34960",
        "method_35718()",
        "getAccountType()",
        "field_1984",
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
        if http_hosts or ("HttpClient" in text and "send(" in text):
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, chosen_token),
                    behavior="possible_minecraft_session_file_exfiltration",
                    evidence="Session/account file reference appears in file that also contains outbound HTTP activity",
                )
            )

    # Identity exfiltration: username/UUID present with outbound HTTP usage in same file.
    outbound_http_present = bool(http_hosts or ("HttpClient" in text and "send(" in text) or ("OkHttpClient" in text and ".newCall(" in text) or ("HttpURLConnection" in text))
    if outbound_http_present and (has_username_access_signal or has_uuid_access_signal):
        out.append(
            BehaviorFinding(
                file=rel,
                line=(find_line(text, ".getUsername()") if has_username_access_signal else find_line(text, ".getUuid()")),
                behavior="possible_minecraft_identity_exfiltration",
                evidence="Username/UUID read present alongside outbound HTTP activity",
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

    if (
        has_get_access_token
        and 'context.add("minecraftInfo"' in text
        and "Helper.stageWithContext(context)" in text
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, 'context.add("minecraftInfo"'),
                behavior="credential_handoff_to_dynamic_stage",
                evidence="Collects username/UUID/access token into context and hands it to second-stage loader flow",
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
        contracts = sorted(set(re.findall(r"0x[a-fA-F0-9]{40}", text)))
        selectors = sorted(set(re.findall(r"0x[a-fA-F0-9]{8}", text)))
        contract_note = contracts[0] if contracts else "unknown"
        selector_note = selectors[0] if selectors else "unknown"
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "eth_call") if "eth_call" in text else find_line(text, "jsonrpc"),
                behavior="blockchain_backed_c2_bootstrap",
                evidence=f"Bootstraps remote config over Ethereum RPC (eth_call) with signature verification contract={contract_note} selector={selector_note}",
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

    if not is_vendor_lib and obfuscated_values:
        runtime_tokens = [s.lower() for s in obfuscated_values]
        has_runtime_reflect_chain = (
            "Class.forName(" in text
            and ".getMethod(" in text
            and ".invoke(" in text
            and any("java.lang.runtime" in s for s in runtime_tokens)
            and any(("getruntime" in s or "exec" in s) for s in runtime_tokens)
        )
        cmd_samples = [
            s for s in obfuscated_values if COMMAND_LITERAL_RE.search(s) or "http://" in s.lower() or "https://" in s.lower()
        ]
        if has_runtime_reflect_chain and cmd_samples:
            sample = cmd_samples[0][:120]
            sample_line = next((line for s, line, _ in obfuscated_string_pool if s == cmd_samples[0]), find_line(text, "Class.forName("))
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=sample_line,
                    behavior="command_execution_capability",
                    evidence=f"Reflective Runtime.exec chain assembled from obfuscated literals; sample={sample}",
                )
            )

    if (
        not is_vendor_lib
        and ("defineClass(" in text or "MethodHandles.lookup().defineClass(" in text or "Unsafe" in text)
        and ("Base64.getDecoder().decode(" in text or "Cipher.getInstance(" in text or "GZIPInputStream" in text or "InflaterInputStream" in text)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "defineClass("),
                behavior="dynamic_class_execution",
                evidence="Defines classes at runtime from decoded/decrypted/compressed byte streams",
            )
        )

    if (not is_vendor_lib) and "ScriptEngineManager" in text and ".eval(" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "ScriptEngineManager"),
                behavior="dynamic_class_execution",
                evidence="Uses ScriptEngine eval for dynamic code execution",
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

    if (
        has_get_access_token
        and not has_token_getter_passthrough
        and not has_internal_profile_key_usage
        and not has_token_sent_to_trusted_chain
        and not has_possible_token_exfiltration
        and not has_credential_exfil_post
    ):
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
    jars = [p for p in root.rglob("*.jar") if p.is_file() and not _is_tool_jar_name(p.name)]
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
    # For directory scans, report the directory as the primary subject.
    # JAR-level metadata is only used when explicitly scanning a JAR workflow directory.
    primary_jar = None
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
    source_jar_meta = {}
    marker = root / ".java_triage_source_jar_metadata.json"
    if marker.is_file():
        try:
            raw = json.loads(marker.read_text(encoding="utf-8", errors="replace"))
            if isinstance(raw, dict):
                source_jar_meta = raw
        except Exception:
            source_jar_meta = {}

    basic = {
        "subject": (
            str(primary_jar.relative_to(root))
            if primary_jar
            else ("cwd" if root.resolve() == Path.cwd().resolve() else (root.name or "scan"))
        ),
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
        # If this directory originated from CFR decompile of a JAR, surface its identity metadata.
        if source_jar_meta:
            basic["subject"] = str(source_jar_meta.get("name", basic["subject"]) or basic["subject"])
            basic["md5"] = str(source_jar_meta.get("md5", "") or "")
            basic["sha1"] = str(source_jar_meta.get("sha1", "") or "")
            basic["sha256"] = str(source_jar_meta.get("sha256", "") or "")
            basic["file_type"] = "JAR"
            basic["compressed"] = "jar"
            basic["magic"] = "Zip archive data (JAR)"
            try:
                sb = int(source_jar_meta.get("size_bytes", 0) or 0)
                if sb > 0:
                    basic["file_size_bytes"] = sb
                    basic["file_size_text"] = _human_size(sb)
            except Exception:
                pass

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
    artifact_identity = build_artifact_identity(root, source_jar_meta)
    library_fingerprints = fingerprint_known_libraries(root)

    return {
        "basic_properties": basic,
        "source_jar_metadata": source_jar_meta,
        "artifact_identity": artifact_identity,
        "library_fingerprints": library_fingerprints,
        "jar_info": jar_info,
        "bundle_info": bundle_info,
    }


def build_artifact_identity(root: Path, source_jar_meta: dict) -> dict:
    root_hash = hashlib.sha256()
    file_count = 0
    try:
        files = sorted([p for p in root.rglob("*") if p.is_file()], key=lambda p: str(p).lower())
        for p in files:
            rel = str(p.relative_to(root)).replace("\\", "/")
            if rel.startswith(".java_triage_source_jar_"):
                continue
            file_count += 1
            root_hash.update(rel.encode("utf-8", errors="replace"))
            root_hash.update(b"\x00")
            root_hash.update(str(int(p.stat().st_size)).encode("ascii"))
            root_hash.update(b"\x00")
            with p.open("rb") as fh:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    root_hash.update(chunk)
    except Exception:
        return {"error": "failed to compute tree identity"}
    return {
        "scan_root_name": root.name or "scan",
        "scan_root_tree_sha256": root_hash.hexdigest(),
        "scan_root_file_count": file_count,
        "source_jar": source_jar_meta or {},
    }


def fingerprint_known_libraries(root: Path) -> dict:
    counts = {k: 0 for k in KNOWN_LIBRARY_PREFIXES.keys()}
    samples = {k: [] for k in KNOWN_LIBRARY_PREFIXES.keys()}
    for p in iter_java_files(root):
        rel = str(p.relative_to(root)).replace("\\", "/").lower()
        for lib, prefixes in KNOWN_LIBRARY_PREFIXES.items():
            if any(rel.startswith(prefix) for prefix in prefixes):
                counts[lib] += 1
                if len(samples[lib]) < 5:
                    samples[lib].append(rel)
                break
    present = {
        lib: {"java_files": counts[lib], "sample_paths": samples[lib]}
        for lib in counts
        if counts[lib] > 0
    }
    return {
        "detected": sorted(present.keys()),
        "libraries": present,
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
    for rr in sorted(referenced_resources):
        p = root / Path(*rr.split("/"))
        if p.is_file():
            candidates.append(p)

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
        decoded_embedded_archive = False
        decoded_embedded_size = 0
        if referenced and p.suffix.lower() in {".txt", ".dat", ".bin", ".cfg", ".json", ""}:
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                txt = ""
            decoded = _try_decode_base32_blob(txt)
            if decoded.startswith(b"PK\x03\x04"):
                decoded_embedded_archive = True
                decoded_embedded_size = len(decoded)

        if decoded_embedded_archive:
            artifact_type = "embedded_encoded_archive_payload"
            evidence = (
                f"Referenced resource appears Base32-encoded and decodes to ZIP/JAR payload "
                f"(decoded_bytes={decoded_embedded_size}; header_hex=504B0304)"
            )
        elif ".jar." in low:
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
    raw = decode_abi_dynamic_bytes(hex_result)
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace").replace("\x00", "").strip()


def decode_abi_dynamic_bytes(hex_result: str) -> bytes:
    data = hex_result[2:] if hex_result.startswith("0x") else hex_result
    if len(data) < 64:
        return b""
    try:
        offset = int(data[:64], 16) * 2
        if offset + 64 > len(data):
            return b""
        strlen = int(data[offset : offset + 64], 16)
        payload_hex = data[offset + 64 : offset + 64 + (strlen * 2)]
        if len(payload_hex) < strlen * 2:
            return b""
        return bytes.fromhex(payload_hex)
    except Exception:
        return b""


def bytes_entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    freq = [0] * 256
    for b in raw:
        freq[b] += 1
    ent = 0.0
    for c in freq:
        if c:
            p = c / len(raw)
            ent -= p * math.log2(p)
    return ent


def analyze_runtime_payload(decoded: str, layers: List[tuple[str, str, str]], abi_raw: bytes) -> dict:
    decoded_text = (decoded or "").strip()
    low = decoded_text.lower()
    ent = bytes_entropy(abi_raw)
    printable = _mostly_printable(abi_raw) if abi_raw else False
    category = "unknown"
    encryption_likely = False
    key_inference = "unknown"
    signature_detected = False
    signature_bytes = 0
    signature_algorithm_guess = ""
    notes: List[str] = []

    # Explicitly classify "url|base64sig" runtime config as signed bootstrap data.
    if "|" in decoded_text:
        left, right = decoded_text.rsplit("|", 1)
        left = left.strip()
        right_compact = "".join(right.split())
        try:
            sig_raw = base64.b64decode(right_compact, validate=True)
            if URL_RE.match(left) and len(sig_raw) in (256, 384, 512):
                signature_detected = True
                signature_bytes = len(sig_raw)
                signature_algorithm_guess = f"RSA-{len(sig_raw) * 8} signature (likely SHA256withRSA or similar)"
                category = "signed_config_rsa_signature"
                key_inference = "no_key_needed_signature_verification_only"
                notes.append("Runtime payload is signed config (URL + RSA signature), not exfiltrated victim data.")
                return {
                    "classification": category,
                    "encryption_likely": False,
                    "key_inference": key_inference,
                    "signature_detected": signature_detected,
                    "signature_bytes": signature_bytes,
                    "signature_algorithm_guess": signature_algorithm_guess,
                    "abi_bytes": len(abi_raw),
                    "abi_entropy": round(ent, 3),
                    "abi_mostly_printable": printable,
                    "notes": notes,
                }
        except Exception:
            pass

    if decoded_text and (URL_RE.match(decoded_text) or "json" in low or "http" in low or "|" in decoded_text):
        category = "plaintext_or_structured_text"
        key_inference = "no_key_needed"
        notes.append("ABI payload decodes directly into readable text/URL structure.")
    elif decoded_text and layers:
        category = "encoded_then_decoded"
        key_inference = "no_key_needed"
        notes.append("Payload is encoded (base64/hex/base32) but decodable without a secret key.")
    elif abi_raw:
        if (not printable and ent >= 7.2) or decoded_text.startswith("<binary "):
            category = "binary_or_ciphertext_likely"
            encryption_likely = True
            key_inference = "key_likely_in_malware_or_backend_not_on_chain"
            notes.append(f"High-entropy/non-printable ABI bytes suggest encrypted or packed payload (entropy={ent:.3f}).")
        else:
            category = "binary_or_nontext"
            key_inference = "unknown"
            notes.append(f"ABI payload exists but is not clearly readable text (entropy={ent:.3f}).")
    else:
        notes.append("No decodable ABI bytes were recovered from eth_call response.")

    if any("xor_recovered" in c for c, _d, _n in layers):
        notes.append("Recovered text via XOR implies obfuscation, not strong cryptography.")
    if any(c.endswith("_decoded_binary") for c, _d, _n in layers):
        encryption_likely = encryption_likely or True
        if key_inference == "unknown":
            key_inference = "key_likely_in_malware_or_backend_not_on_chain"
        notes.append("Decoded layer remains binary/high-entropy, consistent with ciphertext or packed bytes.")

    return {
        "classification": category,
        "encryption_likely": encryption_likely,
        "key_inference": key_inference,
        "signature_detected": signature_detected,
        "signature_bytes": signature_bytes,
        "signature_algorithm_guess": signature_algorithm_guess,
        "abi_bytes": len(abi_raw),
        "abi_entropy": round(ent, 3),
        "abi_mostly_printable": printable,
        "notes": notes,
    }


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
        "raw_result_hex": "",
        "payload_analysis": {
            "classification": "unknown",
            "encryption_likely": False,
            "key_inference": "unknown",
            "signature_detected": False,
            "signature_bytes": 0,
            "signature_algorithm_guess": "",
            "abi_bytes": 0,
            "abi_entropy": 0.0,
            "abi_mostly_printable": False,
            "notes": [],
        },
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
            out["raw_result_hex"] = result_hex
            abi_raw = decode_abi_dynamic_bytes(result_hex)
            if not abi_raw:
                continue
            decoded = decode_abi_string(result_hex)
            if not decoded:
                decoded = f"<binary {len(abi_raw)} bytes>"
            out["resolved"] = True
            out["rpc_used"] = rpc
            out["decoded_response"] = decoded
            layered = decode_encoded_fragments(decoded.strip()) if not decoded.startswith("<binary ") else []
            out["decoded_response_layers"] = [
                {"category": cat, "decoded": dec, "note": note} for cat, dec, note in layered
            ]
            out["payload_analysis"] = analyze_runtime_payload(decoded, layered, abi_raw)
            c2_url = decoded.split("|", 1)[0].strip() if decoded and not decoded.startswith("<binary ") else ""
            if URL_RE.match(c2_url):
                out["c2_base_url"] = c2_url
                out["exfil_endpoint"] = f"{c2_url}/api/delivery/handler"
                out["payload_endpoint"] = f"{c2_url}/files/jar/module"
            return out
        except Exception as exc:
            out["error"] = _friendly_network_error(exc)
            continue
    if not out["resolved"] and not out["error"]:
        out["error"] = "unable to decode runtime c2 response"
    return out


def assess_network_endpoints(findings: List[Finding]) -> dict:
    urls = sorted({f.decoded for f in findings if f.category == "url" and URL_RE.match(str(f.decoded))})
    vendor: List[str] = []
    unknown: List[str] = []
    suspicious: List[str] = []
    for u in urls:
        host = urlparse(u).netloc.lower()
        if not host:
            continue
        is_ip = bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))
        if host in VENDOR_HOST_ALLOWLIST or any(host.endswith("." + d) for d in VENDOR_HOST_ALLOWLIST):
            vendor.append(u)
        elif is_ip or any(k in host for k in ["ngrok", "pastebin", "telegram", "webhook", "duckdns", "no-ip"]):
            suspicious.append(u)
        else:
            unknown.append(u)
    return {
        "total_urls": len(urls),
        "vendor_urls": vendor,
        "unknown_urls": unknown,
        "suspicious_urls": suspicious,
        "vendor_count": len(vendor),
        "unknown_count": len(unknown),
        "suspicious_count": len(suspicious),
    }


def detect_token_source_sink_behaviors(root: Path) -> List[BehaviorFinding]:
    out: List[BehaviorFinding] = []
    token_markers = [
        "accesstoken",
        "getaccesstoken",
        "method_1674",
        "func_148254_d",
        "field_1983",
        "field_148258_c",
        "refresh_token",
        "xbl",
        "session.json",
        "launcher_accounts.json",
        "getsessionid",
        "method_1675",
        "func_111286_b",
        "getclientid",
        "method_38740",
        "field_34961",
        "getxuid",
        "method_38741",
        "field_34960",
        "getaccounttype",
        "method_35718",
        "field_1984",
        "net.minecraft.client.user",
        "net.minecraft.client.session.session",
        "net.minecraft.client.util.session",
        "net.minecraft.util.session",
        "net.minecraft.class_320",
        "class_320",
        "authorization",
        "bearer ",
    ]
    sink_markers = [
        "httpurlconnection",
        "setrequestmethod(\"post\")",
        "getoutputstream(",
        ".execute(",
        "new url(",
    ]
    for p in iter_java_files(root):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        low = text.lower()
        rel = str(p.relative_to(root))
        if _is_known_library_relpath(rel):
            continue
        has_source = any(m in low for m in token_markers)
        has_sink = any(m in low for m in sink_markers)
        if has_source:
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=1,
                    behavior="capability_token_access",
                    evidence="File references session/token identity material",
                )
            )
        if has_source and has_sink:
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=1,
                    behavior="proof_token_source_to_network_sink",
                    evidence="Token/session source markers appear in same file as concrete HTTP send primitives",
                )
            )
        if "raw token" in low and ("log." in low or "logger." in low or "print" in low):
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=1,
                    behavior="proof_raw_token_logging",
                    evidence="Raw token string appears in logging/print context",
                )
            )
    return out


def detect_reachability_proof_chains(root: Path) -> List[BehaviorFinding]:
    out: List[BehaviorFinding] = []
    idx = _build_source_index(root)
    texts: dict[str, str] = idx["texts"]

    def has(marker: str) -> tuple[bool, str]:
        m = marker.lower()
        for rel, txt in texts.items():
            if _is_known_library_relpath(rel):
                continue
            if m in txt.lower():
                return True, rel
        return False, ""

    has_entry, rel_entry = has("onInitializeClient(")
    has_cmd_init, rel_cmd_init = has("CommandSystem.init(")
    has_ws_init, rel_ws_init = has("WebSocketCommandServer.init(")
    has_ws_msg, rel_ws_msg = has("onMessage(")
    has_exec_cmd, rel_exec_cmd = has("executeCommand(")
    has_account_exec, rel_acc_exec = has("AccountCommand")
    has_token, rel_token = has("method_1674(")
    if not has_token:
        has_token, rel_token = has("getAccessToken(")
    has_send = False
    rel_send = ""
    for marker in ["conn.send(", "send(", "CommandResult", "toJson(", "toString("]:
        ok, rel = has(marker)
        if ok:
            has_send = True
            rel_send = rel
            break

    if has_ws_msg and has_exec_cmd:
        out.append(
            BehaviorFinding(
                file=rel_ws_msg or rel_exec_cmd or ".",
                line=1,
                behavior="exposed_local_websocket_command_bridge",
                evidence=(
                    "Local WebSocket command bridge detected (web-origin gated control surface). "
                    "Origin checks are authorization hints, not strong authentication."
                ),
            )
        )

    if all([has_entry, has_cmd_init, has_ws_init, has_ws_msg, has_exec_cmd, has_account_exec, has_token, has_send]):
        chain = (
            "onInitializeClient -> CommandSystem.init -> WebSocketCommandServer.init -> "
            "WebSocketCommandServer.onMessage -> CommandSystem.executeCommand -> "
            "AccountCommand -> session token accessor -> command/response send"
        )
        out.append(
            BehaviorFinding(
                file=rel_entry or rel_cmd_init or rel_ws_msg or rel_exec_cmd or rel_token or ".",
                line=1,
                behavior="proof_reachable_command_token_disclosure_chain",
                evidence=f"Reachable proof chain: {chain}",
            )
        )
    return out


def _read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _build_source_index(root: Path) -> dict:
    java_files = list(iter_java_files(root))
    rel_paths = [str(p.relative_to(root)).replace("\\", "/") for p in java_files]
    texts = {rel: _read_text_safe(root / rel) for rel in rel_paths}
    simple_to_rel: dict[str, List[str]] = {}
    for rel in rel_paths:
        simple_to_rel.setdefault(Path(rel).stem, []).append(rel)
    return {"rel_paths": rel_paths, "texts": texts, "simple_to_rel": simple_to_rel}


def detect_variant_signatures(root: Path) -> dict:
    idx = _build_source_index(root)
    rel_paths: List[str] = idx["rel_paths"]
    texts: dict[str, str] = idx["texts"]
    simple_to_rel: dict[str, List[str]] = idx["simple_to_rel"]

    def has_class(name: str) -> bool:
        return name in simple_to_rel

    def any_text_contains(needle: str) -> tuple[bool, str]:
        low_n = needle.lower()
        for rel, text in texts.items():
            if low_n in text.lower():
                return True, rel
        return False, ""

    def count_package(prefix: str) -> int:
        p = prefix.lower().replace("\\", "/")
        return sum(1 for rel in rel_paths if rel.lower().startswith(p))

    def add_match(matches: list, category: str, description: str, weight: int, file_path: str = "") -> None:
        matches.append(
            {"category": category, "description": description, "weight": int(weight), "file_path": file_path}
        )

    variants: List[dict] = []

    # Weedhack-v3
    wm: List[dict] = []
    we_mal: set[str] = set()
    combo = ["ExampleMod", "Helper", "FabricAdapter", "Entrypoint", "ExampleMixin"]
    present = [c for c in combo if has_class(c)]
    if len(present) >= 3:
        add_match(wm, "signature", f"Weedhack class combination ({len(present)}/5): {', '.join(present)}", 40)
        for c in ["Helper", "FabricAdapter", "Entrypoint"]:
            for rel in simple_to_rel.get(c, []):
                we_mal.add(rel)
    if (root / "fabric.api.json").is_file() and "api_version" in _read_text_safe(root / "fabric.api.json").lower():
        add_match(wm, "signature", "fabric.api.json with 'api_version' (buyer tracking config)", 40, "fabric.api.json")
        we_mal.add("fabric.api.json")
    ok, rel = any_text_contains("Mod init state: M")
    if ok:
        add_match(wm, "string", "Debug string 'Mod init state: M'", 35, rel)
    ok, rel = any_text_contains("Resource state: S")
    if ok:
        add_match(wm, "string", "Debug string 'Resource state: S'", 35, rel)
    ok, rel = any_text_contains("SHA256withRSA")
    if ok:
        add_match(wm, "string", "RSA signature verification 'SHA256withRSA'", 30, rel)
    if wm:
        variants.append(
            {
                "variant": "Weedhack-v3",
                "confidence_score": int(sum(m["weight"] for m in wm)),
                "matches": wm,
                "malicious_entries": sorted(we_mal),
            }
        )

    # AdamRAT
    am: List[dict] = []
    ad_mal: set[str] = set()
    ok, rel = any_text_contains("vindduaptdqxujr")
    if ok:
        add_match(am, "signature", "AdamRAT string pool builder method 'vindduaptdqxujr'", 50, rel)
    ok, rel = any_text_contains("daleoxrvhs")
    if ok:
        add_match(am, "signature", "AdamRAT XOR decrypt method 'daleoxrvhs'", 50, rel)
    ok, rel = any_text_contains("ptbjqryxcd")
    if ok:
        add_match(am, "signature", "AdamRAT string pool field 'ptbjqryxcd'", 50, rel)
    if (root / "lk1gs64i84.txt").is_file():
        add_match(am, "signature", "AdamRAT buyer tracking file 'lk1gs64i84.txt'", 50, "lk1gs64i84.txt")
        ad_mal.add("lk1gs64i84.txt")
    if (root / "META-INF" / "a1b2c3d4").is_file():
        add_match(am, "signature", "AdamRAT metadata artifact 'META-INF/a1b2c3d4'", 40, "META-INF/a1b2c3d4")
        ad_mal.add("META-INF/a1b2c3d4")
    ok, rel = any_text_contains("klavs-mazins.workers.dev")
    if ok:
        add_match(am, "string", "AdamRAT C2 endpoint 'ez.klavs-mazins.workers.dev'", 50, rel)
        ad_mal.add(rel)
    if am:
        variants.append(
            {
                "variant": "AdamRAT",
                "confidence_score": int(sum(m["weight"] for m in am)),
                "matches": am,
                "malicious_entries": sorted(ad_mal),
            }
        )

    # Bambooware
    bm: List[dict] = []
    bb_mal: set[str] = set()
    enh = [r for r in rel_paths if "com/example/enhancer/" in r.lower()]
    if enh:
        add_match(bm, "signature", f"Package com/example/enhancer/ found ({len(enh)} classes)", 50, enh[0])
        bb_mal.update(enh)
    for s, w, d in [
        ("bambooware", 30, "String 'bambooware' found"),
        ("Add-MpPreference", 35, "Defender exclusion string 'Add-MpPreference'"),
        ("cmstp", 25, "UAC bypass string 'cmstp'"),
    ]:
        ok, rel = any_text_contains(s)
        if ok:
            add_match(bm, "string", d, w, rel)
    if (root / "config.json").is_file() and "userid" in _read_text_safe(root / "config.json").lower():
        add_match(bm, "signature", "config.json with 'userid' field (buyer tracking)", 30, "config.json")
        bb_mal.add("config.json")
    if bm:
        variants.append(
            {
                "variant": "Bambooware",
                "confidence_score": int(sum(m["weight"] for m in bm)),
                "matches": bm,
                "malicious_entries": sorted(bb_mal),
            }
        )

    # Curium
    cm: List[dict] = []
    cu_mal: set[str] = set()
    futils = [r for r in rel_paths if "io/github/fabricutils/" in r.lower()]
    curium_pkg = [r for r in rel_paths if "com/curium/" in r.lower()]
    if futils:
        add_match(cm, "signature", f"Curium dropper package io/github/fabricutils/ ({len(futils)} classes)", 50, futils[0])
        cu_mal.update(futils)
    if curium_pkg:
        add_match(cm, "signature", f"Curium RAT package com/curium/ ({len(curium_pkg)} classes)", 50, curium_pkg[0])
        cu_mal.update(curium_pkg)
    for s, w, d in [
        ("2f1c103b39044c312a0e", 50, "Encrypted 'curium.cfg' hex constant"),
        ("curium.su", 50, "C2 domain 'curium.su'"),
        ("[Curium]", 30, "Curium log prefix '[Curium]'"),
    ]:
        ok, rel = any_text_contains(s)
        if ok:
            add_match(cm, "string", d, w, rel)
    for res, w in [("curium.cfg", 40), ("curium.key", 30), ("A.txt", 15), ("cfg.json", 15)]:
        if (root / res).is_file():
            add_match(cm, "signature", f"Malicious resource file: {res}", w, res)
            cu_mal.add(res)
    if cm:
        variants.append(
            {
                "variant": "Curium",
                "confidence_score": int(sum(m["weight"] for m in cm)),
                "matches": cm,
                "malicious_entries": sorted(cu_mal),
            }
        )

    # DonutSMP Session Stealer
    dm: List[dict] = []
    do_mal: set[str] = set()
    donut_pkg = [r for r in rel_paths if "donut/utility/" in r.lower()]
    if donut_pkg:
        add_match(dm, "signature", f"Package donut/utility/ found ({len(donut_pkg)} classes)", 20, donut_pkg[0])
    for s, w, d in [
        ("api.donutsmp.dev", 50, "Typosquatted exfiltration domain: api.donutsmp.dev"),
        ("X-Request-Id", 30, "Suspicious exfil header X-Request-Id"),
        ("X-Forwarded-For", 30, "Suspicious exfil header X-Forwarded-For"),
        ("initializeCacheRef", 20, "Session theft trigger method: initializeCacheRef"),
        ("sendRetryRequest", 30, "Exfiltration method: sendRetryRequest"),
    ]:
        ok, rel = any_text_contains(s)
        if ok:
            add_match(dm, "signature", d, w, rel)
            if w >= 30:
                do_mal.add(rel)
    if dm:
        variants.append(
            {
                "variant": "DonutSMP Session Stealer",
                "confidence_score": int(sum(m["weight"] for m in dm)),
                "matches": dm,
                "malicious_entries": sorted(do_mal),
            }
        )

    # Microstealer
    mm: List[dict] = []
    mi_mal: set[str] = set()
    myth = [r for r in rel_paths if "qw/chudvvick/" in r.lower()]
    if myth:
        add_match(mm, "signature", f"Package qw/chudvvick/ found ({len(myth)} classes)", 60, myth[0])
        mi_mal.update(myth)
    for s, w, d in [
        ("myth-private", 50, "Maven artifact: qw.chudvvick:myth-private"),
        ("Main-Class: x", 25, "Suspicious Main-Class: x"),
        ("sun/misc/Unsafe", 15, "sun.misc.Unsafe usage"),
        ("AES/GCM/NoPadding", 15, "AES/GCM/NoPadding (Chrome credential decryption)"),
    ]:
        ok, rel = any_text_contains(s)
        if ok:
            add_match(mm, "signature", d, w, rel)
    if mm:
        variants.append(
            {
                "variant": "Microstealer",
                "confidence_score": int(sum(m["weight"] for m in mm)),
                "matches": mm,
                "malicious_entries": sorted(mi_mal),
            }
        )

    # Niggaware
    nm: List[dict] = []
    ni_mal: set[str] = set()
    loader_pkg = [r for r in rel_paths if "com/example/loader/" in r.lower()]
    if loader_pkg:
        add_match(nm, "signature", f"Package com/example/loader/ found ({len(loader_pkg)} classes)", 50, loader_pkg[0])
        ni_mal.update(loader_pkg)
    for s, w, d in [
        ("erawaggin", 50, "Reversed niggaware URL string"),
        ("DirectPlayerDetector", 20, "Thread name 'DirectPlayerDetector'"),
        ("performance-tweaks", 25, "Logger string 'performance-tweaks'"),
    ]:
        ok, rel = any_text_contains(s)
        if ok:
            add_match(nm, "signature", d, w, rel)
    for res in ["A.txt", "accid.txt"]:
        if (root / res).is_file():
            add_match(nm, "signature", f"Malicious resource file: {res}", 20, res)
            ni_mal.add(res)
    if nm:
        variants.append(
            {
                "variant": "Niggaware",
                "confidence_score": int(sum(m["weight"] for m in nm)),
                "matches": nm,
                "malicious_entries": sorted(ni_mal),
            }
        )

    # STRRAT
    sm: List[dict] = []
    st_mal: set[str] = set()
    kd = [r for r in rel_paths if "kingdavid/" in r.lower()]
    if kd:
        add_match(sm, "signature", f"Package kingDavid/ found ({len(kd)} classes)", 50, kd[0])
        st_mal.update(kd)
    for s, w, d in [
        ("kingDavid.FirstRun", 40, "Main-Class: kingDavid.FirstRun"),
        ("ALLATORIxDEMO", 35, "Allatori obfuscator signature"),
        ("api.ipify.org", 15, "External IP check: api.ipify.org"),
        ("rw-encrypt", 25, "Ransomware command rw-encrypt"),
    ]:
        ok, rel = any_text_contains(s)
        if ok:
            add_match(sm, "signature", d, w, rel)
    if sm:
        variants.append(
            {
                "variant": "STRRAT",
                "confidence_score": int(sum(m["weight"] for m in sm)),
                "matches": sm,
                "malicious_entries": sorted(st_mal),
            }
        )

    # SilentRaven
    rvm: List[dict] = []
    sr_mal: set[str] = set()
    rav = [r for r in rel_paths if "com/silentraven/" in r.lower()]
    if rav:
        add_match(rvm, "signature", f"Package com/silentraven/ found ({len(rav)} classes)", 50, rav[0])
        sr_mal.update(rav)
    for s, w, d in [
        ("api.telegram.org/bot", 35, "Telegram Bot API URL (exfil endpoint)"),
        ("[SilentRaven]", 30, "Log prefix [SilentRaven]"),
        ("Session Capture", 25, "Exfiltration format string 'Session Capture'"),
    ]:
        ok, rel = any_text_contains(s)
        if ok:
            add_match(rvm, "signature", d, w, rel)
            sr_mal.add(rel)
    if (root / "META-INF" / "Mixins Handler").is_file():
        add_match(rvm, "signature", "Encrypted payload: META-INF/Mixins Handler", 35, "META-INF/Mixins Handler")
        sr_mal.add("META-INF/Mixins Handler")
    if rvm:
        variants.append(
            {
                "variant": "SilentRaven",
                "confidence_score": int(sum(m["weight"] for m in rvm)),
                "matches": rvm,
                "malicious_entries": sorted(sr_mal),
            }
        )

    # Silentnet
    snm: List[dict] = []
    si_mal: set[str] = set()
    libmod = [r for r in rel_paths if "com/libmod/" in r.lower()]
    if libmod:
        add_match(snm, "signature", f"Package com/libmod/ found ({len(libmod)} classes)", 50, libmod[0])
        si_mal.update(libmod)
    for s, w, d in [
        ("dev.github.Main", 40, "Stage2 class reference 'dev.github.Main'"),
        ("eth_call", 25, "Ethereum RPC 'eth_call'"),
        ("jsonrpc", 20, "JSON-RPC protocol string"),
    ]:
        ok, rel = any_text_contains(s)
        if ok:
            add_match(snm, "signature", d, w, rel)
    if (root / "assets" / "libmod" / "rpchelper.dat").is_file():
        add_match(snm, "signature", "Malicious resource: assets/libmod/rpchelper.dat", 50, "assets/libmod/rpchelper.dat")
        si_mal.add("assets/libmod/rpchelper.dat")
    if (root / "lang.dat").is_file():
        add_match(snm, "signature", "Malicious resource: lang.dat", 20, "lang.dat")
        si_mal.add("lang.dat")
    if snm:
        variants.append(
            {
                "variant": "Silentnet",
                "confidence_score": int(sum(m["weight"] for m in snm)),
                "matches": snm,
                "malicious_entries": sorted(si_mal),
            }
        )

    variants = [v for v in variants if v.get("confidence_score", 0) >= 30]
    variants.sort(key=lambda x: (-int(x.get("confidence_score", 0)), x.get("variant", "")))
    return {
        "detected_count": len(variants),
        "detected": variants,
    }


def run_raw_string_scanner(root: Path) -> List[dict]:
    out: List[dict] = []
    class_files = list(root.rglob("*.class"))
    for cf in class_files:
        try:
            raw = cf.read_bytes()
            text = raw.decode("latin-1", errors="ignore")
        except Exception:
            continue
        rel = str(cf.relative_to(root)).replace("\\", "/")
        low = text.lower()
        for pattern, desc, weight in RAW_STRING_PATTERNS:
            if pattern.lower() in low:
                out.append(
                    {
                        "category": "string",
                        "description": f"[RawScan] {desc}",
                        "file_path": rel,
                        "weight": int(weight),
                        "pattern": pattern,
                    }
                )
    dedup = {(x["file_path"], x["description"]): x for x in out}
    return sorted(dedup.values(), key=lambda x: (-int(x.get("weight", 0)), x.get("file_path", "")))


def run_cross_variant_heuristics(root: Path) -> List[dict]:
    out: List[dict] = []
    for p in iter_java_files(root):
        rel = str(p.relative_to(root)).replace("\\", "/")
        t = _read_text_safe(p)
        low = t.lower()
        is_vendor_lib = _is_known_library_relpath(rel)

        def add(desc: str, weight: int) -> None:
            out.append({"category": "heuristic", "description": desc, "file_path": rel, "weight": int(weight)})

        if "extends classloader" in low:
            add("Custom ClassLoader extension", 25)
        if "defineclass(" in low:
            add("Calls defineClass (in-memory class loading)", 20)
        if "jarinputstream" in low and "bytearrayinputstream" in low:
            add("In-memory JAR loading (JarInputStream + ByteArrayInputStream)", 20)
        if any(x in low for x in ["method_1674", "method_1676", "method_44717"]):
            add("MC session theft indicators (accessToken/username/uuid refs)", 25)
        if ("getmethod(" in low or "getdeclaredmethod(" in low) and ".invoke(" in low and any(
            x in low for x in ["method_1548", "method_1674", "method_1676"]
        ):
            add("MC session theft via reflection", 30)
        if "processbuilder" in low:
            add("ProcessBuilder usage (command execution)", 10)
        if ("httpurlconnection" in low or "httpclient" in low or "urlconnection" in low) and (
            "readallbytes(" in low or "tobytearray(" in low
        ):
            add("HTTP download to byte array", 10)
        if (not is_vendor_lib) and "base64" in low:
            add("Base64 encoding/decoding", 10)
        if any(x in low for x in ["hkey_", "software\\microsoft", "reg add"]):
            add("Windows registry access", 15)
        if "powershell" in low or "pwsh" in low:
            add("PowerShell execution", 20)
        if any(x in low for x in [".vbs", ".bat", "wscript"]):
            add("Script file creation (VBS/BAT)", 15)
        if "system.load(" in low or "system.loadlibrary(" in low:
            add("Native library loading (System.load/loadLibrary)", 10)
        if "api.telegram.org/bot" in low:
            add("Telegram Bot API URL (common exfiltration channel)", 25)
        if "discord.com/api/webhooks/" in low:
            add("Discord webhook URL (common exfiltration channel)", 25)
        if (not is_vendor_lib) and any(x in low for x in ["login data", "logins.json", "key4.db", "signons.sqlite"]):
            add("Potential credential-store file access strings", 20)
        if "select" in low and any(x in low for x in ["from logins", "from cookies", "from moz_logins"]):
            add("SQL query targeting credential/cookie tables", 20)
        if any(x in low for x in ["sun/misc/unsafe", "jdk/internal/misc/unsafe"]):
            add("sun.misc.Unsafe usage (low-level JVM memory access)", 10)
        if "allatorixdemo" in low:
            add("Allatori obfuscator signature (ALLATORIxDEMO)", 15)
        if "getdeclaredfields(" in low and "setaccessible(" in low and any(
            x in low for x in ["accesstoken", "sessiontoken", "authtoken"]
        ):
            add("Field brute-force targeting token fields", 20)
        if "wmic" in low and ("csproduct" in low or "os get" in low):
            add("WMI system information extraction", 15)
        if "com/sun/jna/" in low:
            add("JNA usage for native API calls", 10)
        if any(x in low for x in ["ncrypt", "cryptunprotectdata", "ncryptopenstorageprovider"]):
            add("Windows crypto API usage (NCrypt/DPAPI)", 20)
        if (not is_vendor_lib) and "java/net/socket" in low and "getinputstream" in low and "getoutputstream" in low:
            add("Raw socket communication (potential C2 channel)", 10)
        if (not is_vendor_lib) and "java/net/http/websocket" in low:
            add("WebSocket communication capability", 10)
        if ".workers.dev" in low:
            add("Cloudflare Workers endpoint (common malware C2 platform)", 15)
        if any(x in low for x in ["prismlauncher", "atlauncher", "gdlauncher", "modrinth.theseus"]) and (
            "fileoutputstream" in low or "fileinputstream" in low
        ):
            add("Self-propagation to MC launcher directories", 25)
        if any(x in low for x in ["discord.exe", "discordcanary.exe"]) and any(
            x in low for x in ["discord_desktop_core", "index.js"]
        ):
            add("Discord token injection behavior", 25)
        if any(x in low for x in ["metamask", "phantom", "trust wallet"]):
            add("Cryptocurrency wallet data targeting", 20)
        launcher_targets = sum(
            int(x in low)
            for x in ["launcher_accounts.json", ".lunarclient", "feather", "badlion"]
        )
        if launcher_targets >= 2:
            add(f"Multi-launcher MC account theft ({launcher_targets} launchers targeted)", 20)
        if ("setwindowshookex" in low or "wh_keyboard_ll" in low) and ("user32" in low or "com/sun/jna/" in low):
            add("Native keyboard hook (keylogger via JNA/User32)", 20)

    dedup = {(x["file_path"], x["description"]): x for x in out}
    return sorted(dedup.values(), key=lambda x: (-int(x.get("weight", 0)), x.get("file_path", "")))


def _safe_extract_jar(jar_path: Path, dest: Path, max_entries: int = 20000, max_bytes: int = 300 * 1024 * 1024) -> dict:
    result = {"extracted_entries": 0, "extracted_bytes": 0, "error": ""}
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                result["error"] = f"too many entries ({len(infos)})"
                return result
            total = sum(i.file_size for i in infos if not i.is_dir())
            if total > max_bytes:
                result["error"] = f"archive too large when extracted ({total} bytes)"
                return result
            for info in infos:
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or ".." in Path(name).parts:
                    continue
                out_path = (dest / name).resolve()
                if not str(out_path).startswith(str(dest.resolve())):
                    continue
                if info.is_dir():
                    out_path.mkdir(parents=True, exist_ok=True)
                    continue
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, out_path.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
                result["extracted_entries"] += 1
                result["extracted_bytes"] += int(info.file_size)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def analyze_stage2_payload(payload_url: str, timeout: int = 20) -> dict:
    out = {
        "enabled": True,
        "attempted": False,
        "resolved_payload_url": payload_url or "",
        "static_only_no_execution": True,
        "downloaded": False,
        "download_path": "",
        "download_size": 0,
        "download_sha256": "",
        "archive_signature": "",
        "entry_count": 0,
        "class_count": 0,
        "native_entry_count": 0,
        "native_entries_sample": [],
        "extract_dir": "",
        "extract_summary": {},
        "artifact_findings": [],
        "error": "",
    }
    if not payload_url:
        out["error"] = "missing payload URL"
        return out
    out["attempted"] = True
    try:
        base_dir = Path(tempfile.mkdtemp(prefix="java_triage_stage2_")).resolve()
        jar_path = base_dir / "stage2_payload.jar"
        req = request.Request(payload_url, headers={"User-Agent": "java-triage/1.0"}, method="GET")
        with request.urlopen(req, timeout=timeout) as resp, jar_path.open("wb") as f:
            shutil.copyfileobj(resp, f, length=1024 * 1024)
        out["downloaded"] = True
        out["download_path"] = str(jar_path)
        out["download_size"] = int(jar_path.stat().st_size)
        out["download_sha256"] = sha256_file(jar_path)
        out["archive_signature"] = archive_signature_status(jar_path)

        with zipfile.ZipFile(jar_path, "r") as zf:
            names = [n.replace("\\", "/") for n in zf.namelist()]
        out["entry_count"] = len(names)
        out["class_count"] = sum(1 for n in names if n.endswith(".class"))
        native_exts = (".dll", ".so", ".dylib", ".jnilib", ".dat", ".bin")
        native_entries = [n for n in names if n.lower().endswith(native_exts)]
        out["native_entry_count"] = len(native_entries)
        out["native_entries_sample"] = native_entries[:30]

        extract_dir = base_dir / "unz"
        extract_dir.mkdir(parents=True, exist_ok=True)
        out["extract_dir"] = str(extract_dir)
        extract_summary = _safe_extract_jar(jar_path, extract_dir)
        out["extract_summary"] = extract_summary
        if extract_summary.get("error"):
            out["error"] = f"extract failed: {extract_summary.get('error')}"
            return out

        artifacts = discover_artifacts(extract_dir)
        out["artifact_findings"] = [a.__dict__ for a in artifacts]
        return out
    except Exception as exc:
        out["error"] = _friendly_network_error(exc)
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
        obf_literal_entries: List[tuple[str, int, int, str]] = []
        obf_literal_entries.extend((s, line, n, "byte_array") for s, line, n in _extract_printable_byte_array_strings(text))
        obf_literal_entries.extend((s, line, n, "char_array") for s, line, n in _extract_printable_char_array_strings(text))
        obf_literal_entries.extend((s, line, n, "reverse_stringbuilder") for s, line, n in _extract_reversed_stringbuilder_literals(text))
        seen_obf = set()
        for decoded, line, item_count, source_kind in obf_literal_entries:
            key = (decoded, line, source_kind)
            if key in seen_obf:
                continue
            seen_obf.add(key)
            function = nearest_method(decls, line)
            low = decoded.lower()
            if URL_RE.match(decoded):
                category = "url"
                signal = f"{source_kind}_url"
            elif COMMAND_LITERAL_RE.search(decoded):
                category = "dynamic_execution"
                signal = f"{source_kind}_command_or_lolbin"
            elif any(tok in low for tok in ("java.lang.runtime", "getruntime", "exec")):
                category = "dynamic_execution"
                signal = f"{source_kind}_runtime_reflection_token"
            elif any(k in low for k in SUSPICIOUS_STRING_KEYWORDS):
                category = "credential_or_identity_field" if any(k in low for k in ("token", "authorization", "api_key", "bearer ")) else "string"
                signal = f"{source_kind}_keyword_hit"
            else:
                continue
            findings.append(
                Finding(
                    file=rel,
                    line=line,
                    function=function,
                    decoded=decoded,
                    category=category,
                    note=f"source={source_kind}_scanner signal={signal} item_count={item_count}",
                )
            )
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
        seen_reconstructed = set()
        for name, rebuilt, line, parts in _reconstruct_split_string_arrays(text):
            if not URL_RE.match(rebuilt):
                continue
            if rebuilt in seen_reconstructed:
                continue
            seen_reconstructed.add(rebuilt)
            function = nearest_method(decls, line)
            findings.append(
                Finding(
                    file=rel,
                    line=line,
                    function=function,
                    decoded=rebuilt,
                    category="url",
                    note=f"source=split_string_array name={name} parts={parts}",
                )
            )
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


def behavior_verdict_tier(behavior: str) -> str:
    if behavior.startswith("proof_"):
        return "confirmed_behavior"
    if behavior.startswith("capability_") or behavior in {
        "command_execution_capability",
        "dynamic_class_execution",
        "dynamic_urlclassloader_usage",
        "remote_urlclassloader_usage",
        "exposed_local_websocket_command_bridge",
        "audio_capture_capability",
        "audio_playback_capability",
    }:
        return "exposed_capability"
    if behavior.startswith("assessment_suspicious_") or behavior.startswith("assessment_needs_review_"):
        return "suspicious_capability"
    return "suspicious_capability"


def summarize_verdict_tiers(behaviors: List[BehaviorFinding]) -> dict[str, int]:
    counts = {
        "confirmed_behavior": 0,
        "exposed_capability": 0,
        "suspicious_capability": 0,
        "library_noise": 0,
    }
    for b in behaviors:
        if _is_known_library_relpath(b.file):
            counts["library_noise"] += 1
            continue
        counts[behavior_verdict_tier(b.behavior)] += 1
    return counts


def build_contradiction_notes(behaviors: List[BehaviorFinding]) -> List[str]:
    by_behavior = {b.behavior for b in behaviors}
    notes: List[str] = []
    if "minecraft_access_token_access" in by_behavior and "proof_token_source_to_network_sink" not in by_behavior and "proof_reachable_command_token_disclosure_chain" not in by_behavior:
        notes.append("Access token is read, but no confirmed automatic token exfiltration path was proven.")
    if "exposed_local_websocket_command_bridge" in by_behavior:
        notes.append("WebSocket control surface appears local/origin-gated; treat as local command bridge, not definitive public Internet C2.")
    if "audio_playback_capability" in by_behavior and "audio_capture_capability" not in by_behavior:
        notes.append("Audio usage appears playback-only (Clip/AudioInputStream), not microphone capture.")
    return notes


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
        if f.category in {
            "url",
            "credential_or_identity_field",
            "dynamic_execution",
            "rpc_template",
            "path",
            "discord_indicator",
            "comms_indicator",
        }
    ]
    behavior_severity_counts = {k: 0 for k in ["critical", "high", "medium", "low", "info"]}
    for b in behaviors:
        behavior_severity_counts[behavior_severity(b.behavior)] += 1

    assessment_summary = summarize_assessments(behaviors)
    verdict_tiers = summarize_verdict_tiers(behaviors)
    contradiction_notes = build_contradiction_notes(behaviors)
    proof_count = sum(1 for b in behaviors if b.behavior.startswith("proof_"))
    capability_count = sum(1 for b in behaviors if b.behavior.startswith("capability_"))
    suspicion_count = int(assessment_summary["counts"].get("suspicious", 0)) + sum(
        1 for b in behaviors if behavior_severity(b.behavior) in {"critical", "high"} and not b.behavior.startswith("proof_")
    )
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
        "verdict_layers": {
            "proof": proof_count,
            "suspicion": suspicion_count,
            "capability": capability_count,
        },
        "artifact_findings": len(artifacts),
        "assessment_counts": assessment_summary["counts"],
        "verdict_tiers": verdict_tiers,
        "contradiction_notes": contradiction_notes,
    }


def extract_blockchain_indicators(findings: List[Finding]) -> dict:
    contracts = sorted(
        set(
            f.decoded
            for f in findings
            if f.category == "hex_or_contract" and re.fullmatch(r"0x[a-fA-F0-9]{40}", f.decoded or "")
        )
    )
    selectors = sorted(
        set(
            f.decoded
            for f in findings
            if f.category == "hex_or_contract" and re.fullmatch(r"0x[a-fA-F0-9]{8}", f.decoded or "")
        )
    )
    rpc_urls = sorted(
        set(
            f.decoded
            for f in findings
            if f.category == "url"
            and isinstance(f.decoded, str)
            and ("rpc" in f.decoded.lower() or "/eth" in f.decoded.lower() or "mainnet" in f.decoded.lower())
        )
    )
    rpc_hosts = sorted(
        set(urlparse(u).netloc.lower() for u in rpc_urls if urlparse(u).netloc)
    )
    api_key_urls = [u for u in rpc_urls if "api_key=" in u.lower()]
    return {
        "contracts": contracts,
        "selectors": selectors,
        "rpc_urls": rpc_urls,
        "rpc_hosts": rpc_hosts,
        "api_key_urls": api_key_urls,
    }


def render_text(
    findings: List[Finding],
    behaviors: List[BehaviorFinding],
    artifacts: List[ArtifactFinding],
    summary: dict,
    runtime_c2: dict,
    target_metadata: dict,
    stage2_analysis: dict | None = None,
    ratter_scanner: dict | None = None,
    jlab_static_scan: dict | None = None,
    network_endpoint_assessment: dict | None = None,
    variant_detections: dict | None = None,
    raw_string_detections: List[dict] | None = None,
    heuristic_detections: List[dict] | None = None,
) -> str:
    out = []
    blockchain = extract_blockchain_indicators(findings)
    basic = target_metadata.get("basic_properties", {})
    jar_info = target_metadata.get("jar_info", {})
    bundle_info = target_metadata.get("bundle_info", {})
    artifact_identity = target_metadata.get("artifact_identity", {}) or {}
    library_fingerprints = target_metadata.get("library_fingerprints", {}) or {}
    artifact_identity = target_metadata.get("artifact_identity", {}) or {}
    library_fingerprints = target_metadata.get("library_fingerprints", {}) or {}

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
    if artifact_identity:
        out.append("")
        out.append("== Artifact Identity ==")
        out.append(f"Scan root name: {artifact_identity.get('scan_root_name', '')}")
        out.append(f"Scan root tree SHA256: {artifact_identity.get('scan_root_tree_sha256', '')}")
        out.append(f"Scan root file count: {artifact_identity.get('scan_root_file_count', 0)}")
    out.append("")
    out.append("== Library Fingerprints ==")
    if library_fingerprints.get("detected"):
        for lib in library_fingerprints.get("detected", []):
            info = (library_fingerprints.get("libraries", {}) or {}).get(lib, {})
            out.append(f"- {lib}: java_files={info.get('java_files', 0)}")
    else:
        out.append("- none detected")

    assessment = summarize_assessments(behaviors)
    if findings:
        out.append("")
        out.append("== Decode + String Findings ==")
        for f in sorted(findings, key=lambda x: (x.file, x.line, x.decoded)):
            note = f" [{f.note}]" if f.note else ""
            out.append(f"[{f.category}] {f.file}:{f.line} ({f.function}) -> {f.decoded}{note}")

    has_assessment_rows = any(assessment["findings"][label] for label in ["benign", "needs_review", "suspicious"])
    if has_assessment_rows:
        out.append("")
        out.append("== Assessment Findings ==")
        for label in ["benign", "needs_review", "suspicious"]:
            entries = assessment["findings"][label]
            out.append(f"{label}: {len(entries)}")
            for item in entries:
                out.append(f"- [{item['behavior']}] {item['file']}:{item['line']} -> {item['evidence']}")

    vt = summary.get("verdict_tiers", {}) or {}
    out.append("")
    out.append("== Verdict Tiers ==")
    out.append(
        "confirmed_behavior={0} exposed_capability={1} suspicious_capability={2} library_noise={3}".format(
            vt.get("confirmed_behavior", 0),
            vt.get("exposed_capability", 0),
            vt.get("suspicious_capability", 0),
            vt.get("library_noise", 0),
        )
    )
    cn = summary.get("contradiction_notes", []) or []
    if cn:
        out.append("Contradiction / Caveat Notes:")
        for n in cn:
            out.append(f"- {n}")

    if behaviors:
        out.append("")
        out.append("== Behavioral Findings ==")
        for b in sorted(behaviors, key=lambda x: (x.file, x.line, x.behavior)):
            sev = behavior_severity(b.behavior)
            tier = behavior_verdict_tier(b.behavior)
            out.append(f"[{sev}] [{tier}] [{b.behavior}] {b.file}:{b.line} -> {b.evidence}")

    if artifacts:
        out.append("")
        out.append("== Artifact Findings ==")
        for a in artifacts:
            size_text = str(a.size) if a.size >= 0 else "unknown"
            hash_text = a.sha256 if a.sha256 else "<unknown>"
            out.append(f"[{a.artifact_type}] {a.path} filename={a.filename} size={size_text} sha256={hash_text} -> {a.evidence}")

    net = network_endpoint_assessment or {}
    out.append("")
    out.append("== Network Endpoint Assessment ==")
    out.append(
        f"Total={net.get('total_urls', 0)} vendor={net.get('vendor_count', 0)} "
        f"unknown={net.get('unknown_count', 0)} suspicious={net.get('suspicious_count', 0)}"
    )
    if net.get("suspicious_urls"):
        out.append("Suspicious URLs:")
        for u in net.get("suspicious_urls", [])[:20]:
            out.append(f"- {u}")
    if net.get("unknown_urls"):
        out.append("Unknown URLs:")
        for u in net.get("unknown_urls", [])[:20]:
            out.append(f"- {u}")

    if runtime_c2.get("attempted"):
        out.append("")
        out.append("== Runtime C2 Resolution ==")
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
            pa = runtime_c2.get("payload_analysis") or {}
            if pa:
                out.append(
                    f"Payload readability: class={pa.get('classification')} encrypted_likely={pa.get('encryption_likely')} "
                    f"key_inference={pa.get('key_inference')} signature_detected={pa.get('signature_detected')} "
                    f"signature_bytes={pa.get('signature_bytes')} abi_bytes={pa.get('abi_bytes')} entropy={pa.get('abi_entropy')}"
                )
                if pa.get("signature_detected"):
                    out.append(f"Signature detail: {pa.get('signature_algorithm_guess')}")
                for n in pa.get("notes", []) or []:
                    out.append(f"- {n}")
        else:
            out.append("Resolved: no")
            out.append(f"Error: {runtime_c2.get('error')}")

    vd = variant_detections or {}
    out.append("")
    out.append("== Variant Detections ==")
    out.append(f"Detected variants: {vd.get('detected_count', 0)}")
    for item in vd.get("detected", []) or []:
        out.append(f"- {item.get('variant')}: score={item.get('confidence_score', 0)} matches={len(item.get('matches', []))}")
    out.append("")
    out.append("== Raw String Detections ==")
    rsd = raw_string_detections or []
    out.append(f"Matches: {len(rsd)}")
    for item in rsd[:30]:
        out.append(f"- {item.get('file_path','')}: {item.get('description','')} (w={item.get('weight',0)})")
    out.append("")
    out.append("== Heuristic Detections ==")
    hd = heuristic_detections or []
    out.append(f"Matches: {len(hd)}")
    for item in hd[:30]:
        out.append(f"- {item.get('file_path','')}: {item.get('description','')} (w={item.get('weight',0)})")

    rs = ratter_scanner or {}
    if rs.get("attempted"):
        out.append("")
        out.append("== RatterScanner ==")
        if rs.get("error"):
            out.append(f"Error: {rs.get('error')}")
        else:
            rows = rs.get("results", []) or []
            out.append(f"Results: {len(rows)}")
            for item in rows:
                h = item.get("hash", "")
                safe = bool(item.get("safe", False))
                mal = bool(item.get("malicious", False))
                auto_safe = item.get("automated_safe", None)
                auto_text = f" automated_safe={auto_safe}" if auto_safe is not None else ""
                out.append(f"- {h}: safe={safe} malicious={mal}{auto_text}")

    jl = jlab_static_scan or {}
    if jl.get("attempted") or jl.get("error"):
        out.append("")
        out.append("== JLab Static Scan ==")
        out.append(f"Upload file: {jl.get('upload_file', '')}")
        out.append(f"Upload size: {jl.get('upload_size', 0)}")
        if jl.get("status_code"):
            out.append(f"HTTP status: {jl.get('status_code')}")
        if jl.get("rate_limit_limit") is not None or jl.get("rate_limit_remaining") is not None:
            out.append(
                f"Rate limit: limit={jl.get('rate_limit_limit')} remaining={jl.get('rate_limit_remaining')}"
            )
        if jl.get("retry_after") is not None:
            out.append(f"Retry after: {jl.get('retry_after')}s")
        if jl.get("error"):
            out.append(f"Error: {jl.get('error')}")
        else:
            out.append(
                f"Matched signatures: {jl.get('matched_signatures', 0)} / {jl.get('total_signatures', 0)}"
            )
            for sig in (jl.get("signatures", []) or [])[:50]:
                sev = str(sig.get("severity", "") or "")
                sig_id = str(sig.get("id", "") or "")
                name = str(sig.get("name", "") or "")
                count = int(sig.get("count", 0) or 0)
                sig_type = str(sig.get("type", "") or "")
                desc = str(sig.get("description", "") or "")
                out.append(f"- [{sev}] {name} ({sig_id}) type={sig_type} count={count} -> {desc}")
                for match in (sig.get("matches", []) or [])[:3]:
                    cls = str(match.get("className", "") or "")
                    member = str(match.get("member", "") or "")
                    if cls or member:
                        out.append(f"  match: class={cls} member={member}")


    s2 = stage2_analysis or {}
    manual_payload_url = str(runtime_c2.get("payload_endpoint", "") or "")
    if s2.get("enabled") and not s2.get("attempted"):
        out.append("")
        out.append("== Stage2 Analysis ==")
        out.append("Attempted: no")
        if manual_payload_url:
            out.append(f"Manual stage2 download URL: {manual_payload_url}")
        if s2.get("error"):
            out.append(f"Reason: {s2.get('error')}")
    elif s2.get("enabled"):
        out.append("")
        out.append("== Stage2 Analysis ==")
        out.append(f"Attempted: yes")
        out.append(f"Static-only mode: {bool(s2.get('static_only_no_execution', True))}")
        out.append(f"Payload URL: {s2.get('resolved_payload_url', '')}")
        out.append(f"Downloaded: {bool(s2.get('downloaded', False))}")
        if s2.get("downloaded"):
            out.append(f"Downloaded path: {s2.get('download_path', '')}")
            out.append(f"Downloaded size: {s2.get('download_size', 0)}")
            out.append(f"Downloaded SHA256: {s2.get('download_sha256', '')}")
            out.append(f"Archive signature: {s2.get('archive_signature', '')}")
            out.append(f"Entry count: {s2.get('entry_count', 0)}")
            out.append(f"Class count: {s2.get('class_count', 0)}")
            out.append(f"Native entry count: {s2.get('native_entry_count', 0)}")
            for item in s2.get("native_entries_sample", []) or []:
                out.append(f"- {item}")
            ext = s2.get("extract_summary", {}) or {}
            if ext:
                out.append(
                    f"Extract summary: entries={ext.get('extracted_entries', 0)} bytes={ext.get('extracted_bytes', 0)}"
                )
            s2_artifacts = s2.get("artifact_findings", []) or []
            out.append(f"Stage2 artifact findings: {len(s2_artifacts)}")
            for a in s2_artifacts:
                out.append(
                    f"- [{a.get('artifact_type')}] {a.get('path')} filename={a.get('filename')} "
                    f"size={a.get('size')} sha256={a.get('sha256')} -> {a.get('evidence')}"
                )
        if s2.get("error"):
            out.append(f"Error: {s2.get('error')}")

    if any([blockchain["contracts"], blockchain["selectors"], blockchain["rpc_hosts"], blockchain["rpc_urls"], blockchain["api_key_urls"]]):
        out.append("")
        out.append("== Blockchain Indicators ==")
        out.append(f"Contracts: {len(blockchain['contracts'])}")
        for item in blockchain["contracts"]:
            out.append(f"- {item}")
        out.append(f"Method selectors: {len(blockchain['selectors'])}")
        for item in blockchain["selectors"]:
            out.append(f"- {item}")
        out.append(f"RPC hosts: {len(blockchain['rpc_hosts'])}")
        for item in blockchain["rpc_hosts"]:
            out.append(f"- {item}")
        out.append(f"RPC URLs: {len(blockchain['rpc_urls'])}")
        for item in blockchain["rpc_urls"]:
            out.append(f"- {item}")
        if blockchain["api_key_urls"]:
            out.append("RPC URLs with API keys:")
            for item in blockchain["api_key_urls"]:
                out.append(f"- {item}")

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


def _h(text: Any) -> str:
    s = str(text if text is not None else "")
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _render_json_node_html(
    node: Any,
    title: str = "Root",
    open_all: bool = False,
    open_root: bool = True,
    expanded_titles: set[str] | None = None,
) -> str:
    if not isinstance(node, (dict, list)):
        return f"<div class='json-value'>{_h(node)}</div>"
    expanded = {str(x).strip().lower() for x in (expanded_titles or set()) if str(x).strip()}
    title_key = str(title).strip().lower()
    should_open = open_all or open_root or (title_key in expanded)
    open_attr = " open" if should_open else ""
    html = [f"<details class='json-block'{open_attr}><summary>{_h(title)}</summary><div class='json-content'>"]
    if isinstance(node, dict):
        if not node:
            html.append("<div class='json-empty'>empty</div>")
        else:
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    html.append(
                        _render_json_node_html(
                            v,
                            str(k),
                            open_all=open_all,
                            open_root=False,
                            expanded_titles=expanded_titles,
                        )
                    )
                else:
                    html.append(
                        "<div class='json-row'>"
                        f"<span class='json-key'>{_h(k)}</span>"
                        f"<span class='json-val'>{_h(v)}</span>"
                        "</div>"
                    )
    else:
        if not node:
            html.append("<div class='json-empty'>empty</div>")
        else:
            for i, v in enumerate(node):
                key = f"[{i}]"
                if isinstance(v, (dict, list)):
                    html.append(
                        _render_json_node_html(
                            v,
                            key,
                            open_all=open_all,
                            open_root=False,
                            expanded_titles=expanded_titles,
                        )
                    )
                else:
                    html.append(
                        "<div class='json-row'>"
                        f"<span class='json-key'>{_h(key)}</span>"
                        f"<span class='json-val'>{_h(v)}</span>"
                        "</div>"
                    )
    html.append("</div></details>")
    return "".join(html)


def _has_nonempty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, (list, tuple, set)):
        return len(value) > 0
    if isinstance(value, dict):
        for v in value.values():
            if _has_nonempty(v):
                return True
        return False
    return True


def render_html_report(payload: dict[str, Any], executive_summary: str = "") -> str:
    summary = payload.get("summary", {}) or {}
    target_meta = payload.get("target_metadata", {}) or {}
    target_meta_view = dict(target_meta)
    artifact_identity = target_meta_view.get("artifact_identity", {}) or {}
    source_jar_metadata = target_meta_view.get("source_jar_metadata", {}) or {}
    source_jar_from_identity = artifact_identity.get("source_jar", {}) or {}
    if source_jar_metadata and source_jar_from_identity and source_jar_metadata == source_jar_from_identity:
        target_meta_view.pop("source_jar_metadata", None)
    if artifact_identity.get("source_jar") and source_jar_metadata and artifact_identity.get("source_jar") == source_jar_metadata:
        artifact_identity = dict(artifact_identity)
        artifact_identity.pop("source_jar", None)
        target_meta_view["artifact_identity"] = artifact_identity
    basic = target_meta.get("basic_properties", {}) or {}
    findings = payload.get("findings", []) or []
    behaviors = payload.get("behavior_findings", []) or []
    artifacts = payload.get("artifact_findings", []) or []
    runtime = payload.get("runtime_c2", {}) or {}
    stage2 = payload.get("stage2_analysis", {}) or {}
    blockchain = payload.get("blockchain_indicators", {}) or {}
    ratter = payload.get("ratter_scanner", {}) or {}
    jlab = payload.get("jlab_static_scan", {}) or {}
    net_assess = payload.get("network_endpoint_assessment", {}) or {}
    variant_detections = payload.get("variant_detections", {}) or {}
    raw_string_detections = payload.get("raw_string_detections", []) or []
    heuristic_detections = payload.get("heuristic_detections", []) or []
    jar_info = target_meta.get("jar_info", {}) or {}
    bundle_info = target_meta.get("bundle_info", {}) or {}
    library_fingerprints = target_meta.get("library_fingerprints", {}) or {}
    verdict_layers = summary.get("verdict_layers", {}) or {}
    stage2_error = 1 if str((stage2 or {}).get("error", "")).strip() else 0
    blockchain_count = sum(
        len((blockchain or {}).get(k, []) or [])
        for k in ["contracts", "selectors", "rpc_urls", "rpc_hosts", "api_key_urls"]
    )
    network_bad = int((net_assess or {}).get("unknown_count", 0) or 0) + int((net_assess or {}).get("suspicious_count", 0) or 0)
    variant_count = int((variant_detections or {}).get("detected_count", 0) or 0)
    raw_count = len(raw_string_detections)
    heuristic_count = len(heuristic_detections)
    ratter_bad = sum(1 for x in (ratter.get("results", []) or []) if bool(x.get("malicious", False)))
    jlab_bad = int((jlab or {}).get("matched_signatures", 0) or 0)
    behavior_bad = int(summary.get("high_risk_behavior_count", 0) or 0)
    finding_bad = int(summary.get("high_risk_count", 0) or 0)
    artifact_bad = int(summary.get("artifact_findings", 0) or 0)
    total_bad = (
        finding_bad
        + behavior_bad
        + artifact_bad
        + network_bad
        + blockchain_count
        + variant_count
        + raw_count
        + heuristic_count
        + ratter_bad
        + jlab_bad
        + stage2_error
    )
    proof_count = int(verdict_layers.get("proof", 0) or 0)
    if proof_count >= 1 or total_bad >= 80:
        overall_label, overall_tone = "Critical", "critical"
    elif total_bad >= 40:
        overall_label, overall_tone = "High", "high"
    elif total_bad >= 15:
        overall_label, overall_tone = "Medium", "medium"
    else:
        overall_label, overall_tone = "Low", "low"

    def cat_class(cat: str) -> str:
        danger = {"url", "credential_or_identity_field", "dynamic_execution", "rpc_template", "path"}
        warn = {"discord_indicator", "comms_indicator", "crypto_primitive", "base64_blob", "hex_or_contract"}
        if cat in danger:
            return "cat-danger"
        if cat in warn:
            return "cat-warn"
        return "cat-neutral"

    def sev_class(level: str) -> str:
        low = str(level or "").strip().lower()
        if low in {"critical", "high", "medium", "low", "info"}:
            return f"sev-{low}"
        return "sev-info"

    def weight_class(weight: int) -> str:
        if weight >= 20:
            return "sev-high"
        if weight >= 10:
            return "sev-medium"
        if weight >= 1:
            return "sev-low"
        return "sev-info"

    def short_text(value: Any, limit: int = 120) -> str:
        s = str(value or "")
        return s if len(s) <= limit else (s[: max(0, limit - 1)] + "…")

    findings_limit = 200
    behavior_limit = 200
    artifact_limit = 200

    rows_find = []
    for r in findings[:1000]:
        idx = len(rows_find)
        cat = str(r.get("category", ""))
        row_class = "row-high" if cat_class(cat) == "cat-danger" else ""
        decoded_class = "decoded-high" if cat_class(cat) == "cat-danger" else ""
        hidden_attr = " style='display:none' data-findings-extra='1'" if idx >= findings_limit else ""
        rows_find.append(
            f"<tr class='{row_class}'{hidden_attr}>"
            f"<td class='tight'>{_h(r.get('file', ''))}</td>"
            f"<td class='tight'>{_h(r.get('line', ''))}</td>"
            f"<td class='func-col'>{_h(r.get('function', ''))}</td>"
            f"<td class='cat-col'><span class='cat-pill {cat_class(cat)}'>{_h(cat)}</span></td>"
            f"<td class='{decoded_class}'>{_h(r.get('decoded', ''))}</td>"
            "</tr>"
        )
    rows_beh = []
    for r in behaviors[:1000]:
        idx = len(rows_beh)
        sev = str(r.get("severity", "info") or "info").strip().lower()
        row_class = f"row-{sev}" if sev in {"critical", "high", "medium", "low", "info"} else ""
        evidence_class = "behavior-evidence-high" if sev in {"critical", "high"} else ("behavior-evidence-medium" if sev == "medium" else "")
        hidden_attr = " style='display:none' data-behavior-extra='1'" if idx >= behavior_limit else ""
        rows_beh.append(
            f"<tr class='{row_class}'{hidden_attr}>"
            f"<td class='tight'><span class='sev sev-{_h(sev)}'>{_h(sev)}</span></td>"
            f"<td class='tight'>{_h(r.get('file', ''))}</td>"
            f"<td class='tight'>{_h(r.get('line', ''))}</td>"
            f"<td>{_h(r.get('behavior', ''))}</td>"
            f"<td class='{evidence_class}'>{_h(r.get('evidence', ''))}</td>"
            "</tr>"
        )
    rows_art = []
    for r in artifacts[:1000]:
        idx = len(rows_art)
        hidden_attr = " style='display:none' data-artifact-extra='1'" if idx >= artifact_limit else ""
        rows_art.append(
            f"<tr{hidden_attr}>"
            f"<td>{_h(r.get('filename', ''))}</td>"
            f"<td>{_h(r.get('artifact_type', ''))}</td>"
            f"<td>{_h(r.get('size', ''))}</td>"
            f"<td>{_h(r.get('sha256', ''))}</td>"
            f"<td>{_h(r.get('evidence', ''))}</td>"
            "</tr>"
        )
    rows_heur = []
    for r in heuristic_detections[:1000]:
        w = int(r.get("weight", 0) or 0)
        rows_heur.append(
            "<tr>"
            f"<td class='tight'><span class='sev {weight_class(w)}'>{_h(w)}</span></td>"
            f"<td class='tight'>{_h(r.get('file_path', ''))}</td>"
            f"<td>{_h(r.get('description', ''))}</td>"
            "</tr>"
        )
    rows_jlab = []
    for sig in (jlab.get("signatures", []) or [])[:1000]:
        sev = str(sig.get("severity", "") or "").strip().lower()
        matches_preview = []
        for m in (sig.get("matches", []) or [])[:3]:
            cls = str(m.get("className", "") or "")
            member = str(m.get("member", "") or "")
            if cls or member:
                if member:
                    matches_preview.append(short_text(f"{cls}::{member}", 80))
                else:
                    matches_preview.append(short_text(cls, 80))
        matches_more = max(0, len(sig.get("matches", []) or []) - len(matches_preview))
        matches_text = " | ".join(matches_preview)
        if matches_more > 0:
            matches_text = f"{matches_text} (+{matches_more} more)" if matches_text else f"+{matches_more} more"
        rows_jlab.append(
            "<tr>"
            f"<td class='tight'><span class='sev {sev_class(sev)}'>{_h(sev or 'info')}</span></td>"
            f"<td class='tight'>{_h(sig.get('id', ''))}</td>"
            f"<td>{_h(sig.get('name', ''))}</td>"
            f"<td>{_h(sig.get('description', ''))}</td>"
            f"<td class='tight'>{_h(sig.get('type', ''))}</td>"
            f"<td class='tight'>{_h(sig.get('count', 0))}</td>"
            f"<td class='matches-col'>{_h(matches_text)}</td>"
            "</tr>"
        )

    basic_rows = []
    for k, label in [
        ("subject", "Subject"),
        ("md5", "MD5"),
        ("sha1", "SHA-1"),
        ("sha256", "SHA-256"),
        ("file_type", "File Type"),
        ("compressed", "Compressed"),
        ("magic", "Magic"),
        ("file_size_text", "File Size"),
    ]:
        val = basic.get(k, "")
        if _has_nonempty(val):
            basic_rows.append(f"<tr><td class='meta-k'>{_h(label)}</td><td class='meta-v'>{_h(val)}</td></tr>")

    jar_meta = jar_info.get("archive_metadata", {}) or {}
    jar_rows = []
    for k, label in [
        ("contained_directories", "Contained Directories"),
        ("max_directory_depth", "Max Directory Depth"),
        ("contained_files", "Contained Files"),
        ("earliest_content_modification", "Earliest Modification"),
        ("latest_content_modification", "Latest Modification"),
    ]:
        val = jar_meta.get(k, "")
        if _has_nonempty(val):
            jar_rows.append(f"<tr><td class='meta-k'>{_h(label)}</td><td class='meta-v'>{_h(val)}</td></tr>")

    bundle_rows = []
    for k, label in [
        ("contained_files", "Contained Files"),
        ("uncompressed_size_text", "Uncompressed Size"),
        ("earliest_content_modification", "Earliest Modification"),
        ("latest_content_modification", "Latest Modification"),
    ]:
        val = bundle_info.get(k, "")
        if _has_nonempty(val):
            bundle_rows.append(f"<tr><td class='meta-k'>{_h(label)}</td><td class='meta-v'>{_h(val)}</td></tr>")

    artifact_rows = []
    for k, label in [
        ("scan_root_name", "Scan Root Name"),
        ("scan_root_tree_sha256", "Scan Root Tree SHA256"),
        ("scan_root_file_count", "Scan Root File Count"),
    ]:
        val = artifact_identity.get(k, "")
        if _has_nonempty(val):
            artifact_rows.append(f"<tr><td class='meta-k'>{_h(label)}</td><td class='meta-v'>{_h(val)}</td></tr>")

    lib_rows = []
    detected_libs = library_fingerprints.get("detected", []) or []
    if detected_libs:
        libs = library_fingerprints.get("libraries", {}) or {}
        for lib in detected_libs:
            info = libs.get(lib, {}) or {}
            lib_rows.append(
                "<tr>"
                f"<td>{_h(lib)}</td>"
                f"<td class='tight'>{_h(info.get('java_files', 0))}</td>"
                f"<td>{_h(', '.join((info.get('sample_paths', []) or [])[:3]))}</td>"
                "</tr>"
            )
    jlab_overview_rows = []
    if jlab.get("attempted") or jlab.get("error"):
        for label, val in [
            ("Upload file", jlab.get("upload_file", "")),
            ("Upload size", jlab.get("upload_size", 0)),
            ("HTTP status", jlab.get("status_code", "")),
            ("Rate limit", f"limit={jlab.get('rate_limit_limit')} remaining={jlab.get('rate_limit_remaining')}"),
            ("Retry after", f"{jlab.get('retry_after')}s" if jlab.get("retry_after") is not None else ""),
            ("Matched signatures", f"{jlab.get('matched_signatures', 0)} / {jlab.get('total_signatures', 0)}"),
            ("Error", jlab.get("error", "")),
        ]:
            if _has_nonempty(val):
                jlab_overview_rows.append(f"<tr><td class='meta-k'>{_h(label)}</td><td class='meta-v'>{_h(val)}</td></tr>")

    rows_variant = []
    rows_variant_matches = []
    for item in (variant_detections.get("detected", []) or [])[:200]:
        variant_name = str(item.get("variant", "") or "")
        score = int(item.get("confidence_score", 0) or 0)
        matches = item.get("matches", []) or []
        rows_variant.append(
            "<tr>"
            f"<td>{_h(variant_name)}</td>"
            f"<td class='tight'><span class='sev {weight_class(score)}'>{_h(score)}</span></td>"
            f"<td class='tight'>{_h(len(matches))}</td>"
            "</tr>"
        )
        for m in matches[:20]:
            rows_variant_matches.append(
                "<tr>"
                f"<td>{_h(variant_name)}</td>"
                f"<td>{_h(m.get('kind', ''))}</td>"
                f"<td>{_h(short_text(m.get('description', ''), 180))}</td>"
                f"<td>{_h(m.get('file', ''))}</td>"
                f"<td class='tight'>{_h(m.get('weight', 0))}</td>"
                "</tr>"
            )

    rows_raw = []
    for r in raw_string_detections[:1000]:
        w = int(r.get("weight", 0) or 0)
        rows_raw.append(
            "<tr>"
            f"<td class='tight'><span class='sev {weight_class(w)}'>{_h(w)}</span></td>"
            f"<td class='tight'>{_h(r.get('file_path', ''))}</td>"
            f"<td>{_h(r.get('description', ''))}</td>"
            "</tr>"
        )

    runtime_rows = []
    for label, val in [
        ("Attempted", runtime.get("attempted", False)),
        ("Resolved", runtime.get("resolved", False)),
        ("RPC used", runtime.get("rpc_used", "")),
        ("C2 base URL", runtime.get("c2_base_url", "")),
        ("Exfil endpoint", runtime.get("exfil_endpoint", "")),
        ("Payload endpoint", runtime.get("payload_endpoint", "")),
        ("Error", runtime.get("error", "")),
    ]:
        if _has_nonempty(val):
            runtime_rows.append(f"<tr><td class='meta-k'>{_h(label)}</td><td class='meta-v'>{_h(val)}</td></tr>")
    rows_runtime_layers = []
    for layer in (runtime.get("decoded_response_layers", []) or [])[:50]:
        rows_runtime_layers.append(
            "<tr>"
            f"<td class='tight'>{_h(layer.get('category', ''))}</td>"
            f"<td>{_h(short_text(layer.get('decoded', ''), 160))}</td>"
            f"<td>{_h(layer.get('note', ''))}</td>"
            "</tr>"
        )

    rows_ratter = []
    for item in (ratter.get("results", []) or [])[:1000]:
        malicious = bool(item.get("malicious", False))
        safe = bool(item.get("safe", False))
        status = "malicious" if malicious else ("safe" if safe else "unknown")
        status_class = "sev-critical" if malicious else ("sev-low" if safe else "sev-info")
        rows_ratter.append(
            "<tr>"
            f"<td class='tight'><span class='sev {status_class}'>{_h(status)}</span></td>"
            f"<td>{_h(item.get('hash', ''))}</td>"
            f"<td>{_h(item.get('fileName', ''))}</td>"
            f"<td class='tight'>{_h(item.get('automated_safe', ''))}</td>"
            "</tr>"
        )
    ratter_rows = []
    if ratter.get("attempted") or ratter.get("error"):
        for label, val in [
            ("Attempted", ratter.get("attempted", False)),
            ("Error", ratter.get("error", "")),
            ("Results", len(ratter.get("results", []) or [])),
        ]:
            if _has_nonempty(val):
                ratter_rows.append(f"<tr><td class='meta-k'>{_h(label)}</td><td class='meta-v'>{_h(val)}</td></tr>")

    stage2_rows = []
    for label, val in [
        ("Enabled", stage2.get("enabled", False)),
        ("Attempted", stage2.get("attempted", False)),
        ("Static-only mode", stage2.get("static_only_no_execution", True)),
        ("Payload URL", stage2.get("resolved_payload_url", "")),
        ("Downloaded", stage2.get("downloaded", False)),
        ("Downloaded path", stage2.get("download_path", "")),
        ("Downloaded size", stage2.get("download_size", 0)),
        ("Downloaded SHA256", stage2.get("download_sha256", "")),
        ("Archive signature", stage2.get("archive_signature", "")),
        ("Entry count", stage2.get("entry_count", 0)),
        ("Class count", stage2.get("class_count", 0)),
        ("Native entry count", stage2.get("native_entry_count", 0)),
        ("Error", stage2.get("error", "")),
    ]:
        if _has_nonempty(val):
            stage2_rows.append(f"<tr><td class='meta-k'>{_h(label)}</td><td class='meta-v'>{_h(val)}</td></tr>")
    rows_stage2_native = []
    for item in (stage2.get("native_entries_sample", []) or [])[:80]:
        rows_stage2_native.append(f"<tr><td>{_h(item)}</td></tr>")
    rows_stage2_artifacts = []
    for a in (stage2.get("artifact_findings", []) or [])[:300]:
        rows_stage2_artifacts.append(
            "<tr>"
            f"<td>{_h(a.get('artifact_type', ''))}</td>"
            f"<td>{_h(a.get('path', ''))}</td>"
            f"<td>{_h(short_text(a.get('evidence', ''), 180))}</td>"
            "</tr>"
        )

    net_rows = []
    for label, val in [
        ("Total URLs", net_assess.get("total_urls", 0)),
        ("Vendor URLs", net_assess.get("vendor_count", 0)),
        ("Unknown URLs", net_assess.get("unknown_count", 0)),
        ("Suspicious URLs", net_assess.get("suspicious_count", 0)),
    ]:
        if _has_nonempty(val):
            net_rows.append(f"<tr><td class='meta-k'>{_h(label)}</td><td class='meta-v'>{_h(val)}</td></tr>")
    rows_net_suspicious = [f"<tr><td>{_h(u)}</td></tr>" for u in (net_assess.get("suspicious_urls", []) or [])[:200]]
    rows_net_unknown = [f"<tr><td>{_h(u)}</td></tr>" for u in (net_assess.get("unknown_urls", []) or [])[:200]]

    rows_blockchain = []
    for label, items in [
        ("Contracts", blockchain.get("contracts", []) or []),
        ("Method selectors", blockchain.get("selectors", []) or []),
        ("RPC hosts", blockchain.get("rpc_hosts", []) or []),
        ("RPC URLs", blockchain.get("rpc_urls", []) or []),
        ("RPC URLs with API keys", blockchain.get("api_key_urls", []) or []),
    ]:
        for item in items[:200]:
            rows_blockchain.append(f"<tr><td class='tight'>{_h(label)}</td><td>{_h(item)}</td></tr>")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Java Triage Report</title>
  <style>
    :root {{ --bg:#0a1622; --panel:#122235; --panel-soft:#193149; --text:#ebf2f8; --muted:#9eb2c5; --good:#6fd89b; --warn:#ffd166; --bad:#ff6b6b; --accent:#2ad0ff; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:"Segoe UI",Tahoma,Geneva,Verdana,sans-serif; background:radial-gradient(circle at top right,#1f3955,var(--bg) 55%); color:var(--text); min-height:100vh; }}
    .wrap {{ width:min(1300px,96vw); margin:2rem auto; }}
    .card {{ background:linear-gradient(160deg,var(--panel),var(--panel-soft)); border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:1.1rem; margin-bottom:1rem; box-shadow:0 16px 35px rgba(0,0,0,.28); }}
    h1,h2,h3 {{ margin:.2rem 0 .6rem; }}
    .triage-title {{ color:var(--accent); }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:.6rem; }}
    .metric {{ background:rgba(10,24,38,.7); border:1px solid rgba(255,255,255,.08); border-radius:10px; padding:.6rem; }}
    .label {{ color:var(--muted); font-size:.82rem; }}
    .value {{ font-size:1.15rem; font-weight:700; margin-top:.2rem; }}
    .hero {{ display:flex; justify-content:space-between; gap:1rem; flex-wrap:wrap; align-items:flex-start; }}
    .subject-card {{ margin-top:.75rem; border:1px solid rgba(255,255,255,.1); border-radius:12px; padding:.85rem 1rem; background:rgba(7,19,30,.45); }}
    .subject-name {{ font-size:1.45rem; font-weight:800; margin-top:.12rem; }}
    .subject-hash {{ margin-top:.5rem; font-family:Consolas,Monaco,monospace; color:#b9d4e7; font-size:.86rem; word-break:break-all; }}
    .risk-chip {{ padding:.32rem .7rem; border-radius:999px; font-weight:700; border:1px solid transparent; display:inline-block; }}
    .risk-critical {{ background:rgba(255,48,48,.28); border-color:rgba(255,93,93,.6); color:#ffd9d9; }}
    .risk-high {{ background:rgba(255,106,54,.24); border-color:rgba(255,140,91,.55); color:#ffe5da; }}
    .risk-medium {{ background:rgba(255,196,55,.22); border-color:rgba(255,210,102,.5); color:#fff2c9; }}
    .risk-low {{ background:rgba(63,185,120,.2); border-color:rgba(109,217,158,.45); color:#d7f4e1; }}
    .subgrid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:.5rem; margin-top:.6rem; }}
    .kpi {{ border:1px solid rgba(255,255,255,.08); border-radius:8px; padding:.5rem; background:rgba(6,16,27,.5); }}
    .kpi .k {{ color:var(--muted); font-size:.78rem; }}
    .kpi .v {{ font-weight:800; font-size:1.02rem; margin-top:.15rem; }}
    pre {{ overflow:auto; margin:0; white-space:pre-wrap; word-break:break-word; background:#0b1c2b; border-radius:10px; padding:.85rem; border:1px solid rgba(255,255,255,.06); font-size:.85rem; line-height:1.4; }}
    .table-wrap {{ overflow:auto; border:1px solid rgba(255,255,255,.08); border-radius:10px; background:rgba(8,22,35,.72); }}
    table {{ width:100%; border-collapse:collapse; font-size:.86rem; table-layout:auto; }}
    th,td {{ text-align:left; padding:.55rem; border-bottom:1px dashed rgba(255,255,255,.08); vertical-align:top; overflow-wrap:anywhere; word-break:break-word; }}
    th {{ color:#9dd5ff; font-weight:700; background:rgba(0,0,0,.18); position:sticky; top:0; }}
    th.tight,td.tight {{ white-space:nowrap; overflow-wrap:normal; word-break:normal; }}
    .smart-table tbody tr:hover td {{ background:rgba(90,160,220,.08); }}
    .smart-table tbody tr.row-high td:first-child {{ box-shadow:inset 3px 0 0 rgba(255,116,116,.85); }}
    .decoded-high {{ color:#ffd1d1; font-weight:600; }}
    .cat-pill {{ display:inline-block; padding:.15rem .5rem; border-radius:999px; font-size:.74rem; line-height:1.15; font-weight:700; border:1px solid transparent; max-width:100%; }}
    .cat-pill {{ white-space:nowrap; }}
    .cat-neutral {{ color:#d8e9f6; background:rgba(141,181,208,.14); border-color:rgba(149,194,224,.35); }}
    .cat-warn {{ color:#ffecc3; background:rgba(255,196,77,.16); border-color:rgba(255,210,120,.4); }}
    .cat-danger {{ color:#ffd4d4; background:rgba(255,91,91,.16); border-color:rgba(255,131,131,.42); }}
    .sev {{ display:inline-block; padding:.12rem .45rem; border-radius:999px; font-size:.74rem; font-weight:700; text-transform:uppercase; letter-spacing:.02em; border:1px solid transparent; }}
    .sev-critical {{ color:#ffd9d9; background:rgba(255,48,48,.28); border-color:rgba(255,93,93,.6); }}
    .sev-high {{ color:#ffe5da; background:rgba(255,106,54,.24); border-color:rgba(255,140,91,.55); }}
    .sev-medium {{ color:#fff2c9; background:rgba(255,196,55,.22); border-color:rgba(255,210,102,.5); }}
    .sev-low {{ color:#d7f4e1; background:rgba(63,185,120,.2); border-color:rgba(109,217,158,.45); }}
    .sev-info {{ color:#d9ecff; background:rgba(68,152,255,.18); border-color:rgba(120,184,255,.45); }}
    .json-block {{ background:rgba(8,22,35,.72); border:1px solid rgba(255,255,255,.08); border-radius:10px; padding:.55rem .7rem; margin-bottom:.55rem; }}
    .json-block summary {{ cursor:pointer; font-weight:700; color:var(--accent); margin-bottom:.35rem; }}
    .json-content {{ padding-left:.2rem; }}
    .json-row {{ display:grid; grid-template-columns:minmax(180px,280px) 1fr; gap:.8rem; padding:.28rem 0; border-bottom:1px dashed rgba(255,255,255,.08); }}
    .json-row:last-child {{ border-bottom:0; }}
    .json-key {{ color:#9dd5ff; font-family:Consolas,Monaco,monospace; word-break:break-word; }}
    .json-val {{ color:#e9f2fa; font-family:Consolas,Monaco,monospace; word-break:break-word; }}
    .json-empty {{ color:var(--muted); font-style:italic; padding:.2rem 0 .35rem; }}
    .findings-controls {{ margin-top:.55rem; display:flex; gap:.5rem; align-items:center; flex-wrap:wrap; }}
    .btn-link {{ display:inline-block; text-decoration:none; background:linear-gradient(120deg,#1ca4db,#58d5ff); color:#062134; border:none; border-radius:9px; padding:.45rem .75rem; font-weight:700; cursor:pointer; }}
    .table-empty {{ color:var(--muted); }}
    .findings-table col.file-col {{ width:30ch; }}
    .findings-table col.line-col {{ width:6ch; }}
    .findings-table col.func-col {{ width:18ch; }}
    .findings-table col.cat-col {{ width:16ch; }}
    .findings-table td.func-col, .findings-table th.func-col {{ white-space:nowrap; overflow-wrap:normal; word-break:normal; }}
    .findings-table td.cat-col, .findings-table th.cat-col {{ white-space:nowrap; overflow-wrap:normal; word-break:normal; }}
    .behavior-table col.sev-col {{ width:10ch; }}
    .behavior-table col.file-col {{ width:28ch; }}
    .behavior-table col.line-col {{ width:6ch; }}
    .behavior-table col.beh-col {{ width:30ch; }}
    .smart-table tbody tr.row-critical td:first-child {{ box-shadow:inset 3px 0 0 rgba(255,70,70,.92); }}
    .smart-table tbody tr.row-high td:first-child {{ box-shadow:inset 3px 0 0 rgba(255,116,116,.85); }}
    .smart-table tbody tr.row-medium td:first-child {{ box-shadow:inset 3px 0 0 rgba(255,210,102,.78); }}
    .behavior-evidence-high {{ color:#ffd6d6; font-weight:600; }}
    .behavior-evidence-medium {{ color:#ffeabf; }}
    .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:.75rem; }}
    .meta-box {{ border:1px solid rgba(255,255,255,.08); border-radius:10px; background:rgba(8,22,35,.72); padding:.65rem; }}
    .meta-box h3 {{ margin:.1rem 0 .55rem; color:#9dd5ff; }}
    .meta-table {{ width:100%; border-collapse:collapse; font-size:.86rem; }}
    .meta-table td {{ padding:.42rem .5rem; border-bottom:1px dashed rgba(255,255,255,.08); vertical-align:top; }}
    .meta-table tr:last-child td {{ border-bottom:0; }}
    .meta-k {{ color:#9dd5ff; font-family:Consolas,Monaco,monospace; width:38%; }}
    .meta-v {{ color:#edf4fb; }}
    .jlab-table col.sev-col {{ width:10ch; }}
    .jlab-table col.id-col {{ width:16ch; }}
    .jlab-table col.type-col {{ width:11ch; }}
    .jlab-table col.count-col {{ width:7ch; }}
    .jlab-table col.matches-col {{ width:48ch; }}
    .jlab-table td.matches-col {{ min-width:42ch; max-width:none; color:#a8c7df; font-size:.82rem; white-space:normal; overflow-wrap:anywhere; word-break:break-word; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="hero">
        <div>
          <h1>Java Triage Report</h1>
          <div class="label">Total adverse indicators across all categories</div>
          <div class="value">{_h(total_bad)}</div>
        </div>
        <div>
          <div class="label">Overall Assessment</div>
          <div class="risk-chip risk-{_h(overall_tone)}">{_h(overall_label)}</div>
        </div>
      </div>
      <div class="subject-card">
        <div class="label">Subject</div>
        <div class="subject-name">{_h(basic.get("subject", ""))}</div>
        {"<div class='subject-hash'>SHA256: " + _h(basic.get("sha256","")) + "</div>" if str(basic.get("sha256","")).strip() else ""}
      </div>
      <div class="grid" style="margin-top:.8rem;">
        <div class="metric"><div class="label">Total Findings</div><div class="value">{_h(summary.get("total_findings", 0))}</div></div>
        <div class="metric"><div class="label">High Risk Findings</div><div class="value">{_h(finding_bad)}</div></div>
        <div class="metric"><div class="label">High Risk Behaviors</div><div class="value">{_h(behavior_bad)}</div></div>
        <div class="metric"><div class="label">Artifact Flags</div><div class="value">{_h(artifact_bad)}</div></div>
        <div class="metric"><div class="label">Proof Layer</div><div class="value">{_h(proof_count)}</div></div>
        <div class="metric"><div class="label">Suspicion Layer</div><div class="value">{_h(verdict_layers.get("suspicion", 0))}</div></div>
        <div class="metric"><div class="label">Capability Layer</div><div class="value">{_h(verdict_layers.get("capability", 0))}</div></div>
      </div>
      <div class="subgrid">
        <div class="kpi"><div class="k">Stage2 Errors</div><div class="v">{_h(stage2_error)}</div></div>
        <div class="kpi"><div class="k">Blockchain Indicators</div><div class="v">{_h(blockchain_count)}</div></div>
        <div class="kpi"><div class="k">Network Unknown/Suspicious</div><div class="v">{_h(network_bad)}</div></div>
        <div class="kpi"><div class="k">Variant Detections</div><div class="v">{_h(variant_count)}</div></div>
        <div class="kpi"><div class="k">Raw String Detections</div><div class="v">{_h(raw_count)}</div></div>
        <div class="kpi"><div class="k">Heuristic Detections</div><div class="v">{_h(heuristic_count)}</div></div>
        <div class="kpi"><div class="k">RatterScanner Malicious</div><div class="v">{_h(ratter_bad)}</div></div>
        <div class="kpi"><div class="k">JLab Signatures</div><div class="v">{_h(jlab_bad)}</div></div>
      </div>
    </div>
    {"<div class='card'><h2>Executive Summary</h2><pre>" + _h(executive_summary) + "</pre></div>" if executive_summary else ""}
    {("<div class='card'><h2 class='triage-title'>Target Metadata</h2>"
      + "<div class='meta-grid'>"
      + ("<div class='meta-box'><h3>Basic Properties</h3><table class='meta-table'>" + "".join(basic_rows) + "</table></div>" if basic_rows else "")
      + ("<div class='meta-box'><h3>Artifact Identity</h3><table class='meta-table'>" + "".join(artifact_rows) + "</table></div>" if artifact_rows else "")
      + ("<div class='meta-box'><h3>JAR Archive Metadata</h3><table class='meta-table'>" + "".join(jar_rows) + "</table></div>" if jar_rows else "")
      + ("<div class='meta-box'><h3>Bundle Metadata</h3><table class='meta-table'>" + "".join(bundle_rows) + "</table></div>" if bundle_rows else "")
      + ("<div class='meta-box'><h3>Library Fingerprints</h3><div class='table-wrap'><table class='smart-table'><thead><tr><th>Library</th><th class='tight'>Java Files</th><th>Sample Paths</th></tr></thead><tbody>" + "".join(lib_rows) + "</tbody></table></div></div>" if lib_rows else "")
      + "</div>"
      + "</div>") if (basic_rows or artifact_rows or jar_rows or bundle_rows or lib_rows) else ""}
    {("<div class='card'><h2 class='triage-title'>Runtime C2</h2>"
      + ("<div class='meta-box'><table class='meta-table'>" + "".join(runtime_rows) + "</table></div>" if runtime_rows else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th class='tight'>Layer Type</th><th>Decoded</th><th>Note</th></tr></thead><tbody>" + "".join(rows_runtime_layers) + "</tbody></table></div>" if rows_runtime_layers else "")
      + "</div>") if (runtime_rows or rows_runtime_layers) else ""}
    {("<div class='card'><h2 class='triage-title'>RatterScanner</h2>"
      + ("<div class='meta-box'><table class='meta-table'>" + "".join(ratter_rows) + "</table></div>" if ratter_rows else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th class='tight'>Status</th><th>Hash</th><th>File</th><th class='tight'>Automated Safe</th></tr></thead><tbody>" + "".join(rows_ratter) + "</tbody></table></div>" if rows_ratter else "")
      + "</div>") if (ratter_rows or rows_ratter) else ""}
    {("<div class='card'><h2 class='triage-title'>JLab Static Scan</h2>"
      + ("<div class='meta-box'><table class='meta-table'>" + "".join(jlab_overview_rows) + "</table></div>" if jlab_overview_rows else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table jlab-table'><colgroup><col class='sev-col'><col class='id-col'><col><col><col class='type-col'><col class='count-col'><col class='matches-col'></colgroup><thead><tr><th class='tight'>Severity</th><th class='tight'>ID</th><th>Name</th><th>Description</th><th class='tight'>Type</th><th class='tight'>Count</th><th>Matches (preview)</th></tr></thead><tbody>" + "".join(rows_jlab) + "</tbody></table></div>" if rows_jlab else "")
      + "</div>") if (jlab_overview_rows or rows_jlab) else ""}
    {("<div class='card'><h2 class='triage-title'>Stage2 Analysis</h2>"
      + ("<div class='meta-box'><table class='meta-table'>" + "".join(stage2_rows) + "</table></div>" if stage2_rows else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Native Entry (sample)</th></tr></thead><tbody>" + "".join(rows_stage2_native) + "</tbody></table></div>" if rows_stage2_native else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Type</th><th>Path</th><th>Evidence</th></tr></thead><tbody>" + "".join(rows_stage2_artifacts) + "</tbody></table></div>" if rows_stage2_artifacts else "")
      + "</div>") if (stage2_rows or rows_stage2_native or rows_stage2_artifacts) else ""}
    {("<div class='card'><h2 class='triage-title'>Blockchain Indicators</h2>"
      "<div class='table-wrap'><table class='smart-table'><thead><tr><th class='tight'>Indicator Type</th><th>Value</th></tr></thead><tbody>"
      + "".join(rows_blockchain) + "</tbody></table></div>"
      + "</div>") if rows_blockchain else ""}
    {("<div class='card'><h2 class='triage-title'>Network Endpoint Assessment</h2>"
      + ("<div class='meta-box'><table class='meta-table'>" + "".join(net_rows) + "</table></div>" if net_rows else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Suspicious URLs</th></tr></thead><tbody>" + "".join(rows_net_suspicious) + "</tbody></table></div>" if rows_net_suspicious else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Unknown URLs</th></tr></thead><tbody>" + "".join(rows_net_unknown) + "</tbody></table></div>" if rows_net_unknown else "")
      + "</div>") if (net_rows or rows_net_suspicious or rows_net_unknown) else ""}
    {("<div class='card'><h2 class='triage-title'>Variant Detections</h2>"
      + ("<div class='table-wrap'><table class='smart-table'><thead><tr><th>Variant</th><th class='tight'>Confidence</th><th class='tight'>Matches</th></tr></thead><tbody>" + "".join(rows_variant) + "</tbody></table></div>" if rows_variant else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Variant</th><th>Kind</th><th>Description</th><th>File</th><th class='tight'>Weight</th></tr></thead><tbody>" + "".join(rows_variant_matches) + "</tbody></table></div>" if rows_variant_matches else "")
      + "</div>") if (rows_variant or rows_variant_matches) else ""}
    {("<div class='card'><h2 class='triage-title'>Raw String Detections</h2>"
      "<div class='table-wrap'><table class='smart-table'><thead><tr><th class='tight'>Weight</th><th class='tight'>File</th><th>Description</th></tr></thead><tbody>"
      + "".join(rows_raw) + "</tbody></table></div>"
      + "</div>") if rows_raw else ""}
    {("<div class='card'><h2 class='triage-title'>Heuristic Detections</h2>"
      "<div class='table-wrap'><table class='smart-table'><thead><tr><th class='tight'>Weight</th><th class='tight'>File</th><th>Description</th></tr></thead><tbody>"
      + "".join(rows_heur) + "</tbody></table></div>"
      + "</div>") if rows_heur else ""}
    {("<div class='card'><h2 class='triage-title'>Decoded Findings</h2>"
      "<div class='table-wrap'><table class='smart-table findings-table'><colgroup><col class='file-col'><col class='line-col'><col class='func-col'><col class='cat-col'><col></colgroup><thead><tr><th class='tight'>File</th><th class='tight'>Line</th><th class='func-col'>Function</th><th class='cat-col'>Category</th><th>Decoded</th></tr></thead><tbody>"
      + "".join(rows_find) + "</tbody></table></div>"
      + ("<div class='findings-controls' data-findings-controls='1' data-kind='findings' data-limit='200' data-step='200'><button type='button' class='btn-link findings-more-btn'>Show 200 more</button><button type='button' class='btn-link findings-all-btn'>Show all</button><div class='table-empty findings-toggle-status'>Showing first 200 of " + _h(len(rows_find)) + " rows.</div></div>" if len(rows_find) > findings_limit else "")
      + "</div>") if rows_find else ""}
    {("<div class='card'><h2 class='triage-title'>Behavior Indicators</h2>"
      "<div class='table-wrap'><table class='smart-table behavior-table'><colgroup><col class='sev-col'><col class='file-col'><col class='line-col'><col class='beh-col'><col></colgroup><thead><tr><th class='tight'>Severity</th><th class='tight'>File</th><th class='tight'>Line</th><th>Behavior</th><th>Evidence</th></tr></thead><tbody>"
      + "".join(rows_beh) + "</tbody></table></div>"
      + ("<div class='findings-controls' data-findings-controls='1' data-kind='behavior' data-limit='200' data-step='200'><button type='button' class='btn-link findings-more-btn'>Show 200 more</button><button type='button' class='btn-link findings-all-btn'>Show all</button><div class='table-empty findings-toggle-status'>Showing first 200 of " + _h(len(rows_beh)) + " rows.</div></div>" if len(rows_beh) > behavior_limit else "")
      + "</div>") if rows_beh else ""}
    {("<div class='card'><h2 class='triage-title'>Artifact Indicators</h2>"
      "<div class='table-wrap'><table class='smart-table'><thead><tr><th>Name</th><th>Type</th><th class='tight'>Size</th><th>SHA256</th><th>Evidence</th></tr></thead><tbody>"
      + "".join(rows_art) + "</tbody></table></div>"
      + ("<div class='findings-controls' data-findings-controls='1' data-kind='artifact' data-limit='200' data-step='200'><button type='button' class='btn-link findings-more-btn'>Show 200 more</button><button type='button' class='btn-link findings-all-btn'>Show all</button><div class='table-empty findings-toggle-status'>Showing first 200 of " + _h(len(rows_art)) + " rows.</div></div>" if len(rows_art) > artifact_limit else "")
      + "</div>") if rows_art else ""}
  </div>
  <script>
  (function () {{
    var selectors = {{ findings: "tr[data-findings-extra='1']", behavior: "tr[data-behavior-extra='1']", artifact: "tr[data-artifact-extra='1']" }};
    document.querySelectorAll("[data-findings-controls='1']").forEach(function (ctrl) {{
      var kind = ctrl.getAttribute("data-kind") || "findings";
      var limit = parseInt(ctrl.getAttribute("data-limit") || "200", 10);
      var step = parseInt(ctrl.getAttribute("data-step") || "200", 10);
      var rows = Array.prototype.slice.call(document.querySelectorAll(selectors[kind] || selectors.findings));
      var shown = limit;
      var moreBtn = ctrl.querySelector(".findings-more-btn");
      var allBtn = ctrl.querySelector(".findings-all-btn");
      var status = ctrl.querySelector(".findings-toggle-status");
      function apply(count) {{
        shown = count;
        rows.forEach(function (row, idx) {{ row.style.display = idx < Math.max(0, shown - limit) ? "" : "none"; }});
        var visible = Math.min(rows.length + limit, shown);
        if (status) status.textContent = "Showing first " + Math.min(visible, rows.length + limit) + " of " + (rows.length + limit) + " rows.";
        if (moreBtn) moreBtn.style.display = visible >= (rows.length + limit) ? "none" : "";
        if (allBtn) allBtn.style.display = visible >= (rows.length + limit) ? "none" : "";
      }}
      if (moreBtn) moreBtn.addEventListener("click", function () {{ apply(shown + step); }});
      if (allBtn) allBtn.addEventListener("click", function () {{ apply(rows.length + limit); }});
      apply(limit);
    }});
  }})();
  </script>
</body>
</html>"""


def resolve_target(raw_target: str) -> Path:
    # On Windows shells users often pass "/" expecting "current folder".
    # Keep that behavior explicit to avoid scanning an entire drive root.
    if raw_target in {"/", "\\", "cwd"}:
        return Path.cwd().resolve()
    return Path(raw_target).resolve()


def _prompt_select_jar(candidates: List[Path], console=None) -> Path | None:
    if RICH_AVAILABLE:
        ui_console = console or Console(stderr=True, width=_triage_ui_width())
        width = _triage_ui_width(ui_console)
        table = Table(box=box.SIMPLE, show_edge=False, expand=False, padding=(0, 1))
        table.width = width - 4
        table.add_column("#", style="bold #C000FF", no_wrap=True)
        table.add_column("JAR", style="bold white", overflow="fold")
        for idx, jar in enumerate(candidates, start=1):
            table.add_row(str(idx), jar.name)
        table.add_row("0", "Cancel")
        ui_console.print(
            Panel(
                table,
                border_style="#C000FF",
                width=width,
            )
        )
    else:
        print("Multiple JAR files found. Pick one to scan:", file=sys.stderr)
        for idx, jar in enumerate(candidates, start=1):
            print(f"  {idx}. {jar.name}", file=sys.stderr)
        print("  0. Cancel", file=sys.stderr)

    while True:
        print("Select JAR number to decompile and scan: ", end="", file=sys.stderr, flush=True)
        try:
            raw = input().strip()
        except (EOFError, KeyboardInterrupt):
            print("", file=sys.stderr)
            return None
        if not raw:
            print("Selection required. Enter a number.", file=sys.stderr)
            continue
        if not raw.isdigit():
            print("Invalid selection. Enter a numeric choice.", file=sys.stderr)
            continue
        choice = int(raw)
        if choice == 0:
            print("", file=sys.stderr)
            return None
        if 1 <= choice <= len(candidates):
            print("", file=sys.stderr)
            return candidates[choice - 1]
        print(f"Invalid selection. Enter 0-{len(candidates)}.", file=sys.stderr)


def maybe_prepare_cwd_jar_scan_root(initial_root: Path, show_progress: bool, progress_console=None) -> Path:
    cwd = Path.cwd().resolve()
    if initial_root != cwd:
        return initial_root

    cfr = _find_cfr_jar(cwd)
    if cfr is None:
        return initial_root

    jar_candidates = sorted(
        [
            p
            for p in cwd.glob("*.jar")
            if p.is_file()
            and not _is_tool_jar_name(p.name)
            and not p.name.lower().endswith("_droppedjar.jar")
        ],
        key=lambda p: p.name.lower(),
    )
    if not jar_candidates:
        return initial_root

    selected: Path | None
    if len(jar_candidates) == 1:
        selected = jar_candidates[0]
    else:
        if not sys.stdin.isatty():
            progress(
                show_progress,
                "multiple JAR files found but stdin is not interactive; skipping JAR selection",
                progress_console,
            )
            return initial_root
        selected = _prompt_select_jar(jar_candidates, progress_console)
        if selected is None:
            print("JAR selection cancelled. Continuing with current target.", file=sys.stderr)
            return initial_root

    out_dir = (cwd / selected.stem).resolve()
    if out_dir.exists():
        if not out_dir.is_dir():
            print(f"error: output path exists and is not a directory: {out_dir}", file=sys.stderr)
            return initial_root
        progress(
            show_progress,
            f"reusing existing extracted directory for {selected.name}: {_display_report_path(out_dir, cwd)}",
            progress_console,
        )
        return out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    cp = _run_subprocess_with_progress(
        ["java", "-jar", str(cfr), str(selected), "--outputdir", str(out_dir)],
        f"CFR decompiling {selected.name}",
        show_progress,
        progress_console,
    )
    if cp.returncode != 0:
        err = (cp.stderr or cp.stdout or "").strip()
        print(f"error: CFR decompilation failed for {selected.name}", file=sys.stderr)
        if err:
            print(err, file=sys.stderr)
        return initial_root

    if not any(out_dir.rglob("*.java")):
        print(f"error: CFR did not produce Java source in {out_dir}", file=sys.stderr)
        return initial_root
    _write_source_jar_metadata(out_dir, selected)

    return out_dir


def resolve_jlab_upload_target(initial_target: Path, scan_root: Path, target_metadata: dict) -> tuple[Path | None, str]:
    def _is_jar_or_zip(path: Path) -> bool:
        return path.is_file() and path.suffix.lower() in {".jar", ".zip"}

    if _is_jar_or_zip(initial_target):
        return initial_target, "initial target file"
    if _is_jar_or_zip(scan_root):
        return scan_root, "scan root file"

    source_jar_meta = (target_metadata or {}).get("source_jar_metadata", {}) or {}
    source_name = str(source_jar_meta.get("name", "") or "").strip()
    source_path_raw = str(source_jar_meta.get("path", "") or "").strip()
    expected_size = int(source_jar_meta.get("size_bytes", 0) or 0)
    expected_sha256 = str(source_jar_meta.get("sha256", "") or "").strip().lower()

    if source_path_raw:
        direct = Path(source_path_raw)
        if _is_jar_or_zip(direct):
            return direct, "source metadata path"

    candidates: List[Path] = []
    if source_name:
        roots_to_check = [initial_target.parent, scan_root.parent, Path.cwd().resolve()]
        seen_roots: set[str] = set()
        for root in roots_to_check:
            try:
                root_resolved = root.resolve()
            except Exception:
                root_resolved = root
            key = str(root_resolved)
            if key in seen_roots:
                continue
            seen_roots.add(key)
            cand = root_resolved / source_name
            if _is_jar_or_zip(cand):
                candidates.append(cand)

    if not candidates:
        basic = (target_metadata or {}).get("basic_properties", {}) or {}
        subject = str(basic.get("subject", "") or "").strip()
        if subject and subject.lower().endswith((".jar", ".zip")):
            fallback = Path.cwd().resolve() / subject
            if _is_jar_or_zip(fallback):
                candidates.append(fallback)

    if not candidates:
        return None, "unable to locate source JAR/ZIP for upload"

    for cand in candidates:
        try:
            if expected_size and int(cand.stat().st_size) != expected_size:
                continue
            if expected_sha256:
                if _hash_file(cand, "sha256").lower() != expected_sha256:
                    continue
            return cand, "matched source metadata"
        except Exception:
            continue

    # If metadata match failed, still allow first candidate by filename for best-effort scan.
    return candidates[0], "best-effort filename match"


def progress(enabled: bool, message: str, console=None) -> None:
    if enabled:
        msg = f"• {message}"
        if RICH_AVAILABLE and console is not None:
            console.print(msg, style="bold white", highlight=False)
        else:
            print(msg, file=sys.stderr, flush=True)


def _triage_ui_width(console=None) -> int:
    try:
        if RICH_AVAILABLE and console is not None:
            width = getattr(console, "width", None)
            if not width:
                size = getattr(console, "size", None)
                width = getattr(size, "width", 120) if size else 120
            return max(60, min(120, int(width) - 2))
    except Exception:
        pass
    return max(60, min(120, shutil.get_terminal_size((120, 20)).columns - 2))


def _print_section(console, title: str) -> None:
    console.print()
    console.print(Rule(Text(title, style="bold white"), style="#C000FF"))


def _print_scan_beginning(console=None) -> None:
    if RICH_AVAILABLE and console is not None:
        console.print()
        console.print("[bold #C000FF]Scan beginning[/bold #C000FF]")
        console.print(Rule(style="#C000FF"))
        console.print()
    else:
        print("", file=sys.stderr)
        print("Scan beginning", file=sys.stderr)
        print("=" * 48, file=sys.stderr)
        print("", file=sys.stderr)


def _lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


def make_multi_gradient(stops: List[tuple[int, int, int]], steps: int) -> List[tuple[int, int, int]]:
    if steps <= 1:
        return [stops[0]]
    segs = len(stops) - 1
    out: List[tuple[int, int, int]] = []
    for i in range(steps):
        pos = i * segs / (steps - 1)
        idx = int(pos)
        if idx >= segs:
            idx = segs - 1
            t = 1.0
        else:
            t = pos - idx
        r = _lerp(stops[idx][0], stops[idx + 1][0], t)
        g = _lerp(stops[idx][1], stops[idx + 1][1], t)
        b = _lerp(stops[idx][2], stops[idx + 1][2], t)
        out.append((r, g, b))
    return out


def _gradient_banner_text(width: int) -> str:
    lines = BANNER.splitlines()
    stops = [
        (85, 0, 145),
        (122, 87, 176),
        (199, 162, 255),
    ]
    colors = make_multi_gradient(stops, max(1, len(lines)))
    out: List[str] = []
    for line, (r, g, b) in zip(lines, colors):
        out.append(f"\033[38;2;{r};{g};{b}m{line.center(width)}\033[0m")
    return "\n".join(out)


def print_banner(console=None, to_stderr: bool = False) -> None:
    try:
        os.system("")
    except Exception:
        pass
    width = _triage_ui_width(console)
    rendered = _gradient_banner_text(width)
    if RICH_AVAILABLE and console is not None:
        console.print(Text.from_ansi(rendered), highlight=False)
    else:
        stream = sys.stderr if to_stderr else sys.stdout
        print(rendered, file=stream)


def _unlink_existing_result(path: Path | None, show_progress: bool, progress_console=None) -> None:
    if path is None or not path.exists():
        return
    try:
        path.unlink()
        progress(
            show_progress,
            f"removed old result: {_display_report_path(path, Path.cwd().resolve())}",
            progress_console,
        )
    except Exception as exc:
        progress(
            show_progress,
            f"warning: failed to remove old result {_display_report_path(path, Path.cwd().resolve())}: {exc}",
            progress_console,
        )


def _prompt_existing_scan_result(json_path: Path, html_path: Path | None, progress_console=None) -> str:
    html_status = "disabled"
    if html_path is not None:
        html_status = "exists" if html_path.exists() else "missing"

    if RICH_AVAILABLE:
        ui_console = progress_console or Console(stderr=True, width=_triage_ui_width())
        width = _triage_ui_width(ui_console)
        table = Table(box=box.SIMPLE, show_edge=False, expand=False, padding=(0, 1))
        table.width = width - 4
        table.add_column("Item", style="#C000FF", no_wrap=True)
        table.add_column("Status", style="bold white", no_wrap=True)
        table.add_column("Path", style="white", overflow="fold")
        table.add_row("JSON", "exists", _display_report_path(json_path, Path.cwd().resolve()))
        if html_path is not None:
            table.add_row("HTML", html_status, _display_report_path(html_path, Path.cwd().resolve()))
        ui_console.print("\n[bold #C000FF]Existing scan result found[/bold #C000FF]")
        ui_console.print(
            Panel(
                table,
                border_style="#C000FF",
                width=width,
            )
        )
    else:
        print(f"Existing JSON result found: {_display_report_path(json_path, Path.cwd().resolve())}", file=sys.stderr)
        if html_path is not None:
            print(
                f"Existing HTML result status: {html_status} ({_display_report_path(html_path, Path.cwd().resolve())})",
                file=sys.stderr,
            )

    while True:
        print("Rescan and overwrite previous result? [R]escan / [U]se existing / [C]ancel: ", end="", file=sys.stderr, flush=True)
        try:
            raw = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("", file=sys.stderr)
            return "cancel"
        if raw in {"", "u", "use", "reuse", "existing"}:
            return "reuse"
        if raw in {"r", "rescan", "overwrite", "yes", "y"}:
            return "rescan"
        if raw in {"c", "cancel", "q", "quit", "no", "n"}:
            return "cancel"
        print("Invalid selection. Enter R, U, or C.", file=sys.stderr)


def render_rich(
    console,
    findings: List[Finding],
    behaviors: List[BehaviorFinding],
    artifacts: List[ArtifactFinding],
    summary: dict,
    runtime_c2: dict,
    target_metadata: dict,
    stage2_analysis: dict | None = None,
    ratter_scanner: dict | None = None,
    jlab_static_scan: dict | None = None,
    network_endpoint_assessment: dict | None = None,
    variant_detections: dict | None = None,
    raw_string_detections: List[dict] | None = None,
    heuristic_detections: List[dict] | None = None,
    executive_summary: str = "",
) -> None:
    def short(s: str, n: int = 220) -> str:
        return s if len(s) <= n else s[: n - 1] + "…"

    assessment = summarize_assessments(behaviors)
    blockchain = extract_blockchain_indicators(findings)
    basic = target_metadata.get("basic_properties", {})
    jar_info = target_metadata.get("jar_info", {})
    bundle_info = target_metadata.get("bundle_info", {})
    artifact_identity = target_metadata.get("artifact_identity", {}) or {}
    library_fingerprints = target_metadata.get("library_fingerprints", {}) or {}

    _print_section(console, "Basic Properties")
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

    _print_section(console, "JAR Info")
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

    _print_section(console, "Bundle Info")
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
    _print_section(console, "Artifact Identity")
    ai = Table(show_header=False, box=box.SIMPLE)
    ai.add_row("Scan Root Name", str(artifact_identity.get("scan_root_name", "")))
    ai.add_row("Scan Root Tree SHA256", str(artifact_identity.get("scan_root_tree_sha256", "")))
    ai.add_row("Scan Root File Count", str(artifact_identity.get("scan_root_file_count", 0)))
    console.print(ai)
    _print_section(console, "Library Fingerprints")
    lt = Table(show_header=True, box=box.SIMPLE)
    lt.add_column("Library")
    lt.add_column("Java Files", justify="right")
    detected_libs = library_fingerprints.get("detected", []) or []
    if detected_libs:
        for lib in detected_libs:
            info = (library_fingerprints.get("libraries", {}) or {}).get(lib, {})
            lt.add_row(str(lib), str(info.get("java_files", 0)))
    else:
        lt.add_row("none", "0")
    console.print(lt)

    if findings:
        _print_section(console, "Decode + String Findings")
        t = Table(show_lines=False, expand=True)
        t.add_column("Category", style="magenta", max_width=22, no_wrap=True, overflow="ellipsis")
        t.add_column("Location", style="cyan", overflow="fold")
        t.add_column("Function", style="green")
        t.add_column("Decoded", style="white", overflow="fold")
        for f in sorted(findings, key=lambda x: (x.file, x.line, x.decoded)):
            decoded = f.decoded if not f.note else f"{f.decoded} [{f.note}]"
            t.add_row(f.category, f"{f.file}:{f.line}", f.function, decoded)
        console.print(t)

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
        _print_section(console, "Assessment Findings")
        console.print(at)

    if behaviors:
        _print_section(console, "Behavioral Findings")
        t = Table(show_lines=False, box=box.SIMPLE, expand=True)
        t.add_column("Risk", style="red")
        t.add_column("Behavior", style="yellow")
        t.add_column("Location", style="cyan", overflow="fold")
        t.add_column("Evidence", style="white", overflow="fold")
        for b in sorted(behaviors, key=lambda x: (x.file, x.line, x.behavior)):
            t.add_row(behavior_severity(b.behavior), b.behavior, f"{b.file}:{b.line}", short(b.evidence))
        console.print(t)

    if artifacts:
        _print_section(console, "Artifact Findings")
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

    net = network_endpoint_assessment or {}
    _print_section(console, "Network Endpoint Assessment")
    nt = Table(show_header=False, box=box.SIMPLE)
    nt.add_row("Total URLs", str(net.get("total_urls", 0)))
    nt.add_row("Vendor URLs", str(net.get("vendor_count", 0)))
    nt.add_row("Unknown URLs", str(net.get("unknown_count", 0)))
    nt.add_row("Suspicious URLs", str(net.get("suspicious_count", 0)))
    console.print(nt)
    if net.get("suspicious_urls"):
        st = Table(title="Suspicious URLs", show_header=True, box=box.SIMPLE)
        st.add_column("URL")
        for u in net.get("suspicious_urls", [])[:20]:
            st.add_row(str(u))
        console.print(st)

    if runtime_c2.get("attempted"):
        _print_section(console, "Runtime C2 Resolution")
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
            pa = runtime_c2.get("payload_analysis") or {}
            if pa:
                console.print(
                    f"Payload readability: class={pa.get('classification')} encrypted_likely={pa.get('encryption_likely')} "
                    f"key_inference={pa.get('key_inference')} signature_detected={pa.get('signature_detected')} "
                    f"signature_bytes={pa.get('signature_bytes')} abi_bytes={pa.get('abi_bytes')} entropy={pa.get('abi_entropy')}",
                    markup=False,
                )
                if pa.get("signature_detected"):
                    console.print(f"Signature detail: {pa.get('signature_algorithm_guess')}", markup=False)
                for n in pa.get("notes", []) or []:
                    console.print(f"- {n}", markup=False)
        else:
            console.print("[red]Resolved:[/red] no")
            console.print(f"Error: {runtime_c2.get('error')}")

    vd = variant_detections or {}
    _print_section(console, "Variant Detections")
    vdt = Table(show_header=True, box=box.SIMPLE)
    vdt.add_column("Variant")
    vdt.add_column("Score", justify="right")
    vdt.add_column("Matches", justify="right")
    detected = vd.get("detected", []) or []
    if detected:
        for item in detected:
            vdt.add_row(str(item.get("variant", "")), str(item.get("confidence_score", 0)), str(len(item.get("matches", []) or [])))
    else:
        vdt.add_row("none", "0", "0")
    console.print(vdt)
    _print_section(console, "Raw String Detections")
    rsd = raw_string_detections or []
    rst = Table(show_header=True, box=box.SIMPLE)
    rst.add_column("Weight", justify="right")
    rst.add_column("File")
    rst.add_column("Description")
    if rsd:
        for item in rsd[:60]:
            rst.add_row(str(item.get("weight", 0)), str(item.get("file_path", "")), str(item.get("description", "")))
    else:
        rst.add_row("0", "-", "none")
    console.print(rst)
    _print_section(console, "Heuristic Detections")
    hd = heuristic_detections or []
    hdt = Table(show_header=True, box=box.SIMPLE)
    hdt.add_column("Weight", justify="right")
    hdt.add_column("File")
    hdt.add_column("Description")
    if hd:
        for item in hd[:60]:
            hdt.add_row(str(item.get("weight", 0)), str(item.get("file_path", "")), str(item.get("description", "")))
    else:
        hdt.add_row("0", "-", "none")
    console.print(hdt)

    rs = ratter_scanner or {}
    if rs.get("attempted"):
        _print_section(console, "RatterScanner")
        if rs.get("error"):
            console.print(f"[red]Error:[/red] {rs.get('error')}")
        else:
            tr = Table(show_lines=False, box=box.SIMPLE, expand=True)
            tr.add_column("Hash", style="white")
            tr.add_column("Safe", style="green")
            tr.add_column("Automated Safe", style="cyan")
            tr.add_column("Malicious", style="red")
            tr.add_column("File", style="yellow")
            for item in rs.get("results", []) or []:
                safe_val = bool(item.get("safe", False))
                malicious_val = bool(item.get("malicious", False))
                automated_safe_raw = item.get("automated_safe", None)
                unknown_triplet = (
                    safe_val is False
                    and malicious_val is False
                    and automated_safe_raw is False
                )

                if unknown_triplet:
                    safe_text = "[blue]false[/blue]"
                    automated_safe_text = "[blue]false[/blue]"
                    malicious_text = "[blue]false[/blue]"
                else:
                    if malicious_val:
                        malicious_text = "[red]true[/red]"
                        safe_text = f"[red]{str(safe_val).lower()}[/red]"
                    else:
                        malicious_text = "false"
                        safe_text = "[green]true[/green]" if safe_val else "false"
                    if automated_safe_raw is None:
                        automated_safe_text = ""
                    elif bool(automated_safe_raw):
                        automated_safe_text = "[green]true[/green]"
                    else:
                        automated_safe_text = "false"
                tr.add_row(
                    str(item.get("hash", "")),
                    safe_text,
                    automated_safe_text,
                    malicious_text,
                    str(item.get("fileName", "")),
                )
            console.print(tr)

    jl = jlab_static_scan or {}
    if jl.get("attempted") or jl.get("error"):
        _print_section(console, "JLab Static Scan")
        jt = Table(show_header=False, box=box.SIMPLE)
        jt.add_row("Upload file", str(jl.get("upload_file", "")))
        jt.add_row("Upload size", str(jl.get("upload_size", 0)))
        if jl.get("status_code"):
            jt.add_row("HTTP status", str(jl.get("status_code")))
        if jl.get("rate_limit_limit") is not None or jl.get("rate_limit_remaining") is not None:
            jt.add_row(
                "Rate limit",
                f"limit={jl.get('rate_limit_limit')} remaining={jl.get('rate_limit_remaining')}",
            )
        if jl.get("retry_after") is not None:
            jt.add_row("Retry after", f"{jl.get('retry_after')}s")
        if jl.get("error"):
            jt.add_row("Error", str(jl.get("error")))
        else:
            jt.add_row(
                "Matched signatures",
                f"{jl.get('matched_signatures', 0)} / {jl.get('total_signatures', 0)}",
            )
        console.print(jt)

        if not jl.get("error"):
            sig_tbl = Table(title="JLab Matched Signatures", show_header=True, box=box.SIMPLE, expand=True)
            sig_tbl.add_column("Severity", style="red", no_wrap=True)
            sig_tbl.add_column("ID", style="cyan", overflow="fold")
            sig_tbl.add_column("Name", style="yellow", overflow="fold")
            sig_tbl.add_column("Type", style="green", no_wrap=True)
            sig_tbl.add_column("Count", justify="right")
            sig_tbl.add_column("Description", style="white", overflow="fold")
            for sig in (jl.get("signatures", []) or [])[:80]:
                sig_tbl.add_row(
                    str(sig.get("severity", "")),
                    str(sig.get("id", "")),
                    str(sig.get("name", "")),
                    str(sig.get("type", "")),
                    str(sig.get("count", 0)),
                    short(str(sig.get("description", "")), 180),
                )
            if (jl.get("signatures", []) or []):
                console.print(sig_tbl)


    s2 = stage2_analysis or {}
    manual_payload_url = str(runtime_c2.get("payload_endpoint", "") or "")
    if s2.get("enabled") and not s2.get("attempted"):
        _print_section(console, "Stage2 Analysis")
        console.print("Attempted: no")
        if manual_payload_url:
            console.print(f"Manual stage2 download URL: {manual_payload_url}")
        if s2.get("error"):
            console.print(f"Reason: {s2.get('error')}")
    elif s2.get("enabled"):
        _print_section(console, "Stage2 Analysis")
        t2 = Table(show_header=False, box=box.SIMPLE)
        t2.add_row("Attempted", "yes")
        t2.add_row("Static-only mode", str(bool(s2.get("static_only_no_execution", True))))
        t2.add_row("Payload URL", str(s2.get("resolved_payload_url", "")))
        t2.add_row("Downloaded", str(bool(s2.get("downloaded", False))))
        if s2.get("downloaded"):
            t2.add_row("Downloaded path", str(s2.get("download_path", "")))
            t2.add_row("Downloaded size", str(s2.get("download_size", 0)))
            t2.add_row("Downloaded SHA256", str(s2.get("download_sha256", "")))
            t2.add_row("Archive signature", str(s2.get("archive_signature", "")))
            t2.add_row("Entry count", str(s2.get("entry_count", 0)))
            t2.add_row("Class count", str(s2.get("class_count", 0)))
            t2.add_row("Native entry count", str(s2.get("native_entry_count", 0)))
        if s2.get("error"):
            t2.add_row("Error", str(s2.get("error")))
        console.print(t2)
        if s2.get("native_entries_sample"):
            nt = Table(title="Stage2 Native Entries (sample)", show_header=True, box=box.SIMPLE)
            nt.add_column("Entry", style="magenta", overflow="fold")
            for item in (s2.get("native_entries_sample") or [])[:30]:
                nt.add_row(str(item))
            console.print(nt)
        s2_artifacts = s2.get("artifact_findings", []) or []
        if s2_artifacts:
            at = Table(title="Stage2 Artifact Findings", show_header=True, box=box.SIMPLE, expand=True)
            at.add_column("Type", style="red")
            at.add_column("Path", style="cyan", overflow="fold")
            at.add_column("Evidence", style="white", overflow="fold")
            for a in s2_artifacts:
                at.add_row(str(a.get("artifact_type")), str(a.get("path")), short(str(a.get("evidence", ""))))
            console.print(at)

    if any([blockchain["contracts"], blockchain["selectors"], blockchain["rpc_hosts"], blockchain["rpc_urls"], blockchain["api_key_urls"]]):
        _print_section(console, "Blockchain Indicators")
        bt = Table(show_header=False, box=box.SIMPLE)
        bt.add_row("Contracts", str(len(blockchain["contracts"])))
        bt.add_row("Method selectors", str(len(blockchain["selectors"])))
        bt.add_row("RPC hosts", str(len(blockchain["rpc_hosts"])))
        bt.add_row("RPC URLs", str(len(blockchain["rpc_urls"])))
        bt.add_row("RPC URLs with API keys", str(len(blockchain["api_key_urls"])))
        console.print(bt)
        if blockchain["contracts"]:
            t_contract = Table(title="Contract Addresses", show_header=True, box=box.SIMPLE)
            t_contract.add_column("Address", style="cyan")
            for item in blockchain["contracts"]:
                t_contract.add_row(item)
            console.print(t_contract)
        if blockchain["selectors"]:
            t_sel = Table(title="Method Selectors", show_header=True, box=box.SIMPLE)
            t_sel.add_column("Selector", style="yellow")
            for item in blockchain["selectors"]:
                t_sel.add_row(item)
            console.print(t_sel)
        if blockchain["rpc_hosts"]:
            t_hosts = Table(title="RPC Hosts", show_header=True, box=box.SIMPLE)
            t_hosts.add_column("Host", style="magenta")
            for item in blockchain["rpc_hosts"]:
                t_hosts.add_row(item)
            console.print(t_hosts)
        if blockchain["api_key_urls"]:
            t_api = Table(title="RPC URLs With API Keys", show_header=True, box=box.SIMPLE)
            t_api.add_column("URL", style="white", overflow="fold")
            for item in blockchain["api_key_urls"]:
                t_api.add_row(item)
            console.print(t_api)

    _print_section(console, "Summary")
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
    if executive_summary:
        _print_section(console, "Executive Summary")
        console.print(executive_summary)


def _infer_default_output_stem(scan_root: Path, cwd: Path) -> str:
    if scan_root.resolve() != cwd.resolve():
        return _sanitize_label(scan_root.name or "scan") or "scan"
    best_name = ""
    best_count = 0
    try:
        for d in cwd.iterdir():
            if not d.is_dir():
                continue
            if d.name.startswith(".") or d.name.lower() in {"__pycache__"}:
                continue
            cnt = sum(1 for _ in d.rglob("*.java"))
            if cnt > best_count:
                best_count = cnt
                best_name = d.name
    except Exception:
        pass
    if best_name:
        return _sanitize_label(best_name) or "scan"
    return _sanitize_label(scan_root.name or "scan") or "scan"


def _json_output_name_for_scan_root(scan_root: Path, cwd: Path) -> str:
    name = _infer_default_output_stem(scan_root, cwd)
    safe = _sanitize_label(name) or "scan"
    return f"{safe}.json"


def _html_output_name_for_scan_root(scan_root: Path, cwd: Path) -> str:
    name = _infer_default_output_stem(scan_root, cwd)
    safe = _sanitize_label(name) or "scan"
    return f"{safe}.html"


def _display_report_path(path: Path, cwd: Path) -> str:
    try:
        p = path.resolve()
        c = cwd.resolve()
    except Exception:
        return "cwd"
    if p == c:
        return "cwd"
    try:
        rel = p.relative_to(c)
        rel_s = str(rel).replace("\\", "/")
        return f"cwd/{rel_s}" if rel_s else "cwd"
    except Exception:
        return p.name or "cwd"


def _extract_responses_output_text(payload: dict[str, Any]) -> str:
    text = payload.get("output_text", "")
    if isinstance(text, str) and text.strip():
        return text.strip()
    chunks: List[str] = []
    for item in payload.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []) or []:
            if not isinstance(content, dict):
                continue
            if content.get("type") in {"output_text", "text"}:
                val = content.get("text", "")
                if isinstance(val, str) and val.strip():
                    chunks.append(val.strip())
    return "\n\n".join(chunks).strip()


def _friendly_network_error(exc: Exception) -> str:
    msg = str(exc or "").strip()
    low = msg.lower()
    if "getaddrinfo failed" in low or "name or service not known" in low:
        return "Connection failed: could not resolve host"
    if "timed out" in low or "timeout" in low:
        return "Connection failed: request timed out"
    if "connection refused" in low:
        return "Connection failed: remote host refused connection"
    if "forbidden" in low or "http error 403" in low:
        return "Connection failed: remote server denied request (HTTP 403)"
    if "http error" in low:
        return f"Connection failed: {msg}"
    return f"Connection failed: {msg or exc.__class__.__name__}"


def build_openai_executive_summary(triage_payload: dict[str, Any]) -> str:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return ""
    compact_json = json.dumps(triage_payload, ensure_ascii=False, separators=(",", ":"))
    max_chars = 120000
    if len(compact_json) > max_chars:
        compact_json = compact_json[:max_chars] + "...<truncated>"
    user_text = (
        OPENAI_EXEC_SUMMARY_INSTRUCTION
        + "\n\nTriage JSON (truncated where necessary):\n"
        + compact_json
    )
    model = os.getenv("TRIAGE_OPENAI_MODEL", "gpt-4.1-mini").strip() or "gpt-4.1-mini"
    req_body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a senior malware analyst. Be concise, structured, and objective."},
            {"role": "user", "content": user_text},
        ],
        "temperature": 0.2,
    }
    try:
        req = request.Request(
            OPENAI_CHAT_COMPLETIONS_URL,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            data=json.dumps(req_body).encode("utf-8"),
        )
        with request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return ""
    return _normalize_executive_summary_text(_extract_chat_completions_output_text(data))


def _extract_chat_completions_output_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices", []) or []
    if not isinstance(choices, list):
        return ""
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        msg = choice.get("message", {}) or {}
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", "")
        if isinstance(content, str) and content.strip():
            return content.strip()
    return ""


def _normalize_executive_summary_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    out_lines: List[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if not line:
            out_lines.append("")
            continue
        if re.fullmatch(r"\s*[-*_]{3,}\s*", line):
            continue
        line = re.sub(r"^\s{0,3}#{1,6}\s*", "", line)
        line = line.replace("**", "").replace("__", "").replace("`", "")
        if "|" in line and line.count("|") >= 2:
            cells = [c.strip() for c in line.split("|") if c.strip()]
            if not cells:
                continue
            if all(re.fullmatch(r"[:\-]+", c) for c in cells):
                continue
            line = " - ".join(cells)
        out_lines.append(line)
    normalized = "\n".join(out_lines)
    return re.sub(r"\n{3,}", "\n\n", normalized).strip()


def build_deepseek_executive_summary(triage_payload: dict[str, Any]) -> str:
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        return ""
    compact_json = json.dumps(triage_payload, ensure_ascii=False, separators=(",", ":"))
    max_chars = 120000
    if len(compact_json) > max_chars:
        compact_json = compact_json[:max_chars] + "...<truncated>"
    user_text = (
        OPENAI_EXEC_SUMMARY_INSTRUCTION
        + "\n\nTriage JSON (truncated where necessary):\n"
        + compact_json
    )
    model = os.getenv("TRIAGE_DEEPSEEK_MODEL", "deepseek-v4-flash").strip() or "deepseek-v4-flash"
    req_body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a senior malware analyst. Be concise, structured, and objective."},
            {"role": "user", "content": user_text},
        ],
        "temperature": 0.2,
        "reasoning_effort": os.getenv("TRIAGE_DEEPSEEK_REASONING_EFFORT", "high").strip() or "high",
        "thinking": {"type": "enabled"},
    }
    try:
        req = request.Request(
            DEEPSEEK_CHAT_COMPLETIONS_URL,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            data=json.dumps(req_body).encode("utf-8"),
        )
        with request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return ""
    return _normalize_executive_summary_text(_extract_chat_completions_output_text(data))


def build_executive_summary(triage_payload: dict[str, Any]) -> str:
    provider = os.getenv("TRIAGE_LLM_PROVIDER", "auto").strip().lower()
    if provider in {"openai", "oai"}:
        return build_openai_executive_summary(triage_payload)
    if provider in {"deepseek", "ds"}:
        return build_deepseek_executive_summary(triage_payload)
    summary = build_openai_executive_summary(triage_payload)
    if summary:
        return summary
    return build_deepseek_executive_summary(triage_payload)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Java Triage: recursively parse Java files, decode load(new int[]{...}) obfuscation, scan suspicious strings, and summarize findings."
    )
    p.add_argument("target", nargs="?", default=".", help="Folder to scan (default: current directory)")
    p.add_argument("--json", action="store_true", default=True, help="Emit JSON output (default: enabled)")
    p.add_argument("--no-json", dest="json", action="store_false", help="Emit text output instead of JSON")
    p.add_argument("--out", help="Write output to file")
    p.add_argument("--html", action="store_true", default=True, help="Also emit HTML report (default: enabled)")
    p.add_argument("--no-html", dest="html", action="store_false", help="Disable HTML report output")
    p.add_argument("--html-out", help="Write HTML report to file (implies --html)")
    p.add_argument("--no-progress", action="store_true", help="Disable progress messages")
    p.add_argument("--no-network", action="store_true", help="Disable runtime C2 resolution over network")
    p.add_argument(
        "--jlab-static-scan",
        action="store_true",
        default=True,
        help="Upload source JAR/ZIP to JLab public static scan API and include matched signature results (default: enabled)",
    )
    p.add_argument(
        "--no-jlab-static-scan",
        dest="jlab_static_scan",
        action="store_false",
        help="Disable JLab public static scan lookup",
    )
    p.add_argument(
        "--analyze-stage2",
        action="store_true",
        default=True,
        help="After resolving runtime payload endpoint, download stage-2 JAR and perform static-only analysis (never executes jars/classes) (default: enabled)",
    )
    p.add_argument(
        "--no-analyze-stage2",
        dest="analyze_stage2",
        action="store_false",
        help="Disable stage-2 static analysis",
    )
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
    initial_target = root
    show_progress = not args.no_progress
    pref_width = max(80, int(args.rich_width))
    progress_console = Console(stderr=False, width=pref_width) if RICH_AVAILABLE else None
    report_console = Console(width=pref_width) if RICH_AVAILABLE else None
    rich_progress_mode = bool(RICH_AVAILABLE and progress_console is not None and show_progress)
    phase_logs = show_progress and not rich_progress_mode

    # Show banner immediately so users always see identity/header first.
    if rich_progress_mode:
        print_banner(progress_console, to_stderr=False)
    else:
        print_banner(None, to_stderr=True)

    progress(phase_logs, f"target resolved to: {_display_report_path(root, Path.cwd().resolve())}", progress_console)

    if not root.exists():
        print(f"error: target does not exist: {root}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"error: target is not a directory: {root}", file=sys.stderr)
        return 2

    prepared_root = maybe_prepare_cwd_jar_scan_root(root, show_progress, progress_console)
    if prepared_root != root:
        root = prepared_root
        progress(
            phase_logs,
            f"target updated to extracted/decompiled directory: {_display_report_path(root, Path.cwd().resolve())}",
            progress_console,
        )

    html_out_path: Path | None = None

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

    if args.html_out:
        args.html = True
    if args.html:
        html_out_path = (
            Path(args.html_out).resolve()
            if args.html_out
            else (Path.cwd().resolve() / _html_output_name_for_scan_root(scan_root, Path.cwd().resolve()))
        )

    if args.json and not args.out:
        default_json_out = Path.cwd().resolve() / _json_output_name_for_scan_root(scan_root, Path.cwd().resolve())
        if default_json_out.exists():
            html_missing = bool(args.html and html_out_path is not None and not html_out_path.exists())
            if sys.stdin.isatty():
                existing_choice = _prompt_existing_scan_result(default_json_out, html_out_path, progress_console)
                if existing_choice == "reuse":
                    progress(
                        phase_logs,
                        f"using existing JSON result: {_display_report_path(default_json_out, Path.cwd().resolve())}",
                        progress_console,
                    )
                    return 0
                if existing_choice == "cancel":
                    progress(phase_logs, "scan cancelled by user", progress_console)
                    return 0
                _unlink_existing_result(default_json_out, phase_logs, progress_console)
                if args.html and html_out_path is not None:
                    _unlink_existing_result(html_out_path, phase_logs, progress_console)
            elif not html_missing:
                progress(
                    phase_logs,
                    f"existing JSON result found; skipping scan: {_display_report_path(default_json_out, Path.cwd().resolve())}",
                    progress_console,
                )
                return 0
            else:
                progress(
                    phase_logs,
                    "existing JSON result found but HTML output is missing; continuing to regenerate report",
                    progress_console,
                )
        args.out = str(default_json_out)

    if show_progress:
        _print_scan_beginning(progress_console if rich_progress_mode else None)

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

    extra_scan_roots: List[tuple[Path, str]] = []
    extra_scan_roots.extend(prepare_nested_dropped_jar_roots(scan_root, show_progress, progress_console))
    extra_scan_roots.extend(prepare_embedded_base32_archive_roots(scan_root, show_progress, progress_console))
    scan_targets: List[tuple[Path, str]] = [(scan_root, "")]
    seen_target_roots = {str(scan_root.resolve())}
    for target_root, prefix in extra_scan_roots:
        key = str(target_root.resolve())
        if key in seen_target_roots:
            continue
        seen_target_roots.add(key)
        scan_targets.append((target_root, prefix))

    progress(phase_logs, "collecting target metadata", progress_console)
    target_metadata = collect_target_metadata(scan_root)
    progress(phase_logs, "discovering Java files", progress_console)
    file_jobs: List[tuple[Path, Path, str]] = []
    class_jobs: List[tuple[Path, Path, str]] = []
    target_java_counts: dict[str, int] = {}
    target_class_counts: dict[str, int] = {}
    target_finding_counts: dict[str, int] = {}
    target_scan_mode: dict[str, str] = {}
    for target_root, prefix in scan_targets:
        java_list = list(iter_java_files(target_root))
        class_list = list(iter_class_files(target_root))
        root_key = str(target_root.resolve())
        target_java_counts[root_key] = len(java_list)
        target_class_counts[root_key] = len(class_list)
        target_finding_counts[root_key] = 0
        target_scan_mode[root_key] = "java" if java_list else ("class_constant_pool_fallback" if class_list else "none")
        for file_path in java_list:
            file_jobs.append((file_path, target_root, prefix))
        if not java_list and class_list:
            for class_path in class_list:
                class_jobs.append((class_path, target_root, prefix))
    progress(
        phase_logs,
        f"found {len(file_jobs)} Java file(s) and {len(class_jobs)} fallback class file(s) across {len(scan_targets)} scan target(s)",
        progress_console,
    )

    all_findings: List[Finding] = []
    behavior_findings: List[BehaviorFinding] = []
    scan_total = len(file_jobs) + len(class_jobs)
    if rich_progress_mode:
        with Progress(
            SpinnerColumn(style="#C000FF"),
            TextColumn("[bold white]Scanning sources"),
            BarColumn(bar_width=30, complete_style="#C000FF", finished_style="#C000FF", pulse_style="#C000FF"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=progress_console,
            transient=False,
        ) as prog:
            task = prog.add_task("scan", total=scan_total)
            for file_path, target_root, prefix in file_jobs:
                f_items = scan_file(file_path, target_root, decrypt_profile, include_all_literals=decrypt_mode)
                b_items = scan_behavior(file_path, target_root)
                all_findings.extend(_apply_prefix_findings(f_items, prefix))
                behavior_findings.extend(_apply_prefix_behaviors(b_items, prefix))
                target_finding_counts[str(target_root.resolve())] = target_finding_counts.get(str(target_root.resolve()), 0) + len(f_items)
                prog.advance(task)
            for class_path, target_root, prefix in class_jobs:
                c_items = scan_class_constant_pool(class_path, target_root)
                all_findings.extend(_apply_prefix_findings(c_items, prefix))
                target_finding_counts[str(target_root.resolve())] = target_finding_counts.get(str(target_root.resolve()), 0) + len(c_items)
                prog.advance(task)
    else:
        for idx, (file_path, target_root, prefix) in enumerate(file_jobs, start=1):
            if show_progress and (idx == 1 or idx % 50 == 0 or idx == scan_total):
                progress(show_progress, f"scanning source {idx}/{scan_total}", progress_console)
            f_items = scan_file(file_path, target_root, decrypt_profile, include_all_literals=decrypt_mode)
            b_items = scan_behavior(file_path, target_root)
            all_findings.extend(_apply_prefix_findings(f_items, prefix))
            behavior_findings.extend(_apply_prefix_behaviors(b_items, prefix))
            target_finding_counts[str(target_root.resolve())] = target_finding_counts.get(str(target_root.resolve()), 0) + len(f_items)
        for class_idx, (class_path, target_root, prefix) in enumerate(class_jobs, start=len(file_jobs) + 1):
            if show_progress and (class_idx == 1 or class_idx % 50 == 0 or class_idx == scan_total):
                progress(show_progress, f"scanning source {class_idx}/{scan_total}", progress_console)
            c_items = scan_class_constant_pool(class_path, target_root)
            all_findings.extend(_apply_prefix_findings(c_items, prefix))
            target_finding_counts[str(target_root.resolve())] = target_finding_counts.get(str(target_root.resolve()), 0) + len(c_items)

    all_findings = sorted(
        {(f.file, f.line, f.function, f.decoded, f.category, f.note): f for f in all_findings}.values(),
        key=lambda x: (x.file, x.line, x.decoded, x.category),
    )

    progress(show_progress, "Scan Complete; Finalizing Findings", progress_console)

    for target_root, prefix in scan_targets:
        behavior_findings.extend(_apply_prefix_behaviors(discover_structural_behaviors(target_root), prefix))
        behavior_findings.extend(_apply_prefix_behaviors(detect_token_source_sink_behaviors(target_root), prefix))
        behavior_findings.extend(_apply_prefix_behaviors(detect_reachability_proof_chains(target_root), prefix))
        root_key = str(target_root.resolve())
        java_count = target_java_counts.get(root_key, 0)
        class_count = target_class_counts.get(root_key, 0)
        find_count = target_finding_counts.get(root_key, 0)
        mode = target_scan_mode.get(root_key, "unknown")
        if java_count == 0 and class_count > 0:
            behavior_findings.extend(
                _apply_prefix_behaviors(
                    [
                        BehaviorFinding(
                            file=".",
                            line=1,
                            behavior="class_constant_pool_only_scan",
                            evidence=f"No Java source files recovered; scanned {class_count} class file(s) via constant-pool fallback",
                        ),
                        BehaviorFinding(
                            file=".",
                            line=1,
                            behavior="decompiler_failure_or_heavy_obfuscation",
                            evidence=(
                                "Decompiler did not recover Java source files; used class constant-pool fallback scan "
                                f"(class_files={class_count})"
                            ),
                        ),
                    ],
                    prefix,
                )
            )
        elif java_count == 0 and class_count == 0:
            behavior_findings.extend(
                _apply_prefix_behaviors(
                    [
                        BehaviorFinding(
                            file=".",
                            line=1,
                            behavior="decompiler_failure_or_heavy_obfuscation",
                            evidence="Decompiler output appears unavailable/garbled; no Java or class files recovered for static scan",
                        )
                    ],
                    prefix,
                )
            )
        elif java_count > 0 and find_count == 0:
            behavior_findings.extend(
                _apply_prefix_behaviors(
                    [
                        BehaviorFinding(
                            file=".",
                            line=1,
                            behavior="decompiler_failure_or_heavy_obfuscation",
                            evidence=(
                                "Decompiled output yielded zero string/decode findings despite recovered Java files; "
                                f"likely heavy string/control-flow obfuscation or low-quality decompiler output "
                                f"(java_files={java_count}, class_files={class_count}, scan_mode={mode})"
                            ),
                        )
                    ],
                    prefix,
                )
            )
    am = target_metadata.get("jar_info", {}).get("archive_metadata", {}) or {}
    if int(am.get("contained_directories", 0)) >= 1000 or int(am.get("max_directory_depth", 0)) >= 1000:
        behavior_findings.append(
            BehaviorFinding(
                file=".",
                line=1,
                behavior="extreme_archive_structure_obfuscation",
                evidence=(
                    "Archive metadata shows extreme directory topology "
                    f"(contained_directories={am.get('contained_directories', 0)} "
                    f"max_directory_depth={am.get('max_directory_depth', 0)})"
                ),
            )
        )
    behavior_findings = sorted(
        {(b.file, b.line, b.behavior, b.evidence): b for b in behavior_findings}.values(),
        key=lambda x: (x.file, x.line, x.behavior),
    )
    network_endpoint_assessment = assess_network_endpoints(all_findings)
    progress(show_progress, "Running Variant Signature Detections", progress_console)
    variant_detections = detect_variant_signatures(scan_root)
    progress(show_progress, f"Detected {variant_detections.get('detected_count', 0)} Signature Variant(s)", progress_console)
    progress(show_progress, "Running Raw String Scanner", progress_console)
    raw_string_detections = run_raw_string_scanner(scan_root)
    progress(show_progress, f"Raw String Detections: {len(raw_string_detections)}", progress_console)
    progress(show_progress, "Running Cross-Variant Heuristic Scorer", progress_console)
    heuristic_detections = run_cross_variant_heuristics(scan_root)
    progress(show_progress, f"Heuristic Detections: {len(heuristic_detections)}", progress_console)

    progress(show_progress, f"Collected {len(all_findings)} Decode/String Finding(s)", progress_console)
    progress(show_progress, f"Detected {len(behavior_findings)} Behavior Indicator(s)", progress_console)
    progress(show_progress, "Discovering Suspicious Artifacts", progress_console)
    artifact_findings: List[ArtifactFinding] = []
    for target_root, prefix in scan_targets:
        artifact_findings.extend(_apply_prefix_artifacts(discover_artifacts(target_root), prefix))
    artifact_findings = sorted(
        {(a.path, a.filename, a.size, a.sha256, a.artifact_type, a.evidence): a for a in artifact_findings}.values(),
        key=lambda x: x.path,
    )
    progress(show_progress, f"Detected {len(artifact_findings)} Artifact Indicator(s)", progress_console)
    runtime_c2 = {"attempted": False, "resolved": False}
    ratter_scanner = {"attempted": False, "error": "", "results": []}
    jlab_static_scan = {
        "attempted": False,
        "error": "",
        "status_code": 0,
        "upload_file": "",
        "upload_size": 0,
        "file_name": "",
        "file_size": 0,
        "total_signatures": 0,
        "matched_signatures": 0,
        "signatures": [],
        "retry_after": None,
        "rate_limit_limit": None,
        "rate_limit_remaining": None,
    }
    stage2_analysis = {
        "enabled": bool(args.analyze_stage2),
        "attempted": False,
        "static_only_no_execution": True,
        "error": "",
    }
    if not args.no_network:
        progress(show_progress, "Resolving Runtime C2 From On-Chain Config", progress_console)
        runtime_c2 = resolve_runtime_c2(all_findings)
        if runtime_c2.get("resolved"):
            progress(show_progress, f"Runtime C2 Resolved: {runtime_c2.get('c2_base_url')}", progress_console)
        else:
            progress(show_progress, f"Runtime C2 Unresolved: {runtime_c2.get('error', 'unknown error')}", progress_console)
    elif args.analyze_stage2:
        stage2_analysis["error"] = "stage2 analysis requires network access; rerun without --no-network"

    if args.analyze_stage2 and not stage2_analysis.get("error"):
        payload_url = runtime_c2.get("payload_endpoint", "")
        if not payload_url:
            stage2_analysis["error"] = "payload endpoint not resolved from runtime C2"
        else:
            progress(show_progress, f"stage2 static analysis: downloading {payload_url}", progress_console)
            stage2_analysis = analyze_stage2_payload(payload_url)
            if stage2_analysis.get("error"):
                progress(show_progress, f"stage2 analysis error: {stage2_analysis.get('error')}", progress_console)
            else:
                progress(
                    show_progress,
                    f"stage2 static analysis complete: entries={stage2_analysis.get('entry_count', 0)} "
                    f"native_entries={stage2_analysis.get('native_entry_count', 0)} "
                    f"artifacts={len(stage2_analysis.get('artifact_findings', []) or [])}",
                    progress_console,
                )

    if not args.no_network:
        rs_hashes = collect_ratterscanner_hashes(target_metadata, artifact_findings, stage2_analysis, scan_root)
        if rs_hashes:
            progress(show_progress, f"Querying RatterScanner For {len(rs_hashes)} Hash(es)", progress_console)
            ratter_scanner = lookup_ratterscanner(rs_hashes)
            if ratter_scanner.get("error"):
                progress(show_progress, f"RatterScanner Error: {ratter_scanner.get('error')}", progress_console)
            else:
                progress(
                    show_progress,
                    f"RatterScanner Results: {len(ratter_scanner.get('results', []) or [])}",
                    progress_console,
                )

    if args.jlab_static_scan:
        if args.no_network:
            jlab_static_scan["error"] = "JLab static scan requires network access; rerun without --no-network"
        else:
            upload_target, target_note = resolve_jlab_upload_target(initial_target, scan_root, target_metadata)
            if upload_target is None:
                jlab_static_scan["error"] = f"JLab static scan skipped: {target_note}"
            else:
                progress(
                    show_progress,
                    f"Querying JLab Static Scan API For {_display_report_path(upload_target, Path.cwd().resolve())}",
                    progress_console,
                )
                jlab_static_scan = lookup_jlab_static_scan(upload_target)
                if target_note:
                    jlab_static_scan["upload_resolution"] = target_note
                if jlab_static_scan.get("error"):
                    progress(show_progress, f"JLab Static Scan Error: {jlab_static_scan.get('error')}", progress_console)
                else:
                    progress(
                        show_progress,
                        "JLab Static Scan Results: "
                        f"matched={jlab_static_scan.get('matched_signatures', 0)} "
                        f"total={jlab_static_scan.get('total_signatures', 0)}",
                        progress_console,
                    )

    progress(show_progress, "Building Summary", progress_console)

    if rich_progress_mode and RICH_AVAILABLE and progress_console is not None:
        with Progress(
            SpinnerColumn(style="#C000FF"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=30, complete_style="#C000FF", finished_style="#C000FF", pulse_style="#C000FF"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=progress_console,
            transient=False,
        ) as build_prog:
            build_task = build_prog.add_task("Building Report", total=5)

            summary = summarize(all_findings, behavior_findings, artifact_findings)
            if deobf_stats:
                summary["xor_decrypted_count"] = int(deobf_stats.get("stringdecrypt_xor_replaced", 0))
                summary["decrypted_string_count"] = int(
                    deobf_stats.get("stringdecrypt_other_replaced", 0)
                ) + int(deobf_stats.get("load_replaced", 0))
            build_prog.advance(build_task)

            blockchain = extract_blockchain_indicators(all_findings)
            cwd_report = Path.cwd().resolve()
            payload = {
                "root": _display_report_path(scan_root, cwd_report),
                "scan_roots": [_display_report_path(x[0], cwd_report) for x in scan_targets],
                "scan_diagnostics": {
                    _display_report_path(tr, cwd_report): {
                        "java_files": target_java_counts.get(str(tr), 0),
                        "class_files": target_class_counts.get(str(tr), 0),
                        "finding_count": target_finding_counts.get(str(tr), 0),
                        "scan_mode": target_scan_mode.get(str(tr), "unknown"),
                    }
                    for tr, _prefix in scan_targets
                },
                "target_metadata": target_metadata,
                "scan_mode": "post_decryption_only" if decrypt_mode else "standard",
                "deobfuscation": deobf_stats if deobf_stats else {},
                "summary": summary,
                "assessment_summary": summarize_assessments(behavior_findings),
                "verdict_tiers": summarize_verdict_tiers(behavior_findings),
                "contradiction_notes": build_contradiction_notes(behavior_findings),
                "runtime_c2": runtime_c2,
                "ratter_scanner": ratter_scanner,
                "jlab_static_scan": jlab_static_scan,
                "network_endpoint_assessment": network_endpoint_assessment,
                "variant_detections": variant_detections,
                "raw_string_detections": raw_string_detections,
                "heuristic_detections": heuristic_detections,
                "stage2_analysis": stage2_analysis,
                "stage2_manual_payload_url": runtime_c2.get("payload_endpoint", ""),
                "blockchain_indicators": blockchain,
                "findings": [f.__dict__ for f in sorted(all_findings, key=lambda x: (x.file, x.line, x.decoded))],
                "behavior_findings": [
                    {**b.__dict__, "severity": behavior_severity(b.behavior), "verdict_tier": behavior_verdict_tier(b.behavior)}
                    for b in sorted(behavior_findings, key=lambda x: (x.file, x.line, x.behavior))
                ],
                "artifact_findings": [a.__dict__ for a in artifact_findings],
            }
            build_prog.advance(build_task)

            build_prog.update(build_task, description="Generating Executive Summary")
            executive_summary = build_executive_summary(payload)
            output_payload = dict(payload)
            if executive_summary:
                output_payload = {"executive_summary": executive_summary, **output_payload}
            build_prog.advance(build_task)

            json_output = json.dumps(output_payload, indent=2)
            text_output = render_text(
                all_findings,
                behavior_findings,
                artifact_findings,
                summary,
                runtime_c2,
                target_metadata,
                stage2_analysis,
                ratter_scanner,
                jlab_static_scan,
                network_endpoint_assessment,
                variant_detections,
                raw_string_detections,
                heuristic_detections,
            )
            if executive_summary:
                text_output = f"== Executive Summary ==\n{executive_summary}\n\n{text_output}"
            width = max(40, shutil.get_terminal_size((120, 20)).columns)
            centered_banner = "\n".join(line.center(width) for line in BANNER.splitlines())
            text_output_with_banner = f"{centered_banner}\n\n{text_output}"
            build_prog.advance(build_task)

            build_prog.update(build_task, description="Rendering HTML Report")
            html_output = render_html_report(output_payload, executive_summary) if args.html else ""
            build_prog.advance(build_task)
    else:
        summary = summarize(all_findings, behavior_findings, artifact_findings)
        if deobf_stats:
            summary["xor_decrypted_count"] = int(deobf_stats.get("stringdecrypt_xor_replaced", 0))
            summary["decrypted_string_count"] = int(
                deobf_stats.get("stringdecrypt_other_replaced", 0)
            ) + int(deobf_stats.get("load_replaced", 0))

        blockchain = extract_blockchain_indicators(all_findings)
        cwd_report = Path.cwd().resolve()
        payload = {
            "root": _display_report_path(scan_root, cwd_report),
            "scan_roots": [_display_report_path(x[0], cwd_report) for x in scan_targets],
            "scan_diagnostics": {
                _display_report_path(tr, cwd_report): {
                    "java_files": target_java_counts.get(str(tr), 0),
                    "class_files": target_class_counts.get(str(tr), 0),
                    "finding_count": target_finding_counts.get(str(tr), 0),
                    "scan_mode": target_scan_mode.get(str(tr), "unknown"),
                }
                for tr, _prefix in scan_targets
            },
            "target_metadata": target_metadata,
            "scan_mode": "post_decryption_only" if decrypt_mode else "standard",
            "deobfuscation": deobf_stats if deobf_stats else {},
            "summary": summary,
            "assessment_summary": summarize_assessments(behavior_findings),
            "verdict_tiers": summarize_verdict_tiers(behavior_findings),
            "contradiction_notes": build_contradiction_notes(behavior_findings),
            "runtime_c2": runtime_c2,
            "ratter_scanner": ratter_scanner,
            "jlab_static_scan": jlab_static_scan,
            "network_endpoint_assessment": network_endpoint_assessment,
            "variant_detections": variant_detections,
            "raw_string_detections": raw_string_detections,
            "heuristic_detections": heuristic_detections,
            "stage2_analysis": stage2_analysis,
            "stage2_manual_payload_url": runtime_c2.get("payload_endpoint", ""),
            "blockchain_indicators": blockchain,
            "findings": [f.__dict__ for f in sorted(all_findings, key=lambda x: (x.file, x.line, x.decoded))],
            "behavior_findings": [
                {**b.__dict__, "severity": behavior_severity(b.behavior), "verdict_tier": behavior_verdict_tier(b.behavior)}
                for b in sorted(behavior_findings, key=lambda x: (x.file, x.line, x.behavior))
            ],
            "artifact_findings": [a.__dict__ for a in artifact_findings],
        }
        executive_summary = build_executive_summary(payload)
        output_payload = dict(payload)
        if executive_summary:
            output_payload = {"executive_summary": executive_summary, **output_payload}

        json_output = json.dumps(output_payload, indent=2)
        text_output = render_text(
            all_findings,
            behavior_findings,
            artifact_findings,
            summary,
            runtime_c2,
            target_metadata,
            stage2_analysis,
            ratter_scanner,
            jlab_static_scan,
            network_endpoint_assessment,
            variant_detections,
            raw_string_detections,
            heuristic_detections,
        )
        if executive_summary:
            text_output = f"== Executive Summary ==\n{executive_summary}\n\n{text_output}"
        width = max(40, shutil.get_terminal_size((120, 20)).columns)
        centered_banner = "\n".join(line.center(width) for line in BANNER.splitlines())
        text_output_with_banner = f"{centered_banner}\n\n{text_output}"
        html_output = render_html_report(output_payload, executive_summary) if args.html else ""

    if args.json and args.out:
        progress(
            phase_logs,
            f"writing output to {_display_report_path(Path(args.out), Path.cwd().resolve())}",
            progress_console,
        )
        Path(args.out).write_text(json_output, encoding="utf-8")
    elif (not args.json) and args.out:
        progress(
            phase_logs,
            f"writing output to {_display_report_path(Path(args.out), Path.cwd().resolve())}",
            progress_console,
        )
        Path(args.out).write_text(text_output_with_banner, encoding="utf-8")
    if args.html and html_out_path is not None:
        progress(
            phase_logs,
            f"writing HTML output to {_display_report_path(html_out_path, Path.cwd().resolve())}",
            progress_console,
        )
        html_out_path.write_text(html_output, encoding="utf-8")

    progress(phase_logs, "printing output", progress_console)
    if RICH_AVAILABLE and report_console is not None and rich_progress_mode:
        # Clear scan-phase output so the final report is shown on a clean screen.
        report_console.clear()
        if os.name == "nt":
            os.system("cls")
    if RICH_AVAILABLE and report_console is not None:
        print_banner(report_console, to_stderr=False)
        render_rich(
            report_console,
            all_findings,
            behavior_findings,
            artifact_findings,
            summary,
            runtime_c2,
            target_metadata,
            stage2_analysis,
            ratter_scanner,
            jlab_static_scan,
            network_endpoint_assessment,
            variant_detections,
            raw_string_detections,
            heuristic_detections,
            executive_summary,
        )
    else:
        print(text_output_with_banner)
    progress(show_progress, "done", progress_console)
    try:
        input("\nPress Enter to quit...")
    except EOFError:
        pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

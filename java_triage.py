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
DOMAIN_NAME_RE = re.compile(r"^(?=.{4,253}$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
# File extensions that look like domain names but aren't — suppress false-positive domain hits
_DOMAIN_FALSE_POSITIVE_EXTENSIONS = frozenset({
    "exe", "dll", "jar", "py", "log", "dat", "bin", "txt", "cfg", "ini",
    "json", "xml", "yml", "yaml", "png", "jpg", "jpeg", "gif", "html", "css",
    "js", "class", "so", "dylib", "sys", "tmp", "bak", "zip", "tar", "gz",
})
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
# Detect "discord notification" and similar in decoded strings for Discord indicator
DISCORD_KEYWORD_PATTERNS = re.compile(
    r'\b(?:discord\s+notification|discord\s+embed|discord\s+message|discord\s+send|discord\s+alert)\b',
    re.IGNORECASE,
)
TELEGRAM_BOT_TOKEN_RE = re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,60}\b")
GENERIC_WEBHOOK_URL_RE = re.compile(
    r"^https?://[^\s\"'<>]+/(?:api/)?(?:v\d+/)?(?:webhook|webhooks|hooks?)/[^\s\"'<>]+$",
    re.IGNORECASE,
)
DISCORD_SNOWFLAKE_RE = re.compile(r"^\d{17,20}$")
DISCORD_SNOWFLAKE_ANY_RE = re.compile(r"\b\d{17,20}\b")

def _is_binary_looking_digits(s: str) -> bool:
    """Return True if the string looks like binary data (only 0 and 1 digits) rather than a real ID."""
    return set(s) <= {"0", "1"}
# Bitcoin / cryptocurrency address patterns (Base58 P2PKH/P2SH, Bech32)
BITCOIN_ADDRESS_RE = re.compile(
    r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b'
)
DISCORD_ID_CONTEXT_RE = re.compile(
    r"(?:\bguild(?:_id)?\b|\bserver(?:_id)?\b|\bchannel(?:_id)?\b|\buser(?:_id)?\b|\brole(?:_id)?\b|\bapplication(?:_id)?\b|\bdiscord\b)",
    re.IGNORECASE,
)
HTTP_HOST_RE = re.compile(r'https?://([^/:\s"\'<>]+)', re.IGNORECASE)
# Java comment extraction
JAVA_LINE_COMMENT_RE = re.compile(r"//\s*(.*?)$", re.MULTILINE)
JAVA_BLOCK_COMMENT_RE = re.compile(r"/\*\s*(.*?)\s*\*/", re.DOTALL)
# Sensitive terms commonly found in malware author comments
SENSITIVE_COMMENT_TERMS = [
    "sends base coordinates to discord",
    "sends coordinates to discord",
    "sends position to discord",
    "sends player coordinates",
    "sends player position",
    "exfiltrate",
    "exfiltration",
    "steal token",
    "steal credentials",
    "steal session",
    "token grabber",
    "credential grabber",
    "session stealer",
    "webhook sender",
    "discord webhook sender",
    "c2 callback",
    "beacon",
    "keylogger",
    "clipboard stealer",
    "browser stealer",
    "password extractor",
    "credential leak",
    "send to discord",
]
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
    "obf_xor_encoded_name_access": "medium",
    "obf_base64_encoded_name_access": "medium",
    "obf_caesar_encoded_name_access": "medium",
    "obf_methodhandle_token_access": "high",
    "obf_lambdametafactory_token_access": "high",
    "obf_array_indirect_dispatch_token_access": "medium",
    "obf_split_reassembled_name_access": "medium",
    "obf_unsafe_field_token_access": "high",
    "obf_varhandle_field_token_access": "high",
    "obf_stackwalker_indirect_access": "medium",
    "obf_int_array_encoded_name_access": "medium",
    "obf_classloader_bypass_token_access": "high",
    "token_class_sweep_static_field_harvest": "high",
    "token_spin_race_window_harvest": "critical",
    "token_yggdrasil_internal_probe": "high",
    "token_process_commandline_harvest": "high",
    "token_processhandle_commandline_probe": "medium",
    "token_runtime_mxbean_arg_probe": "medium",
    "token_system_property_auth_probe": "medium",
    "token_environment_auth_probe": "medium",
    "token_sun_java_command_probe": "medium",
    "token_jdk_internal_process_probe": "medium",
    "token_bootstrap_constructor_capture": "critical",
    "token_authlib_deep_hook_access": "high",
    "token_connection_authorization_header_probe": "high",
    "token_urlconnection_requests_unsafe_probe": "high",
    "token_connection_spin_race_header_harvest": "critical",
    "blockchain_dns_c2_resolver": "high",
    "raw_socket_http_post_client": "medium",
    "proof_minecraft_token_raw_socket_exfil_chain": "critical",
    "two_payload_exfil_architecture": "critical",
    "persistence_filesystem_copy_relaunch_chain": "critical",
    "persistence_detached_process_relaunch": "high",
    "c2_fallback_domain": "high",
    "payload_download_endpoint": "high",
    "persistence_install_directory": "high",
    "python_executable_reference": "medium",
    "python_script_reference": "medium",
    "exfil_endpoint_prefiremc": "critical",
    "exfil_endpoint_submit_log": "high",
    "c2_custom_header_fingerprint": "high",
    "python_subprocess_argument_chain": "high",
    "detached_process_runtime_indicator": "medium",
    "dataflow_token_to_network_sink": "high",
    "dataflow_username_to_network_sink": "medium",
    "dataflow_uuid_to_network_sink": "medium",
    "minecraft_coordinate_exfiltration": "high",
    "discord_webhook_url_reassembly": "high",
    "multi_path_exfil_breakdown": "critical",
    "sensitive_game_data_comment": "medium",
    "inline_xor_string_decoder": "medium",
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
    # Minecraft avatar / skin CDNs (used by mods for RPC, not exfiltration)
    "crafthead.net",
    "crafatar.com",
    "minotar.net",
    "mc-heads.net",
    "visage.surgeplay.com",
    "mcapi.ca",
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
    ("field_152429_d", "Legacy MCP accountType field", 15),
    ("field_34961", "MC clientId field", 15),
    ("field_34960", "MC xuid field", 15),
    ("field_1984", "MC accountType field", 15),
    ("field_71449_j", "Legacy MCP Minecraft.session field", 15),
    ("field_1726", "Intermediary MinecraftClient.session field", 15),
    ("net.minecraft.client.MinecraftClient", "Yarn/Fabric MinecraftClient class", 15),
    ("net.minecraft.class_310", "Intermediary MinecraftClient class", 15),
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
    ("User.<init>", "Minecraft User constructor token capture path", 25),
    ("BOOTSTRAP CAPTURE", "TokenReader bootstrap constructor capture marker", 35),
    ("prepareRequest", "Authlib MinecraftClient request preparation hook", 20),
    ("postInternal", "Authlib MinecraftClient postInternal hook", 20),
    ("getRequestProperty(\"Authorization\")", "Authorization header read from URLConnection", 25),
    ("URLConnection.requests", "Unsafe URLConnection request-header field probe", 30),
    ("startConnectionRace", "Connection-mode authorization header spin race", 30),
    ("token-reader-output.txt", "TokenReader credential/probe output file", 20),
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
    "Parse the JSON and create an executive summary. Keep it technical but understandable "
    "for both layman and professional. Max 500 words. Output must be plain text optimized for terminal "
    "display. Do NOT use markdown headings, bold/italic markers, tables, code fences, horizontal rules, "
    "or backticks. Use short section labels and simple bullet lines prefixed with '- '.\n\n"

    "CRITICAL RULES — VIOLATING THESE MAKES THE REPORT UNUSABLE:\n"
    "1. NEVER speculate. Only describe behavior that has CONCRETE evidence in the JSON. "
    "If there's no webhook URL, no JSON payload construction, no exfil endpoint — do NOT say "
    "'could exfiltrate' or 'could send data'. You are a reporter of FACTS, not a fiction writer.\n"
    "2. Session/token/username/UUID access is only normal when it is isolated to local auth or "
    "account functionality. If the JSON also shows a resolved C2 domain, exfil endpoint, payload "
    "endpoint, staged download, or token/credential flow to a network sink, treat it as credential "
    "harvesting or exfiltration evidence, not benign mod behavior.\n"
    "3. Account switchers, alt managers, and session utilities handle tokens for LOCAL use. "
    "They are NOT stealers. Do NOT conflate account management with credential theft.\n"
    "4. Analytics, auto-updaters, and API clients (OpenAI, Ollama, Google Translate) "
    "are legitimate mod features. They make outbound connections but are NOT C2 channels.\n"
    "5. If the only behavior findings are 'obfuscated class names' and 'environment variable access' "
    "alongside detected mod modules, the verdict is: BENIGN Minecraft mod/client. No threats found.\n"
    "6. Use the contradiction_notes field. If the tool said there's no proof of exfiltration, "
    "echo that. Do not bury it.\n"
    "7. Cheat/hack modules do not reduce malware severity when the JSON also shows confirmed C2, "
    "staged payload delivery, persistence, or exfiltration. If those are present, the verdict is "
    "Malicious, not just Cheat Client.\n"
    "8. A failed live probe (403, DNS failure, no download) does not negate confirmed infrastructure. "
    "If the scan resolved a C2 domain, assembled exfil/payload endpoints, or found proof-grade "
    "behavior, say so plainly.\n\n"

    "STRUCTURE: Start with VERDICT: [Clean / Cheat Client / Suspicious / Malicious]. "
    "Then MODULES (if detected), then LEGITIMATE FEATURES, then CONFIRMED FINDINGS (only proven), "
    "then CAVEATS (from contradiction_notes). DO NOT invent a RISK PROFILE section — that is "
    "speculation. Only report what IS in the data, not what MIGHT be."
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


KEY_PREFIX_XOR_GETBYTES_RE = re.compile(
    r'"(?P<lit>(?:\\.|[^"\\\r\n]){4,})"\s*\.getBytes\(\s*(?:(?:StandardCharsets\.)?ISO_8859_1|"ISO-8859-1")\s*\)',
    re.DOTALL,
)
KEY_PREFIX_XOR_TOCHAR_RE = re.compile(
    r'"(?P<lit>(?:\\.|[^"\\\r\n]){4,})"\s*\.toCharArray\(\s*\)',
    re.DOTALL,
)
# CFR decompiles getBytes()/toCharArray() calls as bare byte[]/char[] =
# assignments, then the decode loop follows within a few lines.
CFR_BYTE_ARRAY_RE = re.compile(
    r'byte\[\]\s+\w+\s*=\s*"(?P<lit>(?:\\.|[^"\\\r\n]){4,})"\s*;',
    re.DOTALL,
)
CFR_CHAR_ARRAY_RE = re.compile(
    r'char\[\]\s+\w+\s*=\s*"(?P<lit>(?:\\.|[^"\\\r\n]){4,})"\s*;',
    re.DOTALL,
)


def _java_literal_to_codepoints(raw: str) -> List[int]:
    decoded = _unescape_java_literal(raw)
    return [ord(ch) for ch in decoded]


def _decode_key_prefixed_xor_values(vals: List[int]) -> str:
    if len(vals) < 4:
        return ""
    key_len = vals[0] & 0xFF
    if key_len <= 0 or len(vals) <= key_len + 1:
        return ""
    out_len = len(vals) - 1 - key_len
    try:
        raw = bytes((vals[1 + key_len + i] ^ vals[1 + (i % key_len)]) & 0xFF for i in range(out_len))
        return raw.decode("utf-8", errors="replace").replace("\x00", "").strip()
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════
#  Public XOR / AES decode helpers + clean-copy production system
# ═══════════════════════════════════════════════════════════════

def decode_xor_blob(data: bytes) -> str:
    """Decode a prefix-key XOR blob: first byte = key length, next n bytes = key,
    remaining bytes = ciphertext XORed with cycling key. Result is UTF-8 text."""
    if len(data) < 3:
        return ""
    key_len = data[0] & 0xFF
    if key_len <= 0 or len(data) <= key_len + 1:
        return ""
    out_len = len(data) - 1 - key_len
    result = bytearray(out_len)
    for i in range(out_len):
        result[i] = data[1 + key_len + i] ^ data[1 + (i % key_len)]
    try:
        return result.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _unescape_java_literal_robust(raw: str) -> str:
    """Fully decode Java string escape sequences: \\n \\t \\r \\b \\f \\\\ \\\" \\'
    \\uXXXX, and \\ooo octal. Returns the decoded Python string."""
    out = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt == "n":
                out.append("\n"); i += 2
            elif nxt == "t":
                out.append("\t"); i += 2
            elif nxt == "r":
                out.append("\r"); i += 2
            elif nxt == "b":
                out.append("\b"); i += 2
            elif nxt == "f":
                out.append("\f"); i += 2
            elif nxt in ("\\", "\"", "'"):
                out.append(nxt); i += 2
            elif nxt == "u" and i + 5 < len(raw):
                try:
                    out.append(chr(int(raw[i + 2 : i + 6], 16))); i += 6
                except (ValueError, OverflowError):
                    out.append(ch); i += 1
            elif nxt.isdigit() and nxt not in ("8", "9"):
                oct_digits = ""
                j = i + 1
                while j < len(raw) and raw[j].isdigit() and raw[j] not in ("8", "9") and (j - i - 1) < 3:
                    oct_digits += raw[j]; j += 1
                if oct_digits:
                    try:
                        out.append(chr(int(oct_digits, 8)))
                    except (ValueError, OverflowError):
                        out.append("\\" + oct_digits)
                    i = j
                else:
                    out.append(ch); i += 1
            else:
                out.append(ch); i += 1
        else:
            out.append(ch); i += 1
    return "".join(out)


def decode_java_escaped_literal(literal: str, source_type: str) -> str:
    """Decode a Java string literal and apply prefix-key XOR.
    source_type: 'getbytes' (ISO-8859-1 bytes) or 'tochararray' (ord&0xFF bytes)."""
    decoded_str = _unescape_java_literal_robust(literal)
    if source_type == "getbytes":
        data = decoded_str.encode("latin-1", errors="replace")
    elif source_type == "tochararray":
        data = bytes(ord(ch) & 0xFF for ch in decoded_str)
    else:
        return ""
    if len(data) < 3:
        return ""
    return decode_xor_blob(data)


def extract_and_decode_all_strings(java_source: str) -> list[dict]:
    """Extract ALL XOR-obfuscated string patterns from Java source and decode them.
    Returns list of dicts: original_literal, decoded_string, byte_offset, line_number,
    source_type, success."""
    import bisect as _bisec
    results: list[dict] = []
    line_starts = [0]
    for i, ch in enumerate(java_source):
        if ch == "\n":
            line_starts.append(i + 1)
    def _line(offset: int) -> int:
        return _bisec.bisect_right(line_starts, offset)

    patterns = [("getbytes", KEY_PREFIX_XOR_GETBYTES_RE), ("tochararray", KEY_PREFIX_XOR_TOCHAR_RE),
                ("cfr_bytes", CFR_BYTE_ARRAY_RE), ("cfr_chars", CFR_CHAR_ARRAY_RE)]
    seen = set()
    for source_type, regex in patterns:
        for m in regex.finditer(java_source):
            lit = m.group("lit")
            key = (lit, m.start(), source_type)
            if key in seen:
                continue
            seen.add(key)
            decoded = decode_java_escaped_literal(lit, source_type)
            results.append({
                "original_literal": lit,
                "decoded_string": decoded,
                "byte_offset": m.start(),
                "line_number": _line(m.start()),
                "source_type": source_type,
                "success": bool(decoded and len(decoded) > 0),
            })
    return results


def aes_cbc_nopadding_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes | None:
    """AES/CBC/NoPadding decrypt with PKCS#5/7 padding strip. Returns None on bad input."""
    if len(key) not in {16, 24, 32}:
        return None
    if len(iv) != 16:
        return None
    if len(ciphertext) % 16 != 0 or len(ciphertext) == 0:
        return None
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return None
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ciphertext)
    except Exception:
        return None
    if not padded:
        return None
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        return None
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return padded[:-pad_len]


# ── Clean .java copy: rewrite XOR strings in place ──

_GETBYTES_CALL_RE = re.compile(
    r'"((?:\\.|[^"\\\r\n]){4,})"\s*\.getBytes\(\s*(?:(?:StandardCharsets\.)?ISO_8859_1|"ISO-8859-1")\s*\)',
    re.DOTALL,
)
_TOCHAR_CALL_RE = re.compile(
    r'"((?:\\.|[^"\\\r\n]){4,})"\s*\.toCharArray\(\s*\)',
    re.DOTALL,
)


def _java_string_literal_escape(decoded: str) -> str:
    """Escape a string for use as a Java double-quoted literal."""
    out = []
    for ch in decoded:
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
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif code < 0x20 or (code > 0x7E and code < 0xA0):
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _rewrite_xor_strings_in_java_source(java_source: str) -> tuple[str, int, int]:
    """Replace XOR-obfuscated string decode blocks with clean Java string literals.
    Handles both JDK-style (getBytes/toCharArray) and CFR-style (bare byte[]/char[] assignment).
    Returns (rewritten_source, replaced_count, failed_count)."""
    result = java_source
    total_replaced = 0
    total_failed = 0

    # ── Pass 1: JDK-style .getBytes() / .toCharArray() call expressions ──
    replacements: list[tuple[int, int, str]] = []
    for source_type, regex in [("getbytes", _GETBYTES_CALL_RE), ("tochararray", _TOCHAR_CALL_RE)]:
        for m in regex.finditer(result):
            lit = m.group(1)
            decoded = decode_java_escaped_literal(lit, source_type)
            if decoded and len(decoded) > 0:
                escaped = _java_string_literal_escape(decoded)
                replacements.append((m.start(), m.end(), escaped))
    if replacements:
        replacements.sort(key=lambda x: x[0], reverse=True)
        for start, end, new_text in replacements:
            if start <= len(result) and end <= len(result):
                result = result[:start] + new_text + result[end:]
                total_replaced += 1
            else:
                total_failed += 1

    # ── Pass 2: CFR-style byte[]/char[] = "literal" → decode block → .append(new String(...)) ──
    for source_type, regex in [("getbytes", CFR_BYTE_ARRAY_RE), ("tochararray", CFR_CHAR_ARRAY_RE)]:
        cfr_repl: list[tuple[int, int, str]] = []
        for m in regex.finditer(result):
            lit = m.group("lit")
            decoded = decode_java_escaped_literal(lit, source_type)
            if not decoded or len(decoded) < 2:
                continue
            decoded_escaped = _java_string_literal_escape(decoded)
            # Find the end of this decode block: look ahead for
            # .append(new String(resultVar, ...)) or new String(resultVar, ...)
            # within the next ~20 lines
            after = result[m.end():m.end() + 3000]
            var_match = re.search(
                r'(?:\.append\(\s*)?new\s+String\s*\(\s*\w+\d*\s*,\s*(?:StandardCharsets\.)?(?:UTF_8|"UTF-8")\s*\)',
                after
            )
            block_end = m.end() + (var_match.end() + 1 if var_match else len(after))
            if var_match:
                # Replace from array decl to .append(new String(...)) call with the decoded literal
                # Use .append("decoded") to keep the append semantic
                cfr_repl.append((m.start(), min(block_end, len(result)),
                                _java_string_literal_escape(decoded)))
        if cfr_repl:
            cfr_repl.sort(key=lambda x: x[0], reverse=True)
            for start, end, new_text in cfr_repl:
                if start <= len(result) and end <= len(result):
                    result = result[:start] + new_text + result[end:]
                    total_replaced += 1
                else:
                    total_failed += 1

    return result, total_replaced, total_failed


def produce_deciphered_copy(
    scan_root: Path, show_progress: bool, progress_console=None,
) -> tuple[Path, dict]:
    """Produce a deciphered copy of scan_root with all XOR-obfuscated
    getBytes/toCharArray strings replaced by their decoded literals.
    Output dir: <scan_root>_deciphered. Returns (deciphered_root, stats)."""
    base_out = Path.cwd() / f"{scan_root.name}_deciphered"
    out_root = base_out
    if out_root.exists():
        idx = 2
        while True:
            candidate = Path.cwd() / f"{scan_root.name}_deciphered_{idx}"
            if not candidate.exists():
                out_root = candidate
                break
            idx += 1
    progress(show_progress, f"producing deciphered copy: {out_root}", progress_console)
    shutil.copytree(scan_root, out_root)
    java_files = list(out_root.rglob("*.java"))
    total_replaced = 0
    total_failed = 0
    files_changed = 0
    total_java = len(java_files)
    for idx, path in enumerate(java_files, start=1):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        new_text, repl, fail = _rewrite_xor_strings_in_java_source(text)
        if repl > 0:
            try:
                path.write_text(new_text, encoding="utf-8")
                files_changed += 1
                total_replaced += repl
                total_failed += fail
            except Exception:
                total_failed += repl
        if show_progress and (idx == 1 or idx % 50 == 0 or idx == total_java):
            progress(show_progress, f"deciphering {idx}/{total_java} replaced={total_replaced} files_changed={files_changed}", progress_console)
    stats = {
        "java_files": total_java, "files_changed": files_changed,
        "strings_replaced": total_replaced, "strings_failed": total_failed,
        "output_root": str(out_root),
    }
    return out_root, stats


# ── End public decode helpers ──


def _looks_interesting_decoded_literal(decoded: str) -> bool:
    if not decoded or len(decoded.strip()) < 3:
        return False
    d = decoded.strip()
    low = d.lower()
    if URL_RE.match(d) or HEX_ADDR_RE.match(d) or ETH_SELECTOR_RE.match(d) or DOMAIN_NAME_RE.match(d):
        return True
    if d.startswith("/") and len(d) > 3:
        return True
    if COMMAND_LITERAL_RE.search(d):
        return True
    return any(
        k in low
        for k in [
            "jsonrpc",
            "eth_call",
            "authorization",
            "bearer ",
            "token",
            "minecraft",
            "username",
            "uuid",
            "content-type",
            "application/json",
            "user-agent",
            "localappdata",
            "appdata",
            "shard",
            "prefire",
            "ntprofileindex",
            "\\microsoft\\",
            "microsoft\\windows",
            "javaw.exe",
            "java.exe",
            "python.exe",
            "main.py",
            ".exe",
            "getx()",
            "gety()",
            "getz()",
            "blockpos",
            "coordinate",
            "position",
            "vec3d",
            "vec3",
            "discord",
            "webhook",
            # Stealer/persistence-related keywords
            "stealer",
            "_stealer",
            "_spawn",
            "restarted",
            "detached",
            "nul",
            "fatal",
            "download",
            "decrypt",
            "extract",
            "cache",
            "spawn",
            "error:",
            "attempt",
            "context parsed",
            "submiterror",
            "submit error",
            "spawn error",
            "portable",
            "runtime ready",
            "downloading",
            "apphost",
            "latest.log",
            "combined.log",
            "x-cdn-origin",
            "cdn",
            "trust-all",
            "trust all",
            "accept-all",
            "accept all",
            "TLS",
            "X509TrustManager",
        ]
    )


def _extract_key_prefixed_xor_literals(
    text: str,
    starts: Optional[List[int]] = None,
    max_hits: int = 500,
    interesting_only: bool = True,
) -> List[tuple[str, int, int, str]]:
    out: List[tuple[str, int, int, str]] = []
    seen = set()
    starts = starts or build_line_starts(text)
    matches = []
    for source_kind, regex in [
        ("key_prefix_xor_getbytes", KEY_PREFIX_XOR_GETBYTES_RE),
        ("key_prefix_xor_tochar", KEY_PREFIX_XOR_TOCHAR_RE),
        ("cfr_xor_bytes", CFR_BYTE_ARRAY_RE),
        ("cfr_xor_chars", CFR_CHAR_ARRAY_RE),
    ]:
        matches.extend((m.start(), source_kind, m) for m in regex.finditer(text))
    for _pos, source_kind, m in sorted(matches, key=lambda item: item[0]):
        vals = _java_literal_to_codepoints(m.group("lit"))
        decoded = _decode_key_prefixed_xor_values(vals)
        if interesting_only and not _looks_interesting_decoded_literal(decoded):
            continue
        if not decoded or len(decoded) < 2:
            continue
        line = offset_to_line(starts, m.start())
        key = (decoded, line, source_kind)
        if key in seen:
            continue
        seen.add(key)
        out.append((decoded, line, len(vals), source_kind))
        if len(out) >= max_hits:
            return out
    return out


def _extract_full_xor_decoded_strings(
    text: str,
    starts: Optional[List[int]] = None,
    max_hits: int = 800,
) -> List[tuple[str, int, int, str]]:
    """Extract ALL XOR-decoded strings (byte[]/char[] prefixed-key variants) from
    the source file, including those that don't match the interesting-literal
    filter.  This captures full JSON payload templates, encoded exfil data
    structures, and other strings the selective scanner may skip."""
    out: List[tuple[str, int, int, str]] = []
    seen = set()
    starts = starts or build_line_starts(text)
    matches = []
    for source_kind, regex in [
        ("key_prefix_xor_getbytes", KEY_PREFIX_XOR_GETBYTES_RE),
        ("key_prefix_xor_tochar", KEY_PREFIX_XOR_TOCHAR_RE),
        ("cfr_xor_bytes", CFR_BYTE_ARRAY_RE),
        ("cfr_xor_chars", CFR_CHAR_ARRAY_RE),
    ]:
        matches.extend((m.start(), source_kind, m) for m in regex.finditer(text))
    for _pos, source_kind, m in sorted(matches, key=lambda item: item[0]):
        vals = _java_literal_to_codepoints(m.group("lit"))
        decoded = _decode_key_prefixed_xor_values(vals)
        if not decoded or len(decoded) < 2:
            continue
        line = offset_to_line(starts, m.start())
        key = (decoded, line, source_kind)
        if key in seen:
            continue
        seen.add(key)
        out.append((decoded, line, len(vals), source_kind))
        if len(out) >= max_hits:
            return out
    return out


# ── Inline first-byte-key XOR string decoder ─────────────────────────────────
# Matches Skidfuscator-style inline byte array XOR patterns:
#   byte[] arr = "XORobfuscatedString";
#   int n = arr[0] & 0xFF;
#   int m = arr.length - 1 - n;
#   byte[] out = new byte[m];
#   for (int i = 0; i < m; ++i) {
#       out[i] = (byte)(arr[1 + n + i] ^ arr[1 + i % n]);
#   }
#   new String(out, "UTF-8")   — actual decoded result
INLINE_XOR_BYTE_ARRAY_LITERAL_RE = re.compile(
    r'byte\[\]\s+(?P<var>\w+)\s*=\s*"(?P<lit>[^"\n]*)"\s*;',
)
INLINE_XOR_CHAR_ARRAY_LITERAL_RE = re.compile(
    r'char\[\]\s+(?P<var>\w+)\s*=\s*"(?P<lit>[^"\n]*)"\s*;',
)


def _extract_inline_xor_decoded_strings(
    text: str,
    starts: Optional[List[int]] = None,
    max_hits: int = 300,
) -> List[tuple[str, int, int, str]]:
    """Decode Skidfuscator-style inline first-byte-key XOR patterns.

    These are byte[] or char[] literals where the first element is used as
    the XOR key length, and a subsequent loop decodes the rest of the array
    using that key, followed by `new String(out, "UTF-8")`.
    """
    out: List[tuple[str, int, int, str]] = []
    seen = set()
    starts = starts or build_line_starts(text)

    def _attempt_decode(lit: str, pos: int, source_kind: str) -> Optional[tuple[str, int, int]]:
        """Try to decode a byte/char array literal using first-byte-key XOR."""
        try:
            vals = _java_literal_to_codepoints(lit)
            if len(vals) < 3:
                return None
            key_len = vals[0] & 0xFF
            if key_len <= 0 or key_len > 255:
                return None
            total = 1 + key_len  # 1 for key_len, then key_len key bytes
            if total >= len(vals):
                return None
            key = vals[1:total]
            data = vals[total:]
            decoded_bytes = bytearray()
            for i, b in enumerate(data):
                decoded_bytes.append((b ^ key[i % len(key)]) & 0xFF)
            result = bytes(decoded_bytes).decode("utf-8", errors="replace")
            if len(result) < 2:
                return None
            return (result, len(vals), key_len)
        except Exception:
            return None

    # Pattern A: byte[] arr = "XORstring";  ... arr[0] & 0xFF ... new String(out, "UTF-8")
    for m in INLINE_XOR_BYTE_ARRAY_LITERAL_RE.finditer(text):
        var = m.group("var")
        lit = m.group("lit")
        if not lit or len(lit) < 2:
            continue
        pos = m.start()
        # Quick forward-scan: check if var[0] & 0xFF appears nearby (within 500 chars)
        forward = text[pos:pos + 800]
        if f"{var}[0] & 0xFF" not in forward and f"{var}[0]&0xFF" not in forward:
            continue
        if "new String(" not in forward:
            continue

        decoded = _attempt_decode(lit, pos, "inline_xor_bytes")
        if decoded is None:
            continue
        decoded_str, item_count, key_len = decoded
        line = offset_to_line(starts, pos)
        key = (decoded_str, line, "inline_xor_bytes")
        if key in seen:
            continue
        seen.add(key)
        out.append((decoded_str, line, item_count, f"inline_xor_bytes(kl={key_len})"))
        if len(out) >= max_hits:
            return out

    # Pattern B: char[] arr = "XORstring";  ... arr[0] ... arr[1 + arr[0] + i] ^ arr[1 + i % arr[0]]
    for m in INLINE_XOR_CHAR_ARRAY_LITERAL_RE.finditer(text):
        var = m.group("var")
        lit = m.group("lit")
        if not lit or len(lit) < 2:
            continue
        pos = m.start()
        forward = text[pos:pos + 800]
        # Char variant uses cArray[0] directly (not & 0xFF), or (int)cArray[0]
        if f"{var}[0]" not in forward:
            continue
        if "new String(" not in forward:
            continue

        decoded = _attempt_decode(lit, pos, "inline_xor_chars")
        if decoded is None:
            continue
        decoded_str, item_count, key_len = decoded
        line = offset_to_line(starts, pos)
        key = (decoded_str, line, "inline_xor_chars")
        if key in seen:
            continue
        seen.add(key)
        out.append((decoded_str, line, item_count, f"inline_xor_chars(kl={key_len})"))
        if len(out) >= max_hits:
            return out

    return out


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

    return out


def _extract_key_prefixed_xor_stringbuilder_reconstructions(
    text: str,
    starts: Optional[List[int]] = None,
    max_blocks: int = 120,
) -> List[tuple[str, int, int, str]]:
    out: List[tuple[str, int, int, str]] = []
    seen = set()
    starts = starts or build_line_starts(text)
    decls = list(re.finditer(r"\bStringBuilder\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*new\s+StringBuilder\(\)\s*;", text))
    for idx, m in enumerate(decls[:max_blocks]):
        block_end = decls[idx + 1].start() if idx + 1 < len(decls) else min(len(text), m.end() + 6000)
        var_name = re.escape(m.group("name"))
        assign_m = re.search(rf"\b{var_name}\.toString\(\)", text[m.end() : block_end])
        if assign_m:
            block_end = m.end() + assign_m.end()
        block = text[m.end() : block_end]
        pieces = _extract_key_prefixed_xor_literals(block, build_line_starts(block), max_hits=80, interesting_only=False)
        if len(pieces) < 2:
            continue
        rebuilt = "".join(piece for piece, _line, _n, _kind in pieces).strip()
        if not _looks_interesting_decoded_literal(rebuilt):
            continue
        line = offset_to_line(starts, m.start())
        key = (rebuilt, line)
        if key in seen:
            continue
        seen.add(key)
        out.append((rebuilt, line, len(pieces), "key_prefix_xor_stringbuilder"))
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
    if DOMAIN_NAME_RE.match(d):
        return "comms_indicator"
    if d in {"Content-Type", "application/json"}:
        return "http_header"
    if "jsonrpc" in low or "eth_call" in low:
        return "rpc_template"
    if HEX_ADDR_RE.match(d):
        return "hex_or_contract"
    if BITCOIN_ADDRESS_RE.search(d):
        return "cryptocurrency_address"
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
    if d in {"java.home", "java.version", "java.io.tmpdir", "java.class.path"}:
        return "path"
    if d.startswith("java."):
        return "comms_indicator"
    if low in {"localappdata", "appdata", "temp", "userprofile", "programdata"}:
        return "path"
    if d.lower().startswith("user-agent") or d.lower().startswith("content-type"):
        return "http_header"
    if d.startswith("-"):
        return "dynamic_execution"
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


def _run_decipher_only(file_path_str: str) -> int:
    """Standalone CLI mode: decipher a single .java file and output JSON."""
    import json as _json

    path = Path(file_path_str).resolve()
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    if not path.suffix.lower() == ".java":
        print(f"error: expected a .java file: {path}", file=sys.stderr)
        return 2

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        print(f"error: cannot read file: {exc}", file=sys.stderr)
        return 2

    results = extract_and_decode_all_strings(source)
    decoded_count = sum(1 for r in results if r["success"])

    # Categorize decoded strings
    categories: dict[str, list[str]] = {}
    for r in results:
        if not r["success"]:
            continue
        s = r["decoded_string"]
        low = s.lower()
        if URL_RE.match(s):
            cat = "urls_domains"
        elif WINDOWS_PATH_RE.match(s):
            cat = "suspicious_windows_paths"
        elif s.startswith("/"):
            cat = "file_paths"
        elif COMMAND_LITERAL_RE.search(s):
            cat = "command_execution"
        elif any(k in low for k in ("aes", "cipher", "secretkeyspec", "ivparameterspec", "doFinal", "base64", "xor")):
            cat = "crypto_strings"
        elif any(k in low for k in ("minecraft", "latest.log", "session", "launcher_accounts", "accessToken")):
            cat = "minecraft_log_strings"
        elif URL_RE.match(s) and ("shard/" in low or "cdn/" in low or "api/" in low):
            cat = "http_endpoints"
        elif "\\microsoft\\" in low or "ntprofileindex" in low or "localappdata" in low or "appdata" in low:
            cat = "suspicious_windows_paths"
        else:
            cat = "other_strings"
        categories.setdefault(cat, []).append(s)

    out_path = path.with_suffix(".deciphered.json")
    payload = {
        "source_file": str(path),
        "total_patterns": len(results),
        "decoded_count": decoded_count,
        "categories": {k: sorted(set(v)) for k, v in categories.items()},
        "decoded_strings": [
            {
                "line": r["line_number"],
                "offset": r["byte_offset"],
                "source_type": r["source_type"],
                "decoded": r["decoded_string"],
                "original_literal_preview": r["original_literal"][:80],
            }
            for r in results
            if r["success"]
        ],
    }
    out_path.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
    print(f"decoded {decoded_count}/{len(results)} strings -> {out_path}")
    for cat, vals in sorted(payload["categories"].items()):
        print(f"  {cat}: {len(vals)} unique strings")
    return 0


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

    if DISCORD_SNOWFLAKE_RE.match(d) and not _is_binary_looking_digits(d):
        return "discord_snowflake_id", "snowflake_numeric_id"

    if DISCORD_ID_CONTEXT_RE.search(d):
        # Check for a real snowflake that isn't binary-looking
        snowflake_candidates = [m.group(0) for m in DISCORD_SNOWFLAKE_ANY_RE.finditer(d)]
        real_snowflakes = [s for s in snowflake_candidates if not _is_binary_looking_digits(s)]
        if real_snowflakes:
            return "discord_contextual_id", f"contextual_snowflake_in_literal id={real_snowflakes[0]}"

    if "discord.com/api/webhooks/" in low or "discordapp.com/api/webhooks/" in low:
        return "discord_webhook_path", "webhook_pattern_fragment"

    # Catch Discord-related keywords that indicate bot/webhook usage
    if DISCORD_KEYWORD_PATTERNS.search(d):
        return "discord_webhook_keyword", "discord_notification_or_bot_context"

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

        # Never skip high-value indicators like Bitcoin, crypto, Discord, endpoint
        has_high_value_signal = bool(
            discord_kind or endpoint_kind
            or BITCOIN_ADDRESS_RE.search(decoded)
            or (len(compact) >= 80 and BASE64_RE.match(compact))
            or ETH_SELECTOR_RE.match(decoded)
            or (HEX_ADDR_RE.match(decoded) and len(decoded) == 42)
            or URL_RE.match(decoded)
            or COMMAND_LITERAL_RE.search(decoded)
        )
        if (not has_high_value_signal) and generic_hits >= max_hits:
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
        elif BITCOIN_ADDRESS_RE.search(decoded):
            category = "cryptocurrency_address"
            signal = "literal_btc_address"
        elif low.startswith("user-agent") or low.startswith("content-type") or low.startswith("content-"):
            category = "http_header"
            signal = "literal_http_header"
        elif low in {"localappdata", "appdata", "temp", "userprofile", "programdata"}:
            category = "path"
            signal = "literal_env_var_name"
        elif decoded.startswith("-"):
            category = "dynamic_execution"
            signal = "literal_cli_flag"
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


def iter_java_files(root: Path, include_pathological: bool = False) -> Iterable[Path]:
    for p in root.rglob("*.java"):
        if include_pathological or not _source_pathology(p).get("pathological"):
            yield p


def iter_pathological_java_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.java"):
        if _source_pathology(p).get("pathological"):
            yield p


def iter_class_files(root: Path) -> Iterable[Path]:
    yield from root.rglob("*.class")


MAX_SOURCE_SCAN_BYTES = 2_500_000
MAX_SOURCE_SCAN_LINE_BYTES = 250_000
MAX_ESKID_SOURCE_SCAN_BYTES = 300_000
MAX_ESKID_SOURCE_SCAN_LINE_BYTES = 12_000
ESKID_MARKER = "protected_by_eskid"


def _path_has_eskid_profile(path: Path) -> bool:
    for parent in [path.parent, *path.parents]:
        marker = parent / ".java_triage_jar_static_profile.json"
        if marker.is_file():
            try:
                data = json.loads(marker.read_text(encoding="utf-8", errors="replace"))
                return bool(data.get("eskid_marker") or "protected_by_eskid" in (data.get("notes") or []))
            except Exception:
                return False
    return False


def _source_pathology(path: Path) -> dict:
    """Fast guard for decompiler-hostile Java output.

    eSkid-style samples can make CFR/Vineflower emit megabyte-scale single
    lines and illegal identifiers. Running all source regexes over those files
    can look like a freeze, so classify them before full text scanning.
    """
    out = {
        "pathological": False,
        "reason": "",
        "size": 0,
        "max_line": 0,
        "eskid_marker": False,
    }
    try:
        st = path.stat()
        out["size"] = int(st.st_size)
        eskid_parent = _path_has_eskid_profile(path)
        if eskid_parent and st.st_size > MAX_ESKID_SOURCE_SCAN_BYTES:
            out["pathological"] = True
            out["reason"] = f"eskid_source_too_large:{st.st_size}"
            return out
        if st.st_size > MAX_SOURCE_SCAN_BYTES:
            out["pathological"] = True
            out["reason"] = f"source_too_large:{st.st_size}"
            return out
        max_line = 0
        marker = False
        with path.open("rb") as fh:
            for raw in fh:
                ln = len(raw)
                if ln > max_line:
                    max_line = ln
                if ESKID_MARKER.encode("ascii") in raw:
                    marker = True
                if eskid_parent and ln > MAX_ESKID_SOURCE_SCAN_LINE_BYTES:
                    out["pathological"] = True
                    out["reason"] = f"eskid_line_too_large:{ln}"
                    break
                if ln > MAX_SOURCE_SCAN_LINE_BYTES:
                    out["pathological"] = True
                    out["reason"] = f"line_too_large:{ln}"
                    break
        out["max_line"] = max_line
        out["eskid_marker"] = marker
        if marker and max_line > 50_000:
            out["pathological"] = True
            out["reason"] = "eskid_giant_line"
    except Exception as exc:
        out["pathological"] = True
        out["reason"] = f"read_error:{exc}"
    return out


def _pathology_finding(path: Path, root: Path, pathology: dict) -> Finding:
    try:
        rel = str(path.relative_to(root))
    except Exception:
        rel = str(path)
    reason = str(pathology.get("reason") or "pathological_source")
    size = int(pathology.get("size") or 0)
    max_line = int(pathology.get("max_line") or 0)
    note = f"source=source_guard signal={reason} size={size} max_line={max_line}"
    if pathology.get("eskid_marker"):
        note += " marker=protected_by_eskid"
    return Finding(
        file=rel,
        line=1,
        function="<source_guard>",
        decoded="Decompiler-hostile source skipped; use class constant-pool fallback / bytecode view",
        category="encrypted_or_unresolved",
        note=note,
    )


def _is_fallback_class_path(path: Path) -> bool:
    return ".java_triage_classes" in path.parts


def _scan_root_has_eskid_profile(root: Path) -> bool:
    marker = root / ".java_triage_jar_static_profile.json"
    if marker.is_file():
        try:
            data = json.loads(marker.read_text(encoding="utf-8", errors="replace"))
            if data.get("eskid_marker") or "protected_by_eskid" in (data.get("notes") or []):
                return True
        except Exception:
            pass
    try:
        for p in list(root.rglob("*.java"))[:50]:
            info = _source_pathology(p)
            if info.get("eskid_marker"):
                return True
    except Exception:
        pass
    return False


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


def _parse_classfile_static(class_bytes: bytes) -> dict:
    """Parse enough of a JVM class file for static indy/bootstrap triage."""
    if len(class_bytes) < 10 or class_bytes[:4] != b"\xCA\xFE\xBA\xBE":
        return {}
    off = 8

    def u1() -> int:
        nonlocal off
        if off + 1 > len(class_bytes):
            raise ValueError("truncated_u1")
        val = class_bytes[off]
        off += 1
        return val

    def u2() -> int:
        nonlocal off
        if off + 2 > len(class_bytes):
            raise ValueError("truncated_u2")
        val = int.from_bytes(class_bytes[off : off + 2], "big")
        off += 2
        return val

    def u4() -> int:
        nonlocal off
        if off + 4 > len(class_bytes):
            raise ValueError("truncated_u4")
        val = int.from_bytes(class_bytes[off : off + 4], "big")
        off += 4
        return val

    def skip(n: int) -> None:
        nonlocal off
        if n < 0 or off + n > len(class_bytes):
            raise ValueError("truncated_skip")
        off += n

    try:
        cp_count = u2()
        cp: List[dict | None] = [None] * cp_count
        idx = 1
        while idx < cp_count:
            tag = u1()
            item: dict = {"tag": tag}
            if tag == 1:
                ln = u2()
                raw = class_bytes[off : off + ln]
                skip(ln)
                item["value"] = raw.decode("utf-8", errors="replace")
            elif tag == 3:
                val = u4()
                item["value"] = val - 0x100000000 if val & 0x80000000 else val
            elif tag == 4:
                skip(4)
            elif tag == 5:
                val = int.from_bytes(class_bytes[off : off + 8], "big", signed=True)
                skip(8)
                item["value"] = val
                cp[idx] = item
                idx += 2
                continue
            elif tag == 6:
                skip(8)
                cp[idx] = item
                idx += 2
                continue
            elif tag in {7, 8, 16, 19, 20}:
                item["index"] = u2()
            elif tag in {9, 10, 11}:
                item["class_index"] = u2()
                item["name_and_type_index"] = u2()
            elif tag == 12:
                item["name_index"] = u2()
                item["descriptor_index"] = u2()
            elif tag == 15:
                item["reference_kind"] = u1()
                item["reference_index"] = u2()
            elif tag in {17, 18}:
                item["bootstrap_method_attr_index"] = u2()
                item["name_and_type_index"] = u2()
            else:
                raise ValueError(f"unknown_cp_tag_{tag}")
            cp[idx] = item
            idx += 1

        def utf(cp_index: int) -> str:
            if 0 < cp_index < len(cp):
                item = cp[cp_index] or {}
                if item.get("tag") == 1:
                    return str(item.get("value") or "")
            return ""

        def cp_value(cp_index: int):
            if not (0 < cp_index < len(cp)):
                return None
            item = cp[cp_index] or {}
            tag = item.get("tag")
            if tag == 1:
                return item.get("value")
            if tag in {3, 5}:
                return item.get("value")
            if tag == 7:
                return {"kind": "class", "name": utf(int(item.get("index") or 0))}
            if tag == 8:
                return {"kind": "string", "value": utf(int(item.get("index") or 0))}
            if tag == 16:
                return {"kind": "method_type", "descriptor": utf(int(item.get("index") or 0))}
            if tag == 12:
                return {
                    "kind": "name_and_type",
                    "name": utf(int(item.get("name_index") or 0)),
                    "descriptor": utf(int(item.get("descriptor_index") or 0)),
                }
            if tag in {9, 10, 11}:
                cls = cp_value(int(item.get("class_index") or 0))
                nt = cp_value(int(item.get("name_and_type_index") or 0))
                return {
                    "kind": {9: "field_ref", 10: "method_ref", 11: "interface_method_ref"}.get(tag),
                    "owner": (cls or {}).get("name") if isinstance(cls, dict) else None,
                    "name": (nt or {}).get("name") if isinstance(nt, dict) else None,
                    "descriptor": (nt or {}).get("descriptor") if isinstance(nt, dict) else None,
                }
            if tag == 15:
                ref = cp_value(int(item.get("reference_index") or 0))
                out = {
                    "kind": "method_handle",
                    "reference_kind": item.get("reference_kind"),
                    "reference": ref,
                }
                if isinstance(ref, dict):
                    out.update(
                        {
                            "owner": ref.get("owner"),
                            "name": ref.get("name"),
                            "descriptor": ref.get("descriptor"),
                        }
                    )
                return out
            if tag in {17, 18}:
                nt = cp_value(int(item.get("name_and_type_index") or 0))
                return {
                    "kind": "dynamic" if tag == 17 else "invokedynamic",
                    "bootstrap_method_attr_index": item.get("bootstrap_method_attr_index"),
                    "name": (nt or {}).get("name") if isinstance(nt, dict) else None,
                    "descriptor": (nt or {}).get("descriptor") if isinstance(nt, dict) else None,
                }
            return None

        access_flags = u2()
        this_class = u2()
        super_class = u2()
        interfaces_count = u2()
        skip(2 * interfaces_count)

        fields_count = u2()
        for _ in range(fields_count):
            skip(6)
            attr_count = u2()
            for _ in range(attr_count):
                skip(2)
                attr_len = u4()
                skip(attr_len)

        method_invokedynamics: list[dict] = []
        methods_count = u2()
        for _ in range(methods_count):
            skip(2)
            method_name = utf(u2())
            method_descriptor = utf(u2())
            attr_count = u2()
            for _ in range(attr_count):
                attr_name = utf(u2())
                attr_len = u4()
                attr_start = off
                if attr_name == "Code" and attr_len >= 8:
                    max_stack = u2()
                    max_locals = u2()
                    code_len = u4()
                    code_start = off
                    code = class_bytes[code_start : code_start + code_len]
                    skip(code_len)
                    i = 0
                    while i < len(code):
                        op = code[i]
                        if op == 0xBA and i + 4 < len(code):  # invokedynamic
                            cp_index = int.from_bytes(code[i + 1 : i + 3], "big")
                            indy = cp_value(cp_index)
                            item = {
                                "method": method_name,
                                "method_descriptor": method_descriptor,
                                "bytecode_offset": i,
                                "constant_pool_index": cp_index,
                            }
                            if isinstance(indy, dict):
                                item.update(
                                    {
                                        "bootstrap_method_attr_index": indy.get("bootstrap_method_attr_index"),
                                        "name": indy.get("name"),
                                        "descriptor": indy.get("descriptor"),
                                    }
                                )
                            method_invokedynamics.append(item)
                            i += 5
                        else:
                            i += _jvm_instruction_size(code, i)
                    exception_table_len = u2()
                    skip(8 * exception_table_len)
                    code_attr_count = u2()
                    for _ in range(code_attr_count):
                        skip(2)
                        code_attr_len = u4()
                        skip(code_attr_len)
                off = attr_start + attr_len

        bootstrap_methods: list[dict] = []
        class_attr_count = u2()
        for _ in range(class_attr_count):
            attr_name = utf(u2())
            attr_len = u4()
            attr_start = off
            if attr_name == "BootstrapMethods" and attr_len >= 2:
                bm_count = u2()
                for bm_index in range(bm_count):
                    handle_index = u2()
                    arg_count = u2()
                    args = [cp_value(u2()) for _ in range(arg_count)]
                    handle = cp_value(handle_index)
                    bootstrap_methods.append(
                        {
                            "index": bm_index,
                            "method_handle_index": handle_index,
                            "method_handle": handle,
                            "arguments": args,
                            "arguments_count": len(args),
                        }
                    )
            off = attr_start + attr_len

        invokedynamic_constants: list[dict] = []
        for cp_index, item in enumerate(cp):
            if not item or item.get("tag") != 18:
                continue
            value = cp_value(cp_index)
            if isinstance(value, dict):
                value["constant_pool_index"] = cp_index
                invokedynamic_constants.append(value)

        this_info = cp_value(this_class)
        super_info = cp_value(super_class)
        return {
            "class_name": (this_info or {}).get("name") if isinstance(this_info, dict) else "",
            "super_name": (super_info or {}).get("name") if isinstance(super_info, dict) else "",
            "access_flags": access_flags,
            "bootstrap_methods": bootstrap_methods,
            "invokedynamic_constants": invokedynamic_constants,
            "invokedynamic_instructions": method_invokedynamics,
        }
    except Exception as exc:
        return {"error": str(exc)}


def _jvm_instruction_size(code: bytes, offset: int) -> int:
    op = code[offset]
    if op == 0xAA:  # tableswitch
        pad = (4 - ((offset + 1) % 4)) % 4
        base = offset + 1 + pad
        if base + 12 > len(code):
            return max(1, len(code) - offset)
        low = int.from_bytes(code[base + 4 : base + 8], "big", signed=True)
        high = int.from_bytes(code[base + 8 : base + 12], "big", signed=True)
        return 1 + pad + 12 + max(0, high - low + 1) * 4
    if op == 0xAB:  # lookupswitch
        pad = (4 - ((offset + 1) % 4)) % 4
        base = offset + 1 + pad
        if base + 8 > len(code):
            return max(1, len(code) - offset)
        npairs = int.from_bytes(code[base + 4 : base + 8], "big", signed=True)
        return 1 + pad + 8 + max(0, npairs) * 8
    if op == 0xC4:  # wide
        if offset + 1 >= len(code):
            return 1
        return 6 if code[offset + 1] == 0x84 else 4
    fixed = {
        **{x: 1 for x in list(range(0x00, 0x10)) + list(range(0x1A, 0x35)) + list(range(0x3B, 0x84)) + list(range(0x85, 0x99)) + [0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xBE, 0xBF, 0xC2, 0xC3]},
        **{x: 2 for x in [0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3A, 0xA9, 0xBC]},
        **{x: 3 for x in [0x11, 0x13, 0x14, 0x84] + list(range(0x99, 0xA8)) + [0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xBB, 0xBD, 0xC0, 0xC1]},
        **{x: 4 for x in [0xC5]},
        **{x: 5 for x in [0xB9, 0xBA, 0xC8, 0xC9]},
    }
    return fixed.get(op, 1)


def _method_descriptor_return_type(descriptor: str) -> str:
    if not descriptor or ")" not in descriptor:
        return ""
    return descriptor.rsplit(")", 1)[-1]


def _indy_return_category(descriptor: str) -> str:
    ret = _method_descriptor_return_type(descriptor)
    if ret == "Ljava/lang/String;":
        return "string"
    if ret == "[B":
        return "byte_array"
    if ret == "Ljava/lang/Class;":
        return "class"
    if ret in {"Ljava/lang/Object;", "Ljava/lang/invoke/MethodHandle;", "Ljava/lang/invoke/CallSite;"}:
        return "dynamic_object"
    if ret.startswith("Lme/mioclient/") or ret.startswith("L") or ret.startswith("[L"):
        return "object"
    if ret in {"I", "J", "Z", "D", "F", "S", "B", "C"}:
        return "primitive"
    if ret == "V":
        return "void"
    if ret.startswith("["):
        return "array"
    return "unknown"


def produce_invokedynamic_bootstrap_map(root: Path, show_progress: bool, progress_console=None) -> dict:
    class_files = list((root / ".java_triage_classes").rglob("*.class")) if (root / ".java_triage_classes").is_dir() else list(iter_class_files(root))
    class_entries: list[dict] = []
    bootstrap_owner_counts: dict[str, int] = {}
    suspicious_bootstraps: list[dict] = []
    protected_class_pairs: list[dict] = []
    return_category_counts: dict[str, int] = {}
    high_value_sites: list[dict] = []
    invokedynamic_total = 0
    bootstrap_total = 0

    for class_path in class_files:
        try:
            rel = str(class_path.relative_to(root))
            parsed = _parse_classfile_static(class_path.read_bytes())
        except Exception:
            continue
        if not parsed:
            continue
        if parsed.get("error"):
            class_entries.append({"source": rel, "error": parsed.get("error")})
            continue
        bms = parsed.get("bootstrap_methods") or []
        indys = parsed.get("invokedynamic_constants") or []
        indy_ins = parsed.get("invokedynamic_instructions") or []
        if not bms and not indys and not indy_ins:
            continue
        invokedynamic_total += len(indy_ins) or len(indys)
        bootstrap_total += len(bms)

        slim_bms: list[dict] = []
        for bm in bms:
            mh = bm.get("method_handle") or {}
            owner = str(mh.get("owner") or "")
            name = str(mh.get("name") or "")
            descriptor = str(mh.get("descriptor") or "")
            owner_key = f"{owner}.{name}{descriptor}" if owner or name else "<unknown>"
            bootstrap_owner_counts[owner_key] = bootstrap_owner_counts.get(owner_key, 0) + 1
            suspicious = bool(owner and not owner.startswith(("java/", "javax/", "sun/", "jdk/")))
            slim = {
                "index": bm.get("index"),
                "owner": owner,
                "name": name,
                "descriptor": descriptor,
                "reference_kind": mh.get("reference_kind"),
                "arguments_count": bm.get("arguments_count"),
                "arguments": bm.get("arguments", [])[:12],
                "suspicious_non_jdk_owner": suspicious,
            }
            slim_bms.append(slim)
            if suspicious:
                suspicious_bootstraps.append({"source": rel, **slim})
                protected_class_pairs.append(
                    {
                        "protected_class": parsed.get("class_name"),
                        "source": rel,
                        "bootstrap_owner": owner,
                        "bootstrap_name": name,
                        "bootstrap_descriptor": descriptor,
                    }
                )

        for site in indy_ins:
            descriptor = str(site.get("descriptor") or "")
            category = _indy_return_category(descriptor)
            return_category_counts[category] = return_category_counts.get(category, 0) + 1
            if category in {"string", "byte_array", "class", "dynamic_object"}:
                high_value_sites.append(
                    {
                        "source": rel,
                        "class_name": parsed.get("class_name"),
                        "method": site.get("method"),
                        "bytecode_offset": site.get("bytecode_offset"),
                        "bootstrap_method_attr_index": site.get("bootstrap_method_attr_index"),
                        "name": site.get("name"),
                        "descriptor": descriptor,
                        "return_category": category,
                    }
                )

        class_entries.append(
            {
                "source": rel,
                "class_name": parsed.get("class_name"),
                "bootstrap_methods": slim_bms[:200],
                "bootstrap_methods_count": len(bms),
                "invokedynamic_constants": indys[:500],
                "invokedynamic_constants_count": len(indys),
                "invokedynamic_instructions": indy_ins[:1000],
                "invokedynamic_instructions_count": len(indy_ins),
            }
        )

    top_bootstrap_owners = sorted(bootstrap_owner_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:50]
    payload = {
        "root": str(root),
        "class_files_count": len(class_files),
        "classes_with_invokedynamic_or_bootstrap": len(class_entries),
        "bootstrap_methods_count": bootstrap_total,
        "invokedynamic_sites_count": invokedynamic_total,
        "top_bootstrap_owners": [{"owner": owner, "count": count} for owner, count in top_bootstrap_owners],
        "return_category_counts": dict(sorted(return_category_counts.items())),
        "protected_class_pairs": protected_class_pairs[:1000],
        "high_value_sites_count": len(high_value_sites),
        "high_value_sites": high_value_sites[:2000],
        "suspicious_bootstraps_count": len(suspicious_bootstraps),
        "suspicious_bootstraps": suspicious_bootstraps[:1000],
        "classes": class_entries[:1000],
        "truncated": len(class_entries) > 1000,
    }
    json_path = root / ".java_triage_indy_bootstrap_map.json"
    try:
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8", errors="replace")
    except Exception as exc:
        return {
            "class_files_count": len(class_files),
            "bootstrap_methods_count": bootstrap_total,
            "invokedynamic_sites_count": invokedynamic_total,
            "error": str(exc),
        }
    progress(
        show_progress,
        f"invokedynamic bootstrap map ready: {json_path.name} indy_sites={invokedynamic_total} suspicious_bootstraps={len(suspicious_bootstraps)}",
        progress_console,
    )
    return {
        "class_files_count": len(class_files),
        "bootstrap_methods_count": bootstrap_total,
        "invokedynamic_sites_count": invokedynamic_total,
        "suspicious_bootstraps_count": len(suspicious_bootstraps),
        "high_value_sites_count": len(high_value_sites),
        "json": str(json_path),
    }


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


def _is_printable_string_dump_value(s: str) -> bool:
    if len(s) < 4 or len(s) > 5000:
        return False
    printable = sum(1 for ch in s if ch in "\t\r\n" or 32 <= ord(ch) <= 126)
    return printable / max(1, len(s)) >= 0.80


def _aes_candidate_kind(s: str) -> str:
    raw = s.strip()
    low = raw.lower()
    common_non_keys = {
        "bootstrapmethods",
        "findstaticgetter",
        "findstaticsetter",
        "nosuchmethodexception in",
        "longbitstodouble",
    }
    if raw in common_non_keys or low in common_non_keys:
        return ""
    if raw.startswith(("java/", "javax/", "sun/", "jdk/", "org/", "com/")):
        return ""
    if any(tok in raw for tok in (";", "(", ")", "<", ">", ".class")):
        return ""

    def plausible_key_material(value: str) -> bool:
        if len(set(value)) < 8:
            return False
        # Avoid ordinary identifiers while allowing punctuation-heavy obfuscated keys.
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.$-]*", value):
            return False
        freq = {}
        for ch in value:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(value)
            entropy -= p * math.log2(p)
        return entropy >= 3.2

    if len(raw) in {16, 24, 32} and _is_printable_string_dump_value(raw):
        # Avoid flagging obvious class names/descriptors as keys.
        if not any(tok in raw for tok in ("/", "\\", "java", "class")) and plausible_key_material(raw):
            return f"raw_{len(raw)}_byte_candidate"
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{48}|[A-Fa-f0-9]{64}", raw):
        return f"hex_{len(raw)//2}_byte_candidate"
    if re.fullmatch(r"[A-Za-z0-9+/]{22,44}={0,2}", raw):
        if "/" in raw and raw.startswith(("java/", "javax/", "org/", "com/")):
            return ""
        try:
            decoded = base64.b64decode(raw, validate=True)
            if len(decoded) in {16, 24, 32}:
                return f"base64_{len(decoded)}_byte_candidate"
        except Exception:
            pass
    return ""


def produce_post_deobf_string_dump(root: Path, show_progress: bool, progress_console=None) -> dict:
    """Write a post-prep string dump for hostile samples.

    The dump intentionally favors normalized/extracted class constants over
    giant decompiler output. This catches hardcoded AES material even when CFR
    source is too hostile to scan deeply.
    """
    entries: List[dict] = []
    aes_candidates: List[dict] = []
    seen: set[tuple[str, str]] = set()
    class_files = list((root / ".java_triage_classes").rglob("*.class")) if (root / ".java_triage_classes").is_dir() else list(iter_class_files(root))
    for class_path in class_files:
        try:
            rel = str(class_path.relative_to(root))
            raw = class_path.read_bytes()
        except Exception:
            continue
        for value in _extract_class_utf8_constants(raw, max_items=12000):
            value = value.strip()
            if not _is_printable_string_dump_value(value):
                continue
            key = (rel, value)
            if key in seen:
                continue
            seen.add(key)
            item = {"source": rel, "kind": "class_constant", "value": value}
            entries.append(item)
            cand = _aes_candidate_kind(value)
            low = value.lower()
            if cand or "aes" in low or "secretkeyspec" in low or "cipher" in low:
                aes_item = dict(item)
                aes_item["candidate"] = cand or "crypto_context_string"
                aes_candidates.append(aes_item)

    for java_path in iter_java_files(root):
        if _source_pathology(java_path).get("pathological"):
            continue
        try:
            rel = str(java_path.relative_to(root))
            text = java_path.read_text(encoding="utf-8", errors="replace")
            starts = build_line_starts(text)
        except Exception:
            continue
        for m in STRING_ANY_LITERAL_RE.finditer(text):
            value = _unescape_java_literal(m.group(1)).strip()
            if not _is_printable_string_dump_value(value):
                continue
            key = (rel, value)
            if key in seen:
                continue
            seen.add(key)
            item = {
                "source": rel,
                "kind": "java_literal",
                "line": offset_to_line(starts, m.start()),
                "value": value,
            }
            entries.append(item)
            cand = _aes_candidate_kind(value)
            low = value.lower()
            if cand or "aes" in low or "secretkeyspec" in low or "cipher" in low:
                aes_item = dict(item)
                aes_item["candidate"] = cand or "crypto_context_string"
                aes_candidates.append(aes_item)

    entries.sort(key=lambda x: (x.get("source", ""), x.get("kind", ""), x.get("value", "")))
    aes_candidates.sort(key=lambda x: (x.get("source", ""), x.get("candidate", ""), x.get("value", "")))
    payload = {
        "root": str(root),
        "strings_count": len(entries),
        "aes_candidates_count": len(aes_candidates),
        "aes_candidates": aes_candidates[:500],
        "strings": entries[:50000],
        "truncated": len(entries) > 50000,
    }
    json_path = root / ".java_triage_string_dump.json"
    txt_path = root / ".java_triage_string_dump.txt"
    try:
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8", errors="replace")
        with txt_path.open("w", encoding="utf-8", errors="replace") as fh:
            fh.write(f"# strings={len(entries)} aes_candidates={len(aes_candidates)}\n")
            fh.write("# AES candidates\n")
            for item in aes_candidates[:500]:
                fh.write(f"{item.get('candidate')} {item.get('source')} :: {item.get('value')}\n")
            fh.write("\n# All strings\n")
            for item in entries[:50000]:
                fh.write(f"{item.get('kind')} {item.get('source')} :: {item.get('value')}\n")
    except Exception as exc:
        return {"strings_count": len(entries), "aes_candidates_count": len(aes_candidates), "error": str(exc)}
    progress(
        show_progress,
        f"string dump ready: {json_path.name} strings={len(entries)} aes_candidates={len(aes_candidates)}",
        progress_console,
    )
    return {
        "strings_count": len(entries),
        "aes_candidates_count": len(aes_candidates),
        "json": str(json_path),
        "txt": str(txt_path),
    }


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


def _jar_static_profile(jar_path: Path) -> dict:
    app_prefixes = _dominant_app_prefixes(jar_path)
    out = {
        "malformed_class_dirs": 0,
        "space_class_names": 0,
        "class_count": 0,
        "app_class_count": 0,
        "eskid_marker": False,
        "manifest_main_class": "",
        "app_prefixes": list(app_prefixes),
        "notes": [],
    }
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            infos = zf.infolist()
            for info in infos:
                name = info.filename
                norm = name[:-1] if name.endswith(".class/") else name
                if name.endswith(".class/"):
                    out["malformed_class_dirs"] += 1
                if norm.endswith(".class"):
                    out["class_count"] += 1
                    if any(norm.startswith(pfx) for pfx in app_prefixes):
                        out["app_class_count"] += 1
                    stem = Path(norm).name
                    if stem.strip() in {".class", ""} or (stem.endswith(".class") and len(stem) > 240):
                        out["space_class_names"] += 1
                if name.upper() == "META-INF/MANIFEST.MF":
                    try:
                        mf = zf.read(info).decode("utf-8", errors="replace")
                        m = re.search(r"(?im)^Main-Class:\s*(.+?)\s*$", mf)
                        if m:
                            out["manifest_main_class"] = m.group(1).strip()
                    except Exception:
                        pass
            for info in infos:
                name = info.filename
                norm = name[:-1] if name.endswith(".class/") else name
                if not norm.endswith(".class"):
                    continue
                try:
                    raw = zf.read(info)
                except Exception:
                    continue
                if b"protected_by_eskid" in raw:
                    out["eskid_marker"] = True
                    break
    except Exception as exc:
        out["notes"].append(f"profile_error:{exc}")
    if out["malformed_class_dirs"]:
        out["notes"].append("class_entries_have_trailing_slash")
    if out["space_class_names"]:
        out["notes"].append("decompiler_hostile_space_class_name")
    if out["eskid_marker"]:
        out["notes"].append("protected_by_eskid")
    return out


def _rewrite_jar_entries(
    src: Path,
    dst: Path,
    *,
    strip_class_slash: bool = True,
    app_only: bool = False,
    app_prefixes: tuple[str, ...] = ("me/mioclient/installer/",),
) -> tuple[bool, dict]:
    stats = {"entries": 0, "renamed_class_entries": 0, "skipped_duplicates": 0, "written": 0}
    try:
        with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            seen: set[str] = set()
            for info in zin.infolist():
                name = info.filename
                newname = name[:-1] if strip_class_slash and name.endswith(".class/") else name
                if newname != name:
                    stats["renamed_class_entries"] += 1
                keep = newname.upper() == "META-INF/MANIFEST.MF" or any(newname.startswith(pfx) for pfx in app_prefixes)
                if app_only and not keep:
                    continue
                if newname in seen:
                    stats["skipped_duplicates"] += 1
                    continue
                seen.add(newname)
                try:
                    data = zin.read(info)
                except Exception:
                    continue
                zi = zipfile.ZipInfo(newname, info.date_time)
                zi.comment = info.comment
                zi.extra = info.extra
                zi.create_system = info.create_system
                zi.external_attr = info.external_attr
                zi.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(zi, data)
                stats["written"] += 1
            stats["entries"] = len(seen)
        return True, stats
    except Exception as exc:
        stats["error"] = str(exc)
        return False, stats


def _dominant_app_prefixes(jar_path: Path) -> tuple[str, ...]:
    """Infer likely first-party package roots for app-only decompilation.

    This keeps bundled libraries/decoys out of CFR while still handling samples
    whose package is not the Mio installer package.
    """
    counts: dict[str, int] = {}
    library_roots = (
        "com/google/",
        "org/json/",
        "org/slf4j/",
        "org/objectweb/",
        "kotlin/",
        "META-INF/",
    )
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for info in zf.infolist():
                name = info.filename[:-1] if info.filename.endswith(".class/") else info.filename
                if not name.endswith(".class"):
                    continue
                if any(name.startswith(root) for root in library_roots):
                    continue
                parts = name.split("/")[:-1]
                if len(parts) >= 3:
                    prefix = "/".join(parts[:3]) + "/"
                elif len(parts) >= 2:
                    prefix = "/".join(parts[:2]) + "/"
                elif len(parts) == 1:
                    prefix = parts[0] + "/"
                else:
                    continue
                counts[prefix] = counts.get(prefix, 0) + 1
    except Exception:
        return ("me/mioclient/installer/",)
    if not counts:
        return ("me/mioclient/installer/", "me/mioclient/loader/")
    total = sum(counts.values())
    selected = [
        prefix for prefix, count in sorted(counts.items(), key=lambda x: (-x[1], x[0]))
        if count >= 3 and (count / max(1, total)) >= 0.10
    ]
    return tuple(selected[:4] or [max(counts, key=counts.get)])


def _extract_class_files_from_jar(jar_path: Path, out_root: Path) -> int:
    class_root = out_root / ".java_triage_classes"
    count = 0
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for info in zf.infolist():
                name = info.filename[:-1] if info.filename.endswith(".class/") else info.filename
                if not name.endswith(".class"):
                    continue
                # Avoid writing deliberately impossible Windows filenames.
                if Path(name).name.strip() in {".class", ""} or len(Path(name).name) > 240:
                    continue
                dest = class_root / Path(name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(info))
                count += 1
    except Exception:
        return count
    return count


def _prepare_single_jar_scan_root(
    selected: Path,
    cwd: Path,
    cfr: Path,
    show_progress: bool,
    progress_console=None,
) -> Path:
    selected = selected.resolve()
    profile = _jar_static_profile(selected)
    work_jar = selected
    if profile.get("malformed_class_dirs") or profile.get("space_class_names"):
        normalized = cwd / f"{selected.stem}.java_triage.normalized.jar"
        ok, stats = _rewrite_jar_entries(selected, normalized, strip_class_slash=True, app_only=False)
        if ok:
            progress(
                show_progress,
                f"jar normalized: {normalized.name} class_slash_fixed={stats.get('renamed_class_entries', 0)}",
                progress_console,
            )
            work_jar = normalized
            profile = _jar_static_profile(work_jar)
        else:
            progress(show_progress, f"jar normalization failed: {stats.get('error', 'unknown error')}", progress_console)

    decompile_jar = work_jar
    fallback_class_jar = work_jar
    if profile.get("eskid_marker") and profile.get("app_class_count"):
        app_jar = cwd / f"{selected.stem}.java_triage.app-only.jar"
        app_prefixes = tuple(profile.get("app_prefixes") or _dominant_app_prefixes(work_jar))
        ok, stats = _rewrite_jar_entries(work_jar, app_jar, strip_class_slash=True, app_only=True, app_prefixes=app_prefixes)
        if ok and stats.get("written", 0):
            progress(
                show_progress,
                f"eSkid marker detected; using app-only decompile jar: {app_jar.name} prefixes={','.join(app_prefixes)}",
                progress_console,
            )
            decompile_jar = app_jar

    out_dir = (cwd / selected.stem).resolve()
    if out_dir.exists():
        if not out_dir.is_dir():
            print(f"error: output path exists and is not a directory: {out_dir}", file=sys.stderr)
            return cwd
        prepared_marker = out_dir / ".java_triage_jar_static_profile.json"
        if (profile.get("eskid_marker") or profile.get("malformed_class_dirs") or profile.get("space_class_names")) and not prepared_marker.is_file():
            out_dir = _resolve_unique_dir(cwd / f"{selected.stem}_triage").resolve()
            progress(
                show_progress,
                f"existing decompile lacks hostile-jar prep metadata; using fresh directory: {out_dir.name}",
                progress_console,
            )
        if sys.stdin.isatty():
            if out_dir.exists():
                reuse = _prompt_reuse_decompiled_dir(selected, out_dir, progress_console)
                if reuse:
                    progress(
                        show_progress,
                        f"reusing existing extracted directory for {selected.name}: {_display_report_path(out_dir, cwd)}",
                        progress_console,
                    )
                    return out_dir
                progress(show_progress, f"removing existing directory to re-decompile: {out_dir.name}", progress_console)
                shutil.rmtree(out_dir)
        else:
            if out_dir.exists() and prepared_marker.is_file():
                progress(
                    show_progress,
                    f"reusing existing extracted directory for {selected.name}: {_display_report_path(out_dir, cwd)}",
                    progress_console,
                )
                return out_dir
            if out_dir.exists():
                out_dir = _resolve_unique_dir(cwd / f"{selected.stem}_triage").resolve()
                progress(
                    show_progress,
                    f"existing decompile lacks hostile-jar prep metadata; using fresh directory: {out_dir.name}",
                    progress_console,
                )
    out_dir.mkdir(parents=True, exist_ok=True)

    class_count = int(profile.get("class_count") or 0)
    app_count = int(profile.get("app_class_count") or 0)
    if profile.get("eskid_marker") and class_count >= 80 and app_count / max(1, class_count) >= 0.80:
        extracted_classes = _extract_class_files_from_jar(fallback_class_jar, out_dir)
        progress(
            show_progress,
            f"eSkid class-only fast path: skipped CFR decompile, extracted {extracted_classes} class file(s)",
            progress_console,
        )
        _write_source_jar_metadata(out_dir, selected)
        try:
            profile["cfr_skipped"] = True
            profile["cfr_skip_reason"] = "eskid_all_first_party_decompile_hostile"
            (out_dir / ".java_triage_jar_static_profile.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")
        except Exception:
            pass
        return out_dir

    cp = _run_subprocess_with_progress(
        ["java", "-jar", str(cfr), str(decompile_jar), "--outputdir", str(out_dir), "--renameillegalidents", "true", "--renamedupmembers", "true"],
        f"CFR decompiling {decompile_jar.name}",
        show_progress,
        progress_console,
    )
    if cp.returncode != 0:
        err = (cp.stderr or cp.stdout or "").strip()
        print(f"error: CFR decompilation failed for {decompile_jar.name}", file=sys.stderr)
        if err:
            print(err, file=sys.stderr)
        return cwd

    extracted_classes = _extract_class_files_from_jar(fallback_class_jar, out_dir)
    if extracted_classes:
        progress(show_progress, f"extracted {extracted_classes} class file(s) for constant-pool fallback", progress_console)
    if not any(out_dir.rglob("*.java")) and extracted_classes == 0:
        print(f"error: CFR did not produce Java source or fallback classes in {out_dir}", file=sys.stderr)
        return cwd
    _write_source_jar_metadata(out_dir, selected)
    try:
        (out_dir / ".java_triage_jar_static_profile.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")
    except Exception:
        pass
    return out_dir


def _decompile_jar_with_cfr(
    jar_path: Path,
    out_dir: Path,
    cfr_path: Path,
    show_progress: bool,
    progress_console=None,
) -> tuple[bool, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    original_jar = jar_path
    work_jar = jar_path
    fallback_class_jar = jar_path
    profile = _jar_static_profile(jar_path)
    if profile.get("malformed_class_dirs") or profile.get("space_class_names"):
        normalized = out_dir.parent / f"{jar_path.stem}.java_triage.normalized.jar"
        ok, stats = _rewrite_jar_entries(jar_path, normalized, strip_class_slash=True, app_only=False)
        if ok:
            progress(
                show_progress,
                f"jar normalized: {normalized.name} class_slash_fixed={stats.get('renamed_class_entries', 0)}",
                progress_console,
            )
            work_jar = normalized
            fallback_class_jar = normalized
            profile = _jar_static_profile(work_jar)
    if profile.get("eskid_marker") and profile.get("app_class_count"):
        app_jar = out_dir.parent / f"{jar_path.stem}.java_triage.app-only.jar"
        app_prefixes = tuple(profile.get("app_prefixes") or _dominant_app_prefixes(work_jar))
        ok, stats = _rewrite_jar_entries(work_jar, app_jar, strip_class_slash=True, app_only=True, app_prefixes=app_prefixes)
        if ok and stats.get("written", 0):
            progress(
                show_progress,
                f"eSkid marker detected; using app-only decompile jar: {app_jar.name} prefixes={','.join(app_prefixes)}",
                progress_console,
            )
            work_jar = app_jar
    class_count = int(profile.get("class_count") or 0)
    app_count = int(profile.get("app_class_count") or 0)
    if profile.get("eskid_marker") and class_count >= 80 and app_count / max(1, class_count) >= 0.80:
        extracted_classes = _extract_class_files_from_jar(fallback_class_jar, out_dir)
        _write_source_jar_metadata(out_dir, original_jar)
        try:
            profile["cfr_skipped"] = True
            profile["cfr_skip_reason"] = "eskid_all_first_party_decompile_hostile"
            (out_dir / ".java_triage_jar_static_profile.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")
        except Exception:
            pass
        progress(
            show_progress,
            f"eSkid class-only fast path: skipped CFR decompile, extracted {extracted_classes} class file(s)",
            progress_console,
        )
        return extracted_classes > 0, "" if extracted_classes > 0 else "No class files extracted for eSkid class-only fallback"
    cp = _run_subprocess_with_progress(
        ["java", "-jar", str(cfr_path), str(work_jar), "--outputdir", str(out_dir), "--renameillegalidents", "true", "--renamedupmembers", "true"],
        f"CFR decompiling {work_jar.name}",
        show_progress,
        progress_console,
    )
    if cp.returncode != 0:
        err = (cp.stderr or cp.stdout or "").strip()
        return False, f"CFR failed for {work_jar.name}: {err}" if err else f"CFR failed for {work_jar.name}"
    extracted_classes = _extract_class_files_from_jar(fallback_class_jar, out_dir)
    if not any(out_dir.rglob("*.java")) and extracted_classes == 0:
        return False, f"CFR produced no Java sources or fallback classes for {work_jar.name}"
    _write_source_jar_metadata(out_dir, original_jar)
    try:
        (out_dir / ".java_triage_jar_static_profile.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")
    except Exception:
        pass
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


def _prompt_select_nested_jars(jar_candidates: List[Path], scan_root: Path, console=None) -> List[int]:
    """Ask the user which nested JARs to process. Returns a list of 0-based indices
    into jar_candidates, or empty to skip all."""
    if RICH_AVAILABLE:
        ui_console = console or Console(stderr=True, width=_triage_ui_width())
        width = _triage_ui_width(ui_console)
        lines = [
            f"[bold #C000FF]Found {len(jar_candidates)} nested JAR(s)[/bold #C000FF] inside [italic]{scan_root.name}[/italic]:",
            "",
        ]
        for idx, jar in enumerate(jar_candidates, start=1):
            try:
                rel = str(jar.relative_to(scan_root))
            except Exception:
                rel = jar.name
            lines.append(f"  [bold white]{idx}.[/bold white] {rel}")
        lines += [
            "",
            "Enter numbers to process (comma/space separated), [bold]all[/bold], or [bold]none[/bold] (skip).",
            "Nested JARs are often bundled libraries from other triaged samples —",
            "only include the ones you believe are part of [italic]this[/italic] malicious payload.",
        ]
        ui_console.print(
            Panel(
                "\n".join(lines),
                border_style="#C000FF",
                width=width,
            )
        )
    else:
        print("", file=sys.stderr)
        print(f"Found {len(jar_candidates)} nested JAR(s) inside {scan_root.name}:", file=sys.stderr)
        for idx, jar in enumerate(jar_candidates, start=1):
            try:
                rel = str(jar.relative_to(scan_root))
            except Exception:
                rel = jar.name
            print(f"  {idx}. {rel}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Enter numbers to process (comma/space separated), 'all', or 'none' (skip).", file=sys.stderr)

    while True:
        print("Process which nested JARs? ", end="", file=sys.stderr, flush=True)
        try:
            raw = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("", file=sys.stderr)
            return []
        if not raw or raw in ("none", "n", "skip", "0"):
            print("", file=sys.stderr)
            return []
        if raw in ("all", "a"):
            print("", file=sys.stderr)
            return list(range(len(jar_candidates)))

        chosen: set[int] = set()
        tokens = raw.replace(",", " ").split()
        bad = False
        for t in tokens:
            if t.isdigit():
                v = int(t)
                if 1 <= v <= len(jar_candidates):
                    chosen.add(v - 1)
                else:
                    print(f"  {v} is out of range (1-{len(jar_candidates)}).", file=sys.stderr)
                    bad = True
            else:
                print(f"  '{t}' is not a valid number. Use numbers, 'all', or 'none'.", file=sys.stderr)
                bad = True
        if bad:
            continue
        if chosen:
            print("", file=sys.stderr)
            return sorted(chosen)
        print("  No valid selections. Use numbers, 'all', or 'none'.", file=sys.stderr)


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

    # Always ask — don't blindly decompile everything
    if not sys.stdin.isatty():
        progress(
            show_progress,
            f"stdin not interactive; skipping {len(jar_candidates)} nested JAR(s)",
            progress_console,
        )
        return []

    selected_indices = _prompt_select_nested_jars(jar_candidates, scan_root, progress_console)
    if not selected_indices:
        progress(show_progress, "no nested JARs selected; skipping nested dropped-jar scan", progress_console)
        return []

    out: List[tuple[Path, str]] = []
    for idx in selected_indices:
        jar_path = jar_candidates[idx]
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
    pathology = _source_pathology(path)
    if pathology.get("pathological"):
        try:
            rel = str(path.relative_to(root))
        except Exception:
            rel = str(path)
        reason = str(pathology.get("reason") or "pathological_source")
        marker_note = " marker=protected_by_eskid" if pathology.get("eskid_marker") else ""
        return [
            BehaviorFinding(
                file=rel,
                line=1,
                behavior="decompiler_failure_or_heavy_obfuscation",
                evidence=(
                    "Skipped expensive source behavior scan for decompiler-hostile source "
                    f"({reason}, size={int(pathology.get('size') or 0)}, "
                    f"max_line={int(pathology.get('max_line') or 0)}{marker_note})"
                ),
            )
        ]
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
    key_xor_literals = [(s, line, n) for s, line, n, _kind in _extract_key_prefixed_xor_literals(text)]
    key_xor_rebuilt = [(s, line, n) for s, line, n, _kind in _extract_key_prefixed_xor_stringbuilder_reconstructions(text)]
    full_xor_strings = [(s, line, n) for s, line, n, _kind in _extract_full_xor_decoded_strings(text)]
    inline_xor_strings = [(s, line, n) for s, line, n, _kind in _extract_inline_xor_decoded_strings(text)]
    obfuscated_string_pool = byte_array_strings + char_array_strings + reversed_literals + key_xor_literals + key_xor_rebuilt + full_xor_strings + inline_xor_strings
    obfuscated_values = [s for s, _, _ in obfuscated_string_pool]
    decoded_low_blob = "\n".join(obfuscated_values).lower()
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

    if (
        "Socket" in text
        and ("OutputStream" in text or "DataOutputStream" in text)
        and ("SSLSocket" in text or "SSLContext" in text or "https" in decoded_low_blob)
        and ("post" in decoded_low_blob or "content-type" in decoded_low_blob or "application/json" in decoded_low_blob)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "Socket"),
                behavior="raw_socket_http_post_client",
                evidence="Implements raw socket/SSLSocket HTTP client with POST/header/body construction instead of standard HttpURLConnection/HttpClient",
            )
        )

    if (
        ("eth_call" in decoded_low_blob or "jsonrpc" in decoded_low_blob)
        and ("polygon-rpc.com" in decoded_low_blob or "matic" in decoded_low_blob or "llamarpc" in decoded_low_blob)
        and re.search(r"0x[a-fA-F0-9]{40}", "\n".join(obfuscated_values))
        and re.search(r"0x[a-fA-F0-9]{8}", "\n".join(obfuscated_values))
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=next((line for s, line, _ in obfuscated_string_pool if "eth_call" in s.lower() or "jsonrpc" in s.lower()), 1),
                behavior="blockchain_dns_c2_resolver",
                evidence="Decoded strings reveal blockchain-backed C2/domain resolution via Polygon/Matic JSON-RPC eth_call, contract address, and method selector",
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
        "getInstance()",
        "func_110432_I()",
        "Minecraft.getMinecraft()",
        "Minecraft.func_71410_x()",
        "net.minecraft.client.MinecraftClient",
        "net.minecraft.class_310",
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
        "field_152429_d",
        "getProfile()",
        "func_148256_e()",
        "getSessionType()",
        "func_152428_f()",
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

    # Explicit methodology detections for obfuscated token/session access patterns.
    if ("decodeXor(" in text or "xor" in low) and ("Class.forName(" in text or "getDeclaredMethod(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "decodeXor(") if "decodeXor(" in text else find_line(text, "xor"),
                behavior="obf_xor_encoded_name_access",
                evidence="Uses XOR-decoded names to resolve token/session access methods reflectively",
            )
        )
    if ("Base64.getDecoder().decode(" in text and ("Class.forName(" in text or "getDeclaredMethod(" in text)):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "Base64.getDecoder().decode("),
                behavior="obf_base64_encoded_name_access",
                evidence="Uses Base64-decoded class/method names for reflective access",
            )
        )
    if any(k in low for k in ["caesar", "char-offset", "char offset"]) and ("Class.forName(" in text or "getDeclaredMethod(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "caesar") if "caesar" in low else find_line(text, "char"),
                behavior="obf_caesar_encoded_name_access",
                evidence="Uses character offset/Caesar-style decoding to reconstruct sensitive access names",
            )
        )
    if "MethodHandles" in text and ("findVirtual(" in text or "findGetter(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "MethodHandles"),
                behavior="obf_methodhandle_token_access",
                evidence="Uses MethodHandles lookup/findVirtual/findGetter to bypass straightforward reflection checks",
            )
        )
    if "LambdaMetafactory" in text and ("Supplier<" in text or "metafactory(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "LambdaMetafactory"),
                behavior="obf_lambdametafactory_token_access",
                evidence="Generates callable accessors via LambdaMetafactory for indirect token/session reads",
            )
        )
    if ("new String[]" in text or "new Method[" in text or "new Object[" in text) and ("dispatch" in low or "index" in low):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "new String[]") if "new String[]" in text else find_line(text, "new Method["),
                behavior="obf_array_indirect_dispatch_token_access",
                evidence="Uses array-indexed indirection for method/field dispatch to obscure call targets",
            )
        )
    if ("StringBuilder" in text and ".append(" in text and ("Class.forName(" in text or "getDeclaredMethod(" in text)):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "StringBuilder"),
                behavior="obf_split_reassembled_name_access",
                evidence="Reassembles class/method names from fragments before reflective sensitive access",
            )
        )
    if "sun.misc.Unsafe" in text and ("objectFieldOffset(" in text or "getObject(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "sun.misc.Unsafe"),
                behavior="obf_unsafe_field_token_access",
                evidence="Uses sun.misc.Unsafe field offsets and raw object reads for protected token/session fields",
            )
        )
    if "VarHandle" in text and ("findVarHandle(" in text or ".get(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "VarHandle"),
                behavior="obf_varhandle_field_token_access",
                evidence="Uses VarHandle-based field access to reach sensitive runtime state",
            )
        )
    if "StackWalker" in text and ("walk(" in text or "getCallerClass(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "StackWalker"),
                behavior="obf_stackwalker_indirect_access",
                evidence="Uses StackWalker/caller indirection to obscure sensitive access call path",
            )
        )
    if "new int[]" in text and ("(char)" in text or "StringBuilder" in text) and ("Class.forName(" in text or "getDeclaredMethod(" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "new int[]"),
                behavior="obf_int_array_encoded_name_access",
                evidence="Builds access names from integer arrays and uses reflective invocation",
            )
        )
    if ("FabricLoader" in text or "classloader" in low) and ("loadClass(" in text and ("session" in low or "user" in low)):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "FabricLoader") if "FabricLoader" in text else find_line(text, "loadClass("),
                behavior="obf_classloader_bypass_token_access",
                evidence="Uses alternate classloader/Fabric loader paths to reach session/token classes",
            )
        )

    # ── Inline first-byte-key XOR string obfuscation detection ──
    # Catches Skidfuscator-style inline byte[]/char[] XOR patterns where
    # string data is XOR'd with its first byte as key length, decoded inline
    # rather than via getBytes/toCharArray prefixed-key patterns.
    if INLINE_XOR_BYTE_ARRAY_LITERAL_RE.search(text) or INLINE_XOR_CHAR_ARRAY_LITERAL_RE.search(text):
        # Verify the pattern is complete (first-byte key extraction + new String)
        has_complete_pattern = False
        for m in INLINE_XOR_BYTE_ARRAY_LITERAL_RE.finditer(text):
            var = m.group("var")
            forward = text[m.start():m.start() + 1200]
            if f"{var}[0] & 0xFF" in forward and "new String(" in forward:
                has_complete_pattern = True
                break
        if not has_complete_pattern:
            for m in INLINE_XOR_CHAR_ARRAY_LITERAL_RE.finditer(text):
                var = m.group("var")
                forward = text[m.start():m.start() + 1200]
                if f"{var}[0]" in forward and "new String(" in forward:
                    has_complete_pattern = True
                    break
        if has_complete_pattern:
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "byte[]") if "byte[]" in text else find_line(text, "char[]"),
                    behavior="inline_xor_string_decoder",
                    evidence="Uses inline first-byte-key XOR pattern to decode obfuscated string literals at runtime (Skidfuscator-style). Strings decoded this way would otherwise evade static extraction.",
                )
            )

    # Breakthrough vectors and process-argument token harvesting methodology detections.
    if ("getAllLoadedClasses(" in text or "ClassLoader.class.getDeclaredField(\"classes\")" in text) and ("startsWith(\"eyJ\")" in text or "jwt" in low):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "getAllLoadedClasses(") if "getAllLoadedClasses(" in text else find_line(text, "ClassLoader.class.getDeclaredField(\"classes\")"),
                behavior="token_class_sweep_static_field_harvest",
                evidence="Sweeps loaded classes/static fields for JWT-like token strings",
            )
        )
    if ("Thread spinner" in text or "SpinRace" in text or "while (System.nanoTime() < deadline)" in text) and ("accessToken" in text and "Unsafe" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "SpinRace") if "SpinRace" in text else find_line(text, "while (System.nanoTime() < deadline)"),
                behavior="token_spin_race_window_harvest",
                evidence="Implements high-frequency polling race to capture transient real accessToken windows",
            )
        )
    if ("YggdrasilAuthenticationService" in text and ("drillAllFields" in text or "getDeclaredFields()" in text)):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "YggdrasilAuthenticationService"),
                behavior="token_yggdrasil_internal_probe",
                evidence="Introspects YggdrasilAuthenticationService internals for token side-channel extraction",
            )
        )
    if "--accessToken" in text and ("commandLine()" in text or "sun.java.command" in text):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "--accessToken"),
                behavior="token_process_commandline_harvest",
                evidence="Parses process command-line arguments for --accessToken credential leakage",
            )
        )
    if "ProcessHandle.current()" in text and "commandLine()" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "ProcessHandle.current()"),
                behavior="token_processhandle_commandline_probe",
                evidence="Reads process command line via ProcessHandle.info().commandLine()",
            )
        )
    if "ManagementFactory.getRuntimeMXBean()" in text and "getInputArguments()" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "ManagementFactory.getRuntimeMXBean()"),
                behavior="token_runtime_mxbean_arg_probe",
                evidence="Enumerates RuntimeMXBean JVM input arguments for auth/session leakage",
            )
        )
    if "System.getProperties()" in text and ("token" in low or "session" in low or "auth" in low):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "System.getProperties()"),
                behavior="token_system_property_auth_probe",
                evidence="Enumerates system properties for token/access/session/auth material",
            )
        )
    if "System.getenv()" in text and ("token" in low or "minecraft" in low or "mojang" in low):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "System.getenv()"),
                behavior="token_environment_auth_probe",
                evidence="Enumerates environment variables for token/access/auth indicators",
            )
        )
    if "sun.java.command" in text:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "sun.java.command"),
                behavior="token_sun_java_command_probe",
                evidence="Reads sun.java.command property to recover raw process launch arguments",
            )
        )
    if "ProcessHandleImpl" in text or "jdk.internal.process" in low:
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "ProcessHandleImpl") if "ProcessHandleImpl" in text else find_line(text, "jdk.internal.process"),
                behavior="token_jdk_internal_process_probe",
                evidence="Attempts jdk-internal process inspection pathways to obtain process/auth metadata",
            )
        )

    if (
        ("@Mixin(value = User.class" in text or "@Mixin(User.class" in text or "Mixin(value=User.class" in text)
        and 'method = "<init>"' in text
        and "accessToken" in text
        and ("startsWith(\"eyJ\")" in text or "BOOTSTRAP CAPTURE" in text or "onUserConstructed" in text)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, 'method = "<init>"'),
                behavior="token_bootstrap_constructor_capture",
                evidence="Mixin hooks Minecraft User.<init> at HEAD and captures accessToken constructor arguments before field mutation/protection",
            )
        )

    has_authlib_minecraftclient_mixin = (
        ("@Mixin(MinecraftClient.class)" in text or "com.mojang.authlib.minecraft.client.MinecraftClient" in text)
        and "accessToken" in text
        and "@Inject" in text
    )
    if has_authlib_minecraftclient_mixin and any(m in text for m in ["postInternal", "prepareRequest", "getWithEtag", "postWithEtag"]):
        hook = next((m for m in ["prepareRequest", "postInternal", "getWithEtag", "postWithEtag"] if m in text), "authlib hook")
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, hook),
                behavior="token_authlib_deep_hook_access",
                evidence="Injects into authlib MinecraftClient request flow and reads accessToken below normal Minecraft User/session wrappers",
            )
        )

    if (
        "HttpURLConnection" in text
        and "Authorization" in text
        and ('getRequestProperty("Authorization")' in text or "getRequestProperties()" in text)
        and ("accessToken" in text or "Bearer " in text or "startsWith(\"eyJ\")" in text or "contains(\"eyJ\")" in text)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, 'getRequestProperty("Authorization")'),
                behavior="token_connection_authorization_header_probe",
                evidence="Reads Authorization request headers from HttpURLConnection to recover bearer/JWT token material after request preparation",
            )
        )

    if (
        "URLConnection.class.getDeclaredField(\"requests\")" in text
        and "Authorization" in text
        and "sun.misc.Unsafe" in text
        and ("MessageHeader" in text or "findValue" in text)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "URLConnection.class.getDeclaredField(\"requests\")"),
                behavior="token_urlconnection_requests_unsafe_probe",
                evidence="Uses Unsafe to read URLConnection.requests/MessageHeader and extract Authorization header values directly",
            )
        )

    if (
        ("startConnectionRace(" in text or "CONNECTION mode" in text or "SpinRace-Conn" in text)
        and "HttpURLConnection" in text
        and "Authorization" in text
        and ("while (System.nanoTime() < deadline" in text or "deadlineNanos" in text)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "startConnectionRace(") if "startConnectionRace(" in text else find_line(text, "CONNECTION mode"),
                behavior="token_connection_spin_race_header_harvest",
                evidence="Implements high-frequency connection-header race to catch transient real Authorization/JWT values during auth requests",
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
    # Only flag if the HTTP destinations are NOT exclusively vendor-allowlisted hosts.
    outbound_http_present = bool(http_hosts or ("HttpClient" in text and "send(" in text) or ("OkHttpClient" in text and ".newCall(" in text) or ("HttpURLConnection" in text))
    # Check if ALL HTTP hosts in this file are known-safe (vendor-allowlisted).
    # If all hosts are vendor-trusted, identity access is expected (e.g., Discord RPC, skin fetchers).
    all_hosts_vendor = False
    if http_hosts:
        all_hosts_vendor = all(
            h in VENDOR_HOST_ALLOWLIST or any(h.endswith("." + d) for d in VENDOR_HOST_ALLOWLIST)
            for h in http_hosts
        )
    if outbound_http_present and (has_username_access_signal or has_uuid_access_signal) and not all_hosts_vendor:
        out.append(
            BehaviorFinding(
                file=rel,
                line=(find_line(text, ".getUsername()") if has_username_access_signal else find_line(text, ".getUuid()")),
                behavior="possible_minecraft_identity_exfiltration",
                evidence="Username/UUID read present alongside outbound HTTP activity to non-vendor hosts",
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

    if (
        has_get_access_token
        and "new hUvPFYp()" in text
        and ".getDomain()" in text
        and ".prefire(" in text
        and "Base64.getEncoder()" in text
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "method_1674()") if "method_1674()" in text else find_line(text, "getAccessToken()"),
                behavior="proof_minecraft_token_raw_socket_exfil_chain",
                evidence="Reads Minecraft access token/session identity, resolves C2 domain, builds encoded payload, and calls prefire() exfiltration path",
            )
        )

    if (
        ".writeUtffde(" in text
        and ("/shard/prefireMc" in decoded_low_blob or "prefiremc" in decoded_low_blob)
        and ("sessionid" in decoded_low_blob or "userid" in decoded_low_blob)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "writeUtffde("),
                behavior="proof_minecraft_token_raw_socket_exfil_chain",
                evidence="Decoded prefire() payload posts sessionId/userId JSON to /shard/prefireMc through raw socket HTTP client",
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

    # ── Coordinate exfiltration: player position → Discord/webhook ──
    if not is_vendor_lib:
        # Only flag Minecraft-specific coordinate types — NOT generic .getX()/.getY() from
        # font renderers, UI code, or geometry helpers.  Require BlockPos, Vec3d, or the
        # coordinate methods appearing with Minecraft player/entity context.
        has_coordinate_read = any(
            p in text for p in [
                ".xCoord", ".yCoord", ".zCoord",
                ".posX", ".posY", ".posZ",
                "getBlockPos()", "getPosition()",
                ".getPosition()", ".getPos()",
                "BlockPos", "Vec3d", "Vec3",
            ]
        )
        # Generic .getX()/.getY()/.getZ() is too broad (font renderers, UI, etc.) —
        # only count it if there's also a Minecraft entity/player reference nearby.
        has_generic_xyz = any(p in text for p in [".getX()", ".getY()", ".getZ()", ".x", ".y", ".z"])
        has_mc_context = any(
            p in text for p in [
                "class_746", "class_1297", "Entity", "PlayerEntity",
                "field_1724", "field_3937", "field_3944", "field_3951",
                "player", "entity", "LivingEntity", "ClientPlayerEntity",
            ]
        )
        if has_generic_xyz and not has_coordinate_read and not has_mc_context:
            # Generic x/y/z in a non-Minecraft context — likely font/UI/graphics code
            has_coordinate_read = False
        # Broader detection via decoded strings as well
        coord_in_obf = any(
            kw in decoded_low_blob for kw in [
                "getx()", "gety()", "getz()",
                "getpos()", "getposition()",
                "blockpos", "vec3d", "vec3",
                "coordinate", "position",
                ".x,", ", y,", ".z)",
            ]
        )
        has_coordinate_signal = has_coordinate_read or coord_in_obf

        has_discord_webhook_or_post = (
            "discord.com/api/webhooks/" in low
            or "discord.com/api/webhooks/" in decoded_low_blob
            or "discordapp.com/api/webhooks/" in low
            or "discordapp.com/api/webhooks/" in decoded_low_blob
            or ("discord" in low and "webhook" in low)
            or ("discord" in decoded_low_blob and "webhook" in decoded_low_blob)
        )
        has_outbound_post = (
            "HttpURLConnection" in text
            or "HttpClient" in text
            or "OkHttpClient" in text
            or ("OutputStream" in text and ".write(" in text and "ByteArrayOutputStream" not in text and "FileOutputStream" not in text)
            or "setRequestMethod" in text
        )

        if has_coordinate_signal and (has_discord_webhook_or_post or has_outbound_post):
            evidence_parts = []
            if has_discord_webhook_or_post:
                evidence_parts.append("Discord webhook or POST endpoint")
            elif has_outbound_post:
                evidence_parts.append("outbound HTTP POST capability")
            if has_coordinate_read:
                evidence_parts.append("direct coordinate method calls")
            elif coord_in_obf:
                evidence_parts.append("coordinate-related tokens in obfuscated strings")
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, ".getX()") if ".getX()" in text else find_line(text, "getBlockPos()") if "getBlockPos()" in text else find_line(text, "HttpURLConnection") if "HttpURLConnection" in text else 1,
                    behavior="minecraft_coordinate_exfiltration",
                    evidence=(
                        "Player coordinate/position data appears alongside exfiltration channel. "
                        + "; ".join(evidence_parts) + "."
                    ),
                )
            )

    # ── Discord webhook URL reassembly detection ──
    if not is_vendor_lib:
        # Check if webhook path fragments exist in XOR-decoded strings AND a snowflake ID is present
        has_webhook_path_fragment = (
            "discord.com/api/webhooks/" in decoded_low_blob
            or "discordapp.com/api/webhooks/" in decoded_low_blob
            or "api/webhooks/" in decoded_low_blob
        )
        has_snowflake_in_obf = any(
            not _is_binary_looking_digits(m.group(0))
            for s in obfuscated_values
            for m in DISCORD_SNOWFLAKE_ANY_RE.finditer(s)
        )
        _snow_text_match = DISCORD_SNOWFLAKE_ANY_RE.search(text)
        has_snowflake_in_text = bool(
            _snow_text_match and not _is_binary_looking_digits(_snow_text_match.group(0))
        )

        if has_webhook_path_fragment and (has_snowflake_in_obf or has_snowflake_in_text):
            # Look for the specific webhook URL assembly pattern: base URL + snowflake + token fragments
            snowflake_matches = []
            for s in obfuscated_values:
                for sm in DISCORD_SNOWFLAKE_ANY_RE.finditer(s):
                    candidate = sm.group(0)
                    if not _is_binary_looking_digits(candidate):
                        snowflake_matches.append(candidate)
            if not snowflake_matches:
                for sm in DISCORD_SNOWFLAKE_ANY_RE.finditer(text):
                    candidate = sm.group(0)
                    if not _is_binary_looking_digits(candidate):
                        snowflake_matches.append(candidate)
            snowflake_preview = ", ".join(snowflake_matches[:3])
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "discord.com/api/webhooks/") if "discord.com/api/webhooks/" in low else 1,
                    behavior="discord_webhook_url_reassembly",
                    evidence=(
                        "Discord webhook URL fragments detected in XOR-obfuscated or decoded strings — "
                        f"webhook path + snowflake ID(s) found ({snowflake_preview}). "
                        "The full webhook URL is likely assembled at runtime from these fragments, "
                        "indicating exfiltration to a Discord webhook."
                    ),
                )
            )

    # ── Data flow tracer: track MC API calls to network sinks ──
    if not is_vendor_lib:
        out.extend(_trace_minecraft_data_flow(text, rel, obfuscated_values))

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
    rpc_urls = sorted([
        f.decoded
        for f in findings
        if f.category == "url"
        and (
            "/eth" in f.decoded.lower()
            or "rpc" in f.decoded.lower()
            or "matic" in f.decoded.lower()
            or "polygon" in f.decoded.lower()
        )
        and "." in urlparse(str(f.decoded)).netloc
    ], key=len, reverse=True)
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
            # Build full URLs using the resolved domain + path fragments from findings
            _resolved_domain = decoded.split("|", 1)[0].strip() if decoded and not decoded.startswith("<binary ") else ""
            if _resolved_domain and "." in _resolved_domain:
                out["c2_base_url"] = f"https://{_resolved_domain}"
                # Search findings for known path fragments
                path_fragments = sorted(
                    {str(f.decoded).strip() for f in findings if f.category == "path" and str(f.decoded).startswith("/")},
                    key=len,
                    reverse=True,
                )
                path_low = [p.lower() for p in path_fragments]
                # Exfiltration endpoints
                for known, endpoint_key in [
                    ("/shard/prefiremc", "exfil_endpoint_prefiremc"),
                    ("/shard/prefireMc", "exfil_endpoint_prefiremc"),
                    ("/shard/submitminecraftlog", "exfil_endpoint_submit_log"),
                    ("/shard/submitMinecraftLog", "exfil_endpoint_submit_log"),
                ]:
                    if known.lower() in path_low or any(known.lower() in p for p in path_low):
                        if endpoint_key == "exfil_endpoint_prefiremc":
                            out["exfil_endpoint"] = f"https://{_resolved_domain}{known}"
                        else:
                            out["exfil_endpoint"] = out.get("exfil_endpoint", "") or f"https://{_resolved_domain}{known}"
                # CDN/payload endpoint
                for p in path_fragments:
                    if "cdn" in p.lower() or "/e/" in p.lower():
                        out["payload_endpoint"] = f"https://{_resolved_domain}{p}"
                        break
                if not out["payload_endpoint"] and out["exfil_endpoint"]:
                    out["payload_endpoint"] = out["exfil_endpoint"]
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


def detect_two_payload_exfil_architecture(root: Path) -> List[BehaviorFinding]:
    """Detect malware that sends multiple distinct exfiltration payloads to
    different endpoints — e.g. a lightweight prefire beacon followed by a
    full-profile POST with all stolen credentials.

    Now with richer breakdown: tracks exactly which data types flow to which
    endpoints and emits a detailed synthesis finding."""
    out: List[BehaviorFinding] = []
    idx = _build_source_index(root)
    texts: dict[str, str] = idx["texts"]
    rel_paths: List[str] = idx["rel_paths"]

    # Count distinct exfil endpoint shapes across the entire codebase
    exfil_shapes: set[str] = set()
    exfil_rel: dict[str, str] = {}
    exfil_data_types: dict[str, set[str]] = {}  # endpoint → data types

    for rel in rel_paths:
        if _is_known_library_relpath(rel):
            continue
        text = texts.get(rel, "")
        low = text.lower()

        # Also decode XOR-obfuscated strings for exfil endpoint patterns
        xor_decoded_low = ""
        try:
            xor_strings = [s for s, _l, _n, _k in _extract_full_xor_decoded_strings(text, max_hits=150)]
            xor_strings += [s for s, _l, _n, _k in _extract_inline_xor_decoded_strings(text, max_hits=150)]
            xor_decoded_low = "\n".join(xor_strings).lower()
        except Exception:
            pass
        combined_low = low + "\n" + xor_decoded_low

        # Detect which data types are being harvested in this file
        data_types_in_file: set[str] = set()
        if any(m in text for m in ["getAccessToken()", "method_1674()", "mcAccessToken", "access_token"]):
            data_types_in_file.add("mc_token")
        if any(m in text for m in ["getUsername()", "getName()", "method_1676()"]):
            data_types_in_file.add("mc_username")
        if any(m in text for m in ["getUuid()", "getProfileId()", "method_44717()", "GameProfile.getId()"]):
            data_types_in_file.add("mc_uuid")
        if any(m in text for m in ["getSessionId()", "method_1675()"]):
            data_types_in_file.add("mc_session_id")
        if any(m in combined_low for m in [".getX()", ".getY()", ".getZ()", "getBlockPos()", "getPosition()", "coordinates"]):
            data_types_in_file.add("player_coordinates")
        if any(m in combined_low for m in ["discord", "webhook", "leveldb", "local storage", "chromium"]):
            data_types_in_file.add("discord_tokens")
        if any(m in combined_low for m in ["latest.log", "combined.log", "stealer.log", "submitMinecraftLog"]):
            data_types_in_file.add("minecraft_logs")

        # Payload 1 shape: prefire / lightweight beacon
        if "/shard/prefiremc" in combined_low or "/shard/prefire" in combined_low:
            shape = "prefire_beacon"
            exfil_shapes.add(shape)
            exfil_rel[shape] = rel
            exfil_data_types.setdefault(shape, set()).update(data_types_in_file)

        # Payload 2 shape: full credential profile POST
        has_full_profile = (
            ("mcusername" in combined_low or "mc_user" in combined_low or '"tag"' in text or '"mcUsername"' in text)
            and ("mcuuid" in combined_low or '"mcUuid"' in text or '"gameDir"' in text)
            and ("mcInfo" in text or '"mcInfo"' in text or "prefireid" in combined_low or '"prefireId"' in text)
            and ("setRequestMethod" in text or "OutputStream" in text or "writeUtffde" in text or ".write(" in text)
        )
        if has_full_profile:
            shape = "full_profile_post"
            exfil_shapes.add(shape)
            exfil_rel[shape] = rel
            exfil_data_types.setdefault(shape, set()).update(data_types_in_file)

        # Payload 3 shape: Discord webhook multi-bundle
        has_discord_bundle = (
            ('delivery.add("minecraft"' in text or 'delivery.addProperty("minecraft"' in text)
            and ('delivery.add("discord"' in text or 'delivery.addProperty("discord"' in text)
            and ("setRequestMethod" in text or "writeUtffde" in text)
        )
        if has_discord_bundle:
            shape = "discord_multi_bundle"
            exfil_shapes.add(shape)
            exfil_rel[shape] = rel
            exfil_data_types.setdefault(shape, set()).update(data_types_in_file)

        # Payload 4 shape: Minecraft log exfiltration
        if "/shard/submitMinecraftLog" in combined_low or "/shard/submitLog" in combined_low:
            shape = "log_exfiltration"
            exfil_shapes.add(shape)
            exfil_rel[shape] = rel
            exfil_data_types.setdefault(shape, set()).update(data_types_in_file | {"minecraft_logs"})

        # Payload 5 shape: Coordinate → Discord webhook
        has_coordinate_discord = (
            any(m in combined_low for m in [".getX()", ".getY()", ".getZ()", "getBlockPos()", "getPosition()", "coordinates"])
            and ("discord" in combined_low and "webhook" in combined_low)
            and ("setRequestMethod" in text or "OutputStream" in text or ".write(" in text)
        )
        if has_coordinate_discord:
            shape = "coordinate_discord_exfil"
            exfil_shapes.add(shape)
            exfil_rel[shape] = rel
            exfil_data_types.setdefault(shape, set()).update({"player_coordinates"} | data_types_in_file)

    # Emit the original two_payload check
    if len(exfil_shapes) >= 2:
        shapes_str = " + ".join(sorted(exfil_shapes))
        anchor_rel = exfil_rel.get("full_profile_post") or exfil_rel.get("prefire_beacon") or "."
        out.append(
            BehaviorFinding(
                file=anchor_rel,
                line=1,
                behavior="two_payload_exfil_architecture",
                evidence=(
                    f"Multiple distinct exfiltration payload shapes detected: {shapes_str}. "
                    "This indicates tiered exfil — an initial lightweight beacon followed by "
                    "one or more full-credential POST payloads."
                ),
            )
        )

    # Emit the richer multi_path_exfil_breakdown when we have detailed info
    if len(exfil_shapes) >= 2 and exfil_data_types:
        # Build a detailed breakdown of what goes where
        shape_descriptions: list[str] = []
        for shape in sorted(exfil_shapes):
            data = exfil_data_types.get(shape, set())
            desc = _describe_exfil_shape(shape, data)
            shape_descriptions.append(desc)

        anchor_rel = exfil_rel.get("full_profile_post") or exfil_rel.get("prefire_beacon") or "."
        out.append(
            BehaviorFinding(
                file=anchor_rel,
                line=1,
                behavior="multi_path_exfil_breakdown",
                evidence=(
                    f"Multi-path exfiltration architecture broken down into {len(exfil_shapes)} distinct channels: "
                    + "; ".join(shape_descriptions)
                ),
            )
        )

    return out


def _describe_exfil_shape(shape: str, data_types: set[str]) -> str:
    """Return a human-readable description of an exfiltration shape and its data types."""
    data_labels = {
        "mc_token": "Minecraft access token",
        "mc_username": "Minecraft username",
        "mc_uuid": "Minecraft UUID",
        "mc_session_id": "Minecraft session ID",
        "player_coordinates": "player coordinates/position",
        "discord_tokens": "Discord/browser tokens",
        "minecraft_logs": "Minecraft log files",
    }
    data_str = ", ".join(data_labels.get(dt, dt) for dt in sorted(data_types)) if data_types else "unidentified data"

    shape_descriptions = {
        "prefire_beacon": f"Lightweight prefire beacon (→ /shard/prefireMc) carrying {data_str}",
        "full_profile_post": f"Full credential profile POST (mcUsername+mcUuid+mcInfo) carrying {data_str}",
        "discord_multi_bundle": f"Discord webhook multi-bundle JSON (Minecraft + Discord tokens) carrying {data_str}",
        "log_exfiltration": f"Minecraft log file exfiltration (→ /shard/submitMinecraftLog) carrying {data_str}",
        "coordinate_discord_exfil": f"Player coordinate exfiltration → Discord webhook carrying {data_str}",
    }
    return shape_descriptions.get(shape, f"{shape} carrying {data_str}")


def detect_persistence_relaunch_chains(root: Path) -> List[BehaviorFinding]:
    """Detect self-copy + detached re-launch persistence patterns.

    Looks for the flow:
      1. Resolve own JAR path (getProtectionDomain / getCodeSource / getLocation)
      2. Construct a destination under LOCALAPPDATA / %APPDATA% / temp
      3. Copy or write the JAR to that destination (FileOutputStream / Files.copy)
      4. Spawn javaw.exe / java.exe detached with the copied JAR as argument
    """
    out: List[BehaviorFinding] = []
    idx = _build_source_index(root)
    texts: dict[str, str] = idx["texts"]
    rel_paths: List[str] = idx["rel_paths"]

    for rel in rel_paths:
        if _is_known_library_relpath(rel):
            continue
        text = texts.get(rel, "")
        low = text.lower()

        # Also decode XOR-obfuscated strings from this file for persistence indicators
        xor_decoded_low = ""
        try:
            xor_strings = [s for s, _l, _n, _k in _extract_full_xor_decoded_strings(text, max_hits=100)]
            xor_strings += [s for s, _l, _n, _k in _extract_inline_xor_decoded_strings(text, max_hits=100)]
            xor_decoded_low = "\n".join(xor_strings).lower()
        except Exception:
            pass
        combined_low = low + "\n" + xor_decoded_low

        # Step 1: self-path resolution
        has_self_path = (
            "getProtectionDomain" in text
            or "getCodeSource" in text
            or "getLocation" in text
        )
        if not has_self_path:
            continue

        # Step 2: persistence destination (check raw source AND decoded strings)
        has_persist_dest = (
            "localappdata" in combined_low
            or "%localappdata%" in combined_low
            or "appdata" in combined_low
            or "%appdata%" in combined_low
            or "ntprofileindex" in combined_low
            or "microsoft\\windows" in combined_low
            or "\\microsoft\\" in combined_low
        )
        if not has_persist_dest:
            continue

        # Step 3: file copy / write to destination
        has_file_write = (
            "FileOutputStream" in text
            or "Files.copy" in text
            or "Files.write" in text
            or ".transferTo" in text
            or "fileoutputstream" in combined_low
        )
        if not has_file_write:
            continue

        # Step 4: detached re-launch (javaw.exe / java.exe may be XOR-obfuscated)
        has_relaunch = (
            ("javaw.exe" in combined_low or "java.exe" in combined_low)
            and ("ProcessBuilder" in text or "Runtime.getRuntime().exec" in text or "start()" in text)
        )

        # Step 5 (optional): exit current process
        has_exit = "System.exit" in text

        if has_relaunch:
            # Extract persistence path hints for evidence
            path_hint = ""
            if "ntprofileindex" in combined_low:
                path_hint = "LOCALAPPDATA\\Microsoft\\Windows\\NtProfileIndex"
            elif "localappdata" in combined_low:
                path_hint = "%LOCALAPPDATA%"
            elif "appdata" in combined_low:
                path_hint = "%APPDATA%"

            exit_note = " and exits current process" if has_exit else ""

            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "ProcessBuilder") if "ProcessBuilder" in text else find_line(text, "getProtectionDomain"),
                    behavior="persistence_filesystem_copy_relaunch_chain",
                    evidence=(
                        f"Copies self to {path_hint}, re-launches via detached javaw/java process{exit_note}. "
                        "This is a classic persistence pattern — the malware survives Minecraft shutdown "
                        "by running independently from the game process."
                    ),
                )
            )
            break

        # Partial match: has copy but no relaunch detected in same file
        if has_file_write:
            path_hint = ""
            if "ntprofileindex" in combined_low:
                path_hint = "LOCALAPPDATA\\Microsoft\\Windows\\NtProfileIndex"
            elif "localappdata" in combined_low:
                path_hint = "%LOCALAPPDATA%"

            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "FileOutputStream") if "FileOutputStream" in text else find_line(text, "getProtectionDomain"),
                    behavior="persistence_detached_process_relaunch",
                    evidence=(
                        f"Copies self to {path_hint} — persistence file staging. "
                        "Review adjacent classes for ProcessBuilder/javaw.exe relaunch to confirm full persistence chain."
                    ),
                )
            )
            break

    return out


# ── Minecraft module/hack detection ────────────────────────────────────────────

_MODULE_SUPER_CALL_RE = re.compile(
    r'super\s*\(\s*"(?P<name>[^"]+)"\s*,\s*"(?P<desc>[^"]*)"\s*,\s*\w+\s*,\s*(?P<cat>[A-Za-z_.]+)\s*\s*\)',
    re.DOTALL,
)
_ADDMODULE_CALL_RE = re.compile(r'addModule\s*\(\s*(?P<cls>[A-Za-z_$][\w$.]*)\s*\.class\s*\)')
# Wurst-style: extends Hack, category set via setCategory(Category.XXX)
_WURST_EXTENDS_HACK_RE = re.compile(r'extends\s+Hack\b')
_WURST_SUPER_NAME_RE = re.compile(r'super\s*\(\s*"(?P<name>[^"]+)"\s*\)')
_WURST_SETCATEGORY_RE = re.compile(r'setCategory\s*\(\s*(?:Category\.)?(?P<cat>[A-Za-z_]+)\s*\)')
_WURST_HACK_FIELD_RE = re.compile(
    r'public\s+final\s+(?P<cls>[A-Za-z_$][\w$]*Hack)\s+\w+\s*=\s*new\s+\1\s*\(\s*\)\s*;'
)


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

    # ── Phase 2: Wurst-style hack detection ──
    # Wurst registers hacks via public final *Hack fieldName = new *Hack() in HackList.java,
    # with category set via this.setCategory(Category.XXX) in the constructor.
    if out["module_count"] < 4:
        # Find HackList.java-style files: lots of public final *Hack field declarations
        for rel, text in texts.items():
            if _is_known_library_relpath(rel):
                continue
            hack_fields = _WURST_HACK_FIELD_RE.findall(text)
            if len(hack_fields) < 10:
                continue

            # Extract Hack class names from field declarations
            wurst_classes: set[str] = set(hack_fields)
            for cls_name in sorted(wurst_classes):
                if cls_name in seen_modules:
                    continue
                candidates = [
                    r for r in simple_to_rel.get(cls_name, [])
                    if not _is_known_library_relpath(r)
                ]
                if not candidates:
                    continue
                hack_text = ""
                for c in candidates:
                    t = texts.get(c, "")
                    if _WURST_EXTENDS_HACK_RE.search(t):
                        hack_text = t
                        break
                if not hack_text:
                    hack_text = texts.get(candidates[0], "")

                # Extract super("Name") and setCategory(Category.XXX)
                sm = _WURST_SUPER_NAME_RE.search(hack_text)
                cm = _WURST_SETCATEGORY_RE.search(hack_text)
                if sm:
                    name = sm.group("name")
                    category = cm.group("cat").upper() if cm else "OTHER"
                    # Derive description from class name if not available
                    desc = cls_name.replace("Hack", "").replace("_", " ")
                    seen_modules.add(cls_name)
                    out["modules"].append({
                        "name": name,
                        "description": desc,
                        "category": category,
                        "file": candidates[0],
                    })

    out["module_count"] = len(out["modules"])
    out["detected"] = out["module_count"] >= 4

    # Also detect module categories present
    cats: dict[str, int] = {}
    for m in out["modules"]:
        cats[m["category"]] = cats.get(m["category"], 0) + 1
    out["categories"] = dict(sorted(cats.items()))

    return out


def detect_decoded_finding_behaviors(findings: List[Finding]) -> List[BehaviorFinding]:
    out: List[BehaviorFinding] = []
    rpc_urls = sorted([
        f
        for f in findings
        if f.category == "url"
        and any(tok in str(f.decoded).lower() for tok in ("polygon", "matic", "rpc", "llamarpc"))
        and "." in urlparse(str(f.decoded)).netloc
    ], key=lambda f: -len(str(f.decoded)))
    contracts = [f for f in findings if f.category == "hex_or_contract" and re.fullmatch(r"0x[a-fA-F0-9]{40}", str(f.decoded))]
    selectors = [f for f in findings if f.category == "hex_or_contract" and re.fullmatch(r"0x[a-fA-F0-9]{8}", str(f.decoded))]
    rpc_templates = [f for f in findings if f.category == "rpc_template" or "eth_call" in str(f.decoded).lower()]
    if rpc_urls and contracts and selectors:
        anchor = rpc_templates[0] if rpc_templates else rpc_urls[0]
        out.append(
            BehaviorFinding(
                file=anchor.file,
                line=anchor.line,
                behavior="blockchain_dns_c2_resolver",
                evidence=(
                    "Decoded findings reveal blockchain-backed C2/domain resolution via JSON-RPC eth_call; "
                    f"rpc={rpc_urls[0].decoded} contract={contracts[0].decoded} selector={selectors[0].decoded}"
                ),
            )
        )

    # ── hUvPFYp-specific behavior extraction from decoded strings ──
    all_decoded = sorted(set(str(f.decoded) for f in findings), key=len, reverse=True)
    all_low = "\n".join(str(f.decoded).lower() for f in findings)

    # Fallback C2 domain
    fallback_domain = None
    for d in all_decoded:
        dl = d.lower()
        if DOMAIN_NAME_RE.match(d) and "." in d and not d.startswith("/") and not d.startswith("http"):
            # Check if it looks like a standalone fallback domain (not a vendor/library host)
            if any(kw in dl for kw in ("sltnnt", "fallback", "backup")):
                fallback_domain = d
            elif not any(v in dl for v in VENDOR_HOST_ALLOWLIST) and not any(
                kw in dl for kw in ("minecraft", "mojang", "fabric", "modrinth")
            ):
                if dl.endswith(".ru") or dl.endswith(".su") or dl.endswith(".cn") or dl.endswith(".top"):
                    fallback_domain = d
                elif ".ru" in dl or ".su" in dl:
                    fallback_domain = d
    if fallback_domain:
        out.append(BehaviorFinding(
            file=".", line=1,
            behavior="c2_fallback_domain",
            evidence=f"Fallback C2 domain resolved from decoded strings: {fallback_domain}",
        ))

    # Payload endpoint
    payload_eps = [f for f in findings if f.category == "path" and ("cdn" in str(f.decoded).lower() or "/e/" in str(f.decoded).lower())]
    if payload_eps:
        out.append(BehaviorFinding(
            file=payload_eps[0].file, line=payload_eps[0].line,
            behavior="payload_download_endpoint",
            evidence=f"Payload download endpoint: {payload_eps[0].decoded}",
        ))

    # install dir (Windows persistence path)
    install_paths = [f for f in findings if "ntprofileindex" in str(f.decoded).lower() or ("microsoft" in str(f.decoded).lower() and "windows" in str(f.decoded).lower())]
    if install_paths:
        out.append(BehaviorFinding(
            file=install_paths[0].file, line=install_paths[0].line,
            behavior="persistence_install_directory",
            evidence=f"Persistence install directory: {install_paths[0].decoded}",
        ))

    # Python executable path
    py_refs = [f for f in findings if str(f.decoded).lower().endswith("python.exe")]
    if py_refs:
        out.append(BehaviorFinding(
            file=py_refs[0].file, line=py_refs[0].line,
            behavior="python_executable_reference",
            evidence=f"Python executable referenced in decoded strings: {py_refs[0].decoded}",
        ))

    # main.py path
    main_py = [f for f in findings if str(f.decoded).lower().endswith("main.py")]
    if main_py:
        out.append(BehaviorFinding(
            file=main_py[0].file, line=main_py[0].line,
            behavior="python_script_reference",
            evidence=f"Python script referenced in decoded strings: {main_py[0].decoded}",
        ))

    # Exfil endpoints (shard/*)
    shard_eps = [f for f in findings if "/shard/" in str(f.decoded).lower()]
    seen_eps: set[str] = set()
    for f in shard_eps:
        ep = str(f.decoded).strip().lower()
        if ep in seen_eps:
            continue
        seen_eps.add(ep)
        if "prefiremc" in ep:
            out.append(BehaviorFinding(
                file=f.file, line=f.line,
                behavior="exfil_endpoint_prefiremc",
                evidence=f"Exfiltration endpoint (prefire beacon): /shard/prefireMc",
            ))
        elif "submitminecraftlog" in ep:
            out.append(BehaviorFinding(
                file=f.file, line=f.line,
                behavior="exfil_endpoint_submit_log",
                evidence=f"Exfiltration endpoint (log submission): /shard/submitMinecraftLog",
            ))

    # ── C2 HTTP header fingerprint ──
    x_edge = any("X-Edge-Cache-Revalidate" in str(f.decoded) for f in findings)
    stale_if = any("stale-if-error" in str(f.decoded) for f in findings)
    x_runtime = any("X-Runtime-Env" in str(f.decoded) for f in findings)
    jre_embedded = any("jre-embedded" in str(f.decoded) for f in findings)
    if (x_edge or stale_if) and (x_runtime or jre_embedded):
        headers = []
        if x_edge:
            headers.append("X-Edge-Cache-Revalidate")
        if stale_if:
            headers.append("stale-if-error")
        if x_runtime:
            headers.append("X-Runtime-Env")
        if jre_embedded:
            headers.append("jre-embedded")
        out.append(BehaviorFinding(
            file=".", line=1,
            behavior="c2_custom_header_fingerprint",
            evidence=f"Custom C2 HTTP headers detected: {', '.join(headers)}. "
                     "This CDN-cache-bypass + embedded-runtime header combo is a distinctive network IOC.",
        ))

    # ── Python CLI arg chain ──
    py_args = [f for f in findings if str(f.decoded).startswith("--") and len(str(f.decoded)) > 3 and not str(f.decoded).startswith("---")]
    py_arg_values = sorted(set(str(f.decoded) for f in py_args))
    if len(py_arg_values) >= 3:
        out.append(BehaviorFinding(
            file=py_args[0].file, line=py_args[0].line,
            behavior="python_subprocess_argument_chain",
            evidence=f"Python subprocess CLI argument chain detected: {', '.join(py_arg_values)}. "
                     "This confirms structured argument-passing to the detached Python payload.",
        ))

    # Detached process indicator
    has_detached_log = any("DETACHED PROCESS STARTED" in str(f.decoded) for f in findings)
    has_detached_env = any("executionEnvironment" in str(f.decoded) for f in findings) or any("-Detached" in str(f.decoded) for f in findings)
    if has_detached_log or has_detached_env:
        out.append(BehaviorFinding(
            file=".", line=1,
            behavior="detached_process_runtime_indicator",
            evidence="Detached process runtime indicators found: log markers or executionEnvironment tracking. "
                     "Malware tracks whether it's running in detached mode.",
        ))

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


# ── URL assembly from decoded fragments ──────────────────────────────────────

def assemble_c2_urls(findings: List[Finding], runtime_c2: dict) -> dict:
    """Assemble full C2 URLs from decoded path fragments and the resolved
    blockchain C2 domain (or fallback domain).

    Returns structured endpoint info including full URLs for every known
    exfiltration / download path found in the codebase.
    """
    result: dict = {
        "c2_domain": "",
        "c2_domain_source": "",
        "fallback_domain": "",
        "cdn_path": "",
        "endpoints": [],
        "assembled_urls": [],
        "unresolved_paths": [],
        "note": "",
    }

    # 1. Get the C2 domain from runtime resolution or fallback
    c2_domain = (
        runtime_c2.get("decoded_response", "")
        if runtime_c2.get("resolved")
        else ""
    )
    if c2_domain and URL_RE.match(f"https://{c2_domain}"):
        result["c2_domain"] = c2_domain
        result["c2_domain_source"] = "blockchain_eth_call"
    else:
        # Try fallback domain from findings
        for f in findings:
            low = str(f.decoded).lower()
            if DOMAIN_NAME_RE.match(str(f.decoded)) and any(
                kw in low for kw in ("sltnnt", "fallback", "backup")
            ):
                result["c2_domain"] = str(f.decoded).strip()
                result["c2_domain_source"] = "fallback_domain_string"
                break
        if not result["c2_domain"]:
            # Try .ru/.su domains
            for f in findings:
                d = str(f.decoded).strip()
                low = d.lower()
                if DOMAIN_NAME_RE.match(d) and (
                    low.endswith(".ru") or low.endswith(".su") or low.endswith(".st")
                ):
                    # Exclude library/vendor hosts
                    if not any(v in low for v in VENDOR_HOST_ALLOWLIST):
                        result["c2_domain"] = d
                        result["c2_domain_source"] = "suspicious_domain_string"
                        break

    # 2. Collect path fragments
    path_fragments = sorted(
        {str(f.decoded).strip() for f in findings if f.category == "path" and str(f.decoded).startswith("/")},
        key=len,
        reverse=True,
    )

    # 3. Identify known-malicious path patterns (case-insensitive, canonical forms)
    known_paths: dict[str, str] = {
        "/shard/prefiremc": "Prefire beacon endpoint",
        "/shard/submitminecraftlog": "Minecraft log exfiltration",
    }
    path_low_set = {p.lower() for p in path_fragments}
    cdn_paths = [p for p in path_fragments if "cdn" in p.lower() or "/e/" in p.lower()]

    seen_endpoint_paths: set[str] = set()
    for canon_path, desc in known_paths.items():
        canon_low = canon_path.lower()
        # Find the actual path fragment that matches (case-insensitive)
        for p in path_fragments:
            if p.lower() == canon_low:
                key = canon_path  # use canonical lowercase
                if key not in seen_endpoint_paths:
                    seen_endpoint_paths.add(key)
                    result["endpoints"].append({"path": p, "description": desc, "method": "POST"})
                break
        else:
            # Also check for substring matches
            for p in path_fragments:
                if canon_low in p.lower() and p.lower() not in seen_endpoint_paths:
                    seen_endpoint_paths.add(p.lower())
                    result["endpoints"].append({"path": p, "description": desc, "method": "POST"})
                    break

    for cdn_p in cdn_paths[:3]:
        if not any(e["path"] == cdn_p for e in result["endpoints"]):
            result["endpoints"].append({
                "path": cdn_p,
                "description": "Stage-2 payload download (CDN)",
                "method": "GET",
            })
            if not result["cdn_path"]:
                result["cdn_path"] = cdn_p

    # 4. Assemble full URLs
    domain = result["c2_domain"]
    result["assembled_urls"] = []
    for ep in result["endpoints"]:
        if domain and ep["path"]:
            full = f"https://{domain}{ep['path']}"
            result["assembled_urls"].append({
                "url": full,
                "path": ep["path"],
                "description": ep["description"],
                "method": ep["method"],
            })

    # 5. Collect unresolved paths that might be interesting
    result["unresolved_paths"] = [
        p for p in path_fragments
        if not any(known in p.lower() for known in known_paths)
        and not any(p in ep["path"] for ep in result["endpoints"])
        and len(p) > 3
    ][:20]

    if not result["c2_domain"]:
        result["note"] = "C2 domain not resolved; set manually via blockchain eth_call or fallback domain string"
    elif not result["assembled_urls"]:
        result["note"] = "Domain resolved but no path fragments found to assemble URLs"

    return result


# ── Live infrastructure probing ──────────────────────────────────────────────

def probe_live_endpoints(assembled_urls: list[dict], timeout: int = 10) -> dict:
    """Probe assembled URLs for liveness: DNS resolution + HTTP HEAD/GET.

    Does NOT download payloads — HEAD requests for regular endpoints,
    GET with Range: bytes=0-0 for CDN payload endpoints (just checks
    existence and Content-Type, never downloads full payloads).
    """
    import socket as _socket

    result: dict = {
        "probed": False,
        "probe_count": 0,
        "results": [],
        "summary": {"live": 0, "dead": 0, "error": 0, "total": 0},
    }

    if not assembled_urls:
        return result

    result["probed"] = True
    result["probe_count"] = len(assembled_urls)

    for entry in assembled_urls:
        url = entry["url"]
        desc = entry.get("description", "?")
        method = entry.get("method", "GET")
        probe: dict = {
            "url": url,
            "description": desc,
            "host": urlparse(url).netloc,
            "dns_resolved": False,
            "dns_ip": "",
            "http_reachable": False,
            "http_status": 0,
            "http_reason": "",
            "content_type": "",
            "error": "",
            "status": "unknown",
        }

        # DNS
        try:
            probe["dns_ip"] = _socket.gethostbyname(probe["host"])
            probe["dns_resolved"] = True
        except Exception:
            probe["status"] = "dead"
            probe["error"] = "DNS resolution failed"
            result["results"].append(probe)
            result["summary"]["dead"] += 1
            continue

        # HTTP — HEAD for most, Range request for CDN paths
        try:
            if "/cdn" in url.lower() or "/e/" in url.lower() or method == "GET":
                # Range probe: request first byte only to check existence
                req = request.Request(
                    url,
                    headers={
                        "User-Agent": "java-triage/1.0 (infra-probe)",
                        "Range": "bytes=0-0",
                    },
                    method="GET",
                )
            else:
                req = request.Request(
                    url,
                    headers={"User-Agent": "java-triage/1.0 (infra-probe)"},
                    method="HEAD",
                )
            with request.urlopen(req, timeout=timeout) as resp:
                probe["http_reachable"] = True
                probe["http_status"] = resp.status
                probe["http_reason"] = resp.reason
                probe["content_type"] = resp.headers.get("Content-Type", "")
                if resp.status < 400:
                    probe["status"] = "live"
                else:
                    probe["status"] = "error"
                    probe["error"] = f"HTTP {resp.status} {resp.reason}"
        except error.HTTPError as e:
            probe["http_reachable"] = True
            probe["http_status"] = e.code
            probe["http_reason"] = e.reason
            probe["status"] = "error"
            probe["error"] = f"HTTP {e.code} {e.reason}"
        except Exception as e:
            probe["error"] = _friendly_network_error(e) if "HTTP" not in str(e) else str(e)[:120]
            probe["status"] = "dead"

        if probe["status"] == "live":
            result["summary"]["live"] += 1
        elif probe["status"] == "error":
            result["summary"]["error"] += 1
        else:
            result["summary"]["dead"] += 1

        result["results"].append(probe)

    result["summary"]["total"] = len(result["results"])
    return result


# ── Interactive stage-2 prompt ───────────────────────────────────────────────

def interactive_stage2_prompt(
    url_assembly: dict,
    runtime_c2: dict,
    findings: List[Finding],
    stage2_analysis: dict | None = None,
) -> dict:
    """After the scan, present the user with actionable options for any
    resolved infrastructure, including scanning an already-downloaded
    stage-2 JAR or downloading the encrypted blob.

    If stage2_analysis is provided and a payload was already downloaded:
      - If it's a valid JAR → offer to scan it (java_triage.py <path>)
      - If it's an encrypted blob → show download info and suggest decryption

    Returns a dict with user choices — does NOT execute any actions itself.
    """
    result: dict = {
        "prompted": False,
        "chosen_action": "",
        "available_actions": [],
        "notes": [],
    }

    assembled = url_assembly.get("assembled_urls", [])
    cdn_urls = [e for e in assembled if "cdn" in e.get("url", "").lower() or "/e/" in e.get("url", "").lower()]
    exfil_urls = [e for e in assembled if e.get("method") == "POST"]
    c2_domain = url_assembly.get("c2_domain", "")
    fallback = url_assembly.get("fallback_domain", "")

    already_downloaded = bool(stage2_analysis and stage2_analysis.get("downloaded", False))
    download_is_jar = False
    download_is_blob = False
    download_path = ""
    download_sha256 = ""
    download_size = 0

    if already_downloaded:
        dl_err = stage2_analysis.get("error", "")
        entry_count = stage2_analysis.get("entry_count", 0)
        dl_size = stage2_analysis.get("download_size", 0)
        # A valid JAR/ZIP: downloaded + entries > 0 + no error
        download_is_jar = bool(entry_count > 0 and not dl_err)
        # An encrypted blob: downloaded + bytes received + error about not being a zip
        download_is_blob = bool(dl_size > 0 and dl_err and "not a zip" in dl_err.lower())
        download_path = stage2_analysis.get("download_path", "")
        download_sha256 = stage2_analysis.get("download_sha256", "")
        download_size = dl_size

    action_list: list[dict] = []

    # ── If already downloaded and it's a valid JAR → offer to scan ──
    if download_is_jar and download_path:
        size_mb = download_size / (1024 * 1024)
        action_list.append({
            "id": "scan_downloaded_stage2",
            "label": f"Scan the already-downloaded stage-2 JAR ({size_mb:.1f} MB, SHA256: {download_sha256[:16]}...)",
            "risk": "low",
            "note": (
                f"The stage-2 payload was downloaded to {download_path} during this scan. "
                f"Re-run: java_triage.py \"{download_path}\" to analyze it statically."
            ),
        })

    # ── If already downloaded but it's an encrypted blob → offer to DECRYPT, NOT re-download ──
    if download_is_blob and cdn_urls:
        size_mb = download_size / (1024 * 1024)
        action_list.append({
            "id": "decrypt_downloaded_blob",
            "label": f"Decrypt the already-downloaded AES blob ({size_mb:.1f} MB) using key from source code",
            "download_path": download_path,
            "url": cdn_urls[0]["url"],
            "risk": "medium",
            "note": (
                f"The blob was already downloaded to {download_path} during the scan. "
                "Will attempt AES/CBC/NoPadding decryption using key dK9mT3nR7xQ2pL8wF4jH6yB1cN5gA0sZ... "
                "The decrypted output (a ZIP containing python.exe + main.py) will be written to disk "
                "for static-only inspection. NO CODE IS EXECUTED."
            ),
        })

    # ── If NOT already downloaded and CDN URLs are available ──
    if not already_downloaded and cdn_urls:
        for cdn in cdn_urls:
            action_list.append({
                "id": "download_stage2_payload",
                "label": f"Download stage-2 payload from {cdn['url']} for static analysis (no execution)",
                "url": cdn["url"],
                "risk": "medium",
                "note": "Downloads the encrypted blob to disk. Use --analyze-stage2 or re-scan the downloaded file.",
            })

        # Action: download and decrypt
        aes_key_in_findings = any(
            "SecretKeySpec" in str(f.decoded) or "AES" in str(f.decoded) or "Cipher" in str(f.decoded)
            for f in findings
        )
        if aes_key_in_findings:
            action_list.append({
                "id": "download_and_decrypt_stage2",
                "label": f"Download {cdn_urls[0]['url']} AND attempt AES decryption using key from source",
                "url": cdn_urls[0]["url"],
                "risk": "high",
                "note": (
                    "Downloads the encrypted blob and attempts AES/CBC/NoPadding decryption using "
                    "the key extracted from StringDecrypt fields. The decrypted output (likely a ZIP "
                    "containing python.exe + main.py) is written to disk for static-only inspection. "
                    "NO CODE IS EXECUTED."
                ),
            })

    # Action: probe all endpoints
    if assembled:
        action_list.append({
            "id": "probe_all_endpoints",
            "label": f"DNS-resolve and HTTP-probe all {len(assembled)} assembled endpoints (HEAD/range requests only)",
            "risk": "low",
            "note": "Performs DNS resolution and HTTP HEAD (or Range: bytes=0-0) on every endpoint. No payloads downloaded.",
        })

    # Action: re-run with stage2 analysis
    if cdn_urls and not runtime_c2.get("resolved"):
        action_list.append({
            "id": "rerun_with_network",
            "label": "Re-run scan with --analyze-stage2 to download and triage the stage-2 JAR automatically",
            "risk": "low",
            "note": "The current scan ran with --no-network. Re-run to enable C2 resolution + stage-2 download.",
        })

    result["available_actions"] = action_list
    result["c2_domain"] = c2_domain
    result["cdn_urls"] = [e["url"] for e in cdn_urls]
    result["exfil_urls"] = [e["url"] for e in exfil_urls]

    # If there are risky actions available, set flag
    if any(a["risk"] == "high" for a in action_list):
        result["has_risky_actions"] = True

    return result


# ── Java comment scanning ────────────────────────────────────────────────────

# Coordinate-related patterns in comments for sensitive game data exfil
_COMMENT_COORDINATE_DISCORD_PATTERNS = [
    re.compile(r"sends?\s+(base\s+)?coordinates?\s+to\s+discord", re.IGNORECASE),
    re.compile(r"sends?\s+(player\s+)?positions?\s+to\s+discord", re.IGNORECASE),
    re.compile(r"sends?\s+(player\s+)?coordinates?\s+to\s+webhook", re.IGNORECASE),
    re.compile(r"coordinates?\s+exfiltrat", re.IGNORECASE),
    re.compile(r"positions?\s+leak(?:ed|ing)?\s+to\s+discord", re.IGNORECASE),
    re.compile(r"location\s+exfiltrat", re.IGNORECASE),
]


def _scan_java_comments(text: str, rel: str) -> List[Finding]:
    """Scan Java comments for suspicious indicators like coordinate exfil.

    Malware authors often leave self-documenting comments about what their
    code does — e.g. '// Sends base coordinates to discord webhook'.
    These are not string literals and would otherwise go undetected.
    """
    out: List[Finding] = []
    seen = set()

    def _build_finding(line_num: int, decoded: str, signal: str, category: str) -> Finding:
        return Finding(
            file=rel,
            line=line_num,
            function="<comment>",
            decoded=decoded,
            category=category,
            note=f"source=comment_scanner signal={signal}",
        )

    # 1. Scan line comments: // ...
    for m in JAVA_LINE_COMMENT_RE.finditer(text):
        comment_text = m.group(1).strip()
        if len(comment_text) < 8:
            continue
        line_num = text[: m.start()].count("\n") + 1
        low = comment_text.lower()

        # Coordinate → Discord webhook
        for pat in _COMMENT_COORDINATE_DISCORD_PATTERNS:
            cm = pat.search(comment_text)
            if cm:
                key = (line_num, "coordinate_to_discord")
                if key not in seen:
                    seen.add(key)
                    out.append(_build_finding(line_num, comment_text[:200], "coordinate_exfil_comment", "sensitive_game_data"))
                break

        # Other sensitive terms in comments
        for term in SENSITIVE_COMMENT_TERMS:
            if term in low:
                key = (line_num, term)
                if key not in seen:
                    seen.add(key)
                    if any(kw in low for kw in ("token", "credential", "session", "password", "stealer")):
                        cat = "credential_or_identity_field"
                    elif any(kw in low for kw in ("coordinate", "position", "location")):
                        cat = "sensitive_game_data"
                    elif any(kw in low for kw in ("discord", "webhook")):
                        cat = "discord_indicator"
                    elif any(kw in low for kw in ("beacon", "callback", "c2")):
                        cat = "comms_indicator"
                    else:
                        cat = "string"
                    out.append(_build_finding(line_num, comment_text[:200], "sensitive_comment", cat))
                break  # One term match per comment is sufficient

    # 2. Scan block comments: /* ... */
    for m in JAVA_BLOCK_COMMENT_RE.finditer(text):
        comment_text = m.group(1).strip()
        if len(comment_text) < 8:
            continue
        line_num = text[: m.start()].count("\n") + 1
        low = comment_text.lower()

        for pat in _COMMENT_COORDINATE_DISCORD_PATTERNS:
            cm = pat.search(comment_text)
            if cm:
                key = (line_num, "coordinate_to_discord_block")
                if key not in seen:
                    seen.add(key)
                    out.append(_build_finding(line_num, comment_text[:200], "coordinate_exfil_block_comment", "sensitive_game_data"))
                break

        for term in SENSITIVE_COMMENT_TERMS:
            if term in low:
                key = (line_num, f"{term}_block")
                if key not in seen:
                    seen.add(key)
                    if any(kw in low for kw in ("token", "credential", "session", "password", "stealer")):
                        cat = "credential_or_identity_field"
                    elif any(kw in low for kw in ("coordinate", "position", "location")):
                        cat = "sensitive_game_data"
                    elif any(kw in low for kw in ("discord", "webhook")):
                        cat = "discord_indicator"
                    elif any(kw in low for kw in ("beacon", "callback", "c2")):
                        cat = "comms_indicator"
                    else:
                        cat = "string"
                    out.append(_build_finding(line_num, comment_text[:200], "sensitive_block_comment", cat))
                break

    return out


def scan_file(
    path: Path,
    root: Path,
    decrypt_profile: Optional[DecryptProfile] = None,
    include_all_literals: bool = False,
) -> List[Finding]:
    pathology = _source_pathology(path)
    if pathology.get("pathological"):
        return [_pathology_finding(path, root, pathology)]
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
        obf_literal_entries.extend(_extract_key_prefixed_xor_literals(text, starts))
        obf_literal_entries.extend(_extract_key_prefixed_xor_stringbuilder_reconstructions(text, starts))
        # Full XOR decode pass: capture ALL decoded strings, not just "interesting" ones
        obf_literal_entries.extend(_extract_full_xor_decoded_strings(text, starts))
        # Inline first-byte-key XOR decode: Skidfuscator-style byte[]/char[] inline patterns
        obf_literal_entries.extend(_extract_inline_xor_decoded_strings(text, starts))
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
            elif DOMAIN_NAME_RE.match(decoded):
                # Suppress file-extension false positives
                tld = decoded.rsplit(".", 1)[-1].lower()
                if tld not in _DOMAIN_FALSE_POSITIVE_EXTENSIONS:
                    category = "comms_indicator"
                    signal = f"{source_kind}_domain"
                else:
                    # It's a filename with an extension, not a domain
                    category = "path"
                    signal = f"{source_kind}_filename"
            elif ETH_SELECTOR_RE.match(decoded):
                category = "hex_or_contract"
                signal = f"{source_kind}_eth_method_selector"
            elif HEX_ADDR_RE.match(decoded) and len(decoded) == 42:
                category = "hex_or_contract"
                signal = f"{source_kind}_contract_address"
            elif "jsonrpc" in low or "eth_call" in low:
                category = "rpc_template"
                signal = f"{source_kind}_eth_rpc_template"
            elif decoded in {"Content-Type", "application/json"}:
                category = "http_header"
                signal = f"{source_kind}_http_header"
            elif decoded.startswith("/"):
                category = "path"
                signal = f"{source_kind}_path"
            elif COMMAND_LITERAL_RE.search(decoded):
                category = "dynamic_execution"
                signal = f"{source_kind}_command_or_lolbin"
            elif any(tok in low for tok in ("java.lang.runtime", "getruntime", "exec")):
                category = "dynamic_execution"
                signal = f"{source_kind}_runtime_reflection_token"
            elif any(k in low for k in SUSPICIOUS_STRING_KEYWORDS):
                category = "credential_or_identity_field" if any(k in low for k in ("token", "authorization", "api_key", "bearer ")) else "string"
                signal = f"{source_kind}_keyword_hit"
            # Catch decoded strings that fall through the specific classifier
            # but are still meaningful — Windows paths, env vars, persistence targets, etc.
            elif "\\microsoft\\" in low or "\\windows\\" in low or "ntprofileindex" in low:
                category = "path"
                signal = f"{source_kind}_persistence_path"
            elif WINDOWS_PATH_RE.match(decoded):
                category = "path"
                signal = f"{source_kind}_windows_path"
            elif "%localappdata%" in low or "%appdata%" in low or "%temp%" in low or "%userprofile%" in low:
                category = "path"
                signal = f"{source_kind}_env_path"
            elif decoded.endswith(".exe") or decoded.endswith(".py") or decoded.endswith(".bat") or decoded.endswith(".cmd"):
                category = "dynamic_execution"
                signal = f"{source_kind}_executable_ref"
            elif decoded.startswith("java."):
                # java.home / java.version are JVM system properties, not comms
                if decoded in {"java.home", "java.version", "java.io.tmpdir", "java.class.path"}:
                    category = "path"
                    signal = f"{source_kind}_java_sysprop"
                else:
                    category = "comms_indicator"
                    signal = f"{source_kind}_java_property"
            elif decoded.startswith("--") and len(decoded) > 3:
                category = "dynamic_execution"
                signal = f"{source_kind}_cli_flag"
            elif decoded.startswith("-") and len(decoded) > 2 and not decoded.startswith("--"):
                # Single-dash CLI flags like -restarted, -cp, -u, -Detached
                category = "dynamic_execution"
                signal = f"{source_kind}_cli_flag"
            elif any(decoded.startswith(p) for p in ("X-", "x-")) and "-" in decoded:
                category = "http_header"
                signal = f"{source_kind}_custom_header"
            elif low.startswith("user-agent") or low.startswith("content-type") or low.startswith("content-"):
                category = "http_header"
                signal = f"{source_kind}_http_header"
            elif low.startswith("error") or low.startswith("spawn") or "download" in low or "runtime ready" in low:
                category = "string"
                signal = f"{source_kind}_op_log"
            elif decoded in {"jre-embedded", "stale-if-error", "-Detached", "-Detached\"}"}:
                category = "http_header"
                signal = f"{source_kind}_header_value"
            elif low in {"detached process started", "apphost"}:
                category = "path"
                signal = f"{source_kind}_payload_path"
            elif "executionenvironment" in low:
                category = "credential_or_identity_field"
                signal = f"{source_kind}_env_field"
            # Bare Windows env var names used as path prefixes
            elif low in {"localappdata", "appdata", "temp", "userprofile", "programdata"}:
                category = "path"
                signal = f"{source_kind}_env_var_name"
            # Discord keywords that appear in decoded strings
            elif DISCORD_KEYWORD_PATTERNS.search(decoded):
                category = "discord_indicator"
                signal = f"{source_kind}_discord_keyword"
            # Bitcoin / cryptocurrency address
            elif BITCOIN_ADDRESS_RE.search(decoded):
                category = "cryptocurrency_address"
                signal = f"{source_kind}_btc_address"
            elif decoded == "null" or low in {"null", "none"}:
                # JSON placeholder literals — not paths
                category = "string"
                signal = f"{source_kind}_json_placeholder"
            # Stealer/persistence-specific decoded strings
            elif any(tok in low for tok in ("_stealer.log", "_spawn.log", "latest.log", "combined.log")):
                category = "path"
                signal = f"{source_kind}_persistence_artifact"
            elif any(tok in low for tok in ("fatal", "context parsed", "attempt", "cached", "decrypt", "extract", "portable")):
                category = "string"
                signal = f"{source_kind}_stealer_log"
            elif any(tok in low for tok in ("detached", "spawn error", "submit error")):
                category = "dynamic_execution"
                signal = f"{source_kind}_stealer_event"
            elif "stealer" in low:
                category = "credential_or_identity_field"
                signal = f"{source_kind}_stealer_ref"
            elif "cdn" in low or "cdn-origin" in low or "x-cdn" in low:
                category = "comms_indicator"
                signal = f"{source_kind}_cdn_indicator"
            elif "trust" in low and ("all" in low or "accept" in low):
                category = "comms_indicator"
                signal = f"{source_kind}_trust_all_tls"
            elif _looks_interesting_decoded_literal(decoded):
                category = "string"
                signal = f"{source_kind}_decoded_literal"
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
        # Scan Java comments for sensitive indicators
        findings.extend(_scan_java_comments(text, rel))
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
    if behavior in {
        "two_payload_exfil_architecture",
        "multi_path_exfil_breakdown",
        "discord_webhook_url_reassembly",
        "persistence_filesystem_copy_relaunch_chain",
        "credential_handoff_to_dynamic_stage",
        "staged_remote_jar_execution",
    }:
        return "confirmed_behavior"
    if behavior.startswith("capability_") or behavior in {
        "command_execution_capability",
        "dynamic_class_execution",
        "dynamic_urlclassloader_usage",
        "remote_urlclassloader_usage",
        "exposed_local_websocket_command_bridge",
        "audio_capture_capability",
        "audio_playback_capability",
        "minecraft_coordinate_exfiltration",
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
    token_proofs = {
        "proof_token_source_to_network_sink",
        "proof_reachable_command_token_disclosure_chain",
        "proof_minecraft_token_raw_socket_exfil_chain",
    }
    if "minecraft_access_token_access" in by_behavior and not (by_behavior & token_proofs):
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
            "sensitive_game_data",
            "cryptocurrency_address",
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
    # Also count XOR-decoded strings from key_prefix_xor / full_xor scanners
    xor_from_findings = sum(
        1 for f in findings
        if "key_prefix_xor" in (f.note or "") or "full_xor" in (f.note or "")
    )
    xor_decrypted_count = max(xor_decrypted_count, xor_from_findings)
    # Count reconstructed strings (StringBuilder reassembly)
    reconstructed_count = sum(
        1 for f in findings
        if "key_prefix_xor_stringbuilder" in (f.note or "")
    )
    return {
        "total_findings": len(findings),
        "unique_decoded_strings": len(unique),
        "category_counts": dict(sorted(by_category.items(), key=lambda x: (-x[1], x[0]))),
        "xor_decrypted_count": xor_decrypted_count,
        "decrypted_string_count": decrypted_string_count,
        "reconstructed_strings": reconstructed_count,
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


def _extract_windows_artifacts(findings: List[Finding], behaviors: List[BehaviorFinding]) -> dict:
    """Extract Windows persistence/staging indicators from findings and behaviors."""
    env_vars: list[str] = []
    paths: list[str] = []
    executables: list[str] = []
    launched_payloads: list[str] = []
    confirmed: list[str] = []
    not_confirmed: list[str] = []

    all_decoded = [str(f.decoded).lower() for f in findings]
    all_decoded_set = set(all_decoded)
    behavior_ids = {b.behavior for b in behaviors}

    # Extract from decoded strings
    for d in all_decoded_set:
        if d in {"localappdata", "appdata", "temp", "userprofile", "programdata"}:
            env_vars.append(d.upper())
        if "microsoft" in d and "windows" in d:
            paths.append(d)
        if "ntprofileindex" in d.lower():
            paths.append(d)
        if d in {"python.exe", "javaw.exe", "java.exe", "cmd.exe", "powershell.exe"}:
            executables.append(d)
        if d.endswith(".py") and not d.startswith("--"):
            launched_payloads.append(d)

    # Check behaviors for persistence indicators
    if "persistence_filesystem_copy_relaunch_chain" in behavior_ids:
        confirmed.append("cached runtime staging")
    if "persistence_detached_process_relaunch" in behavior_ids:
        confirmed.append("detached payload execution")
    if "detached_process_runtime_indicator" in behavior_ids:
        confirmed.append("detached process runtime tracking")
    if any("self-overwrite" in (getattr(b, "behavior", "")) for b in behaviors):
        confirmed.append("self-overwrite/update capability")

    # Check JLab signatures for timestamp spoofing
    # (handled at call site via stage2/jlab)

    # Check for timestamp spoofing via setLastModified in behaviors/code
    if any("timestamp" in getattr(b, "evidence", "").lower() for b in behaviors):
        confirmed.append("timestamp spoofing")

    # Deduplicate confirmed
    confirmed = sorted(set(confirmed))

    # Always list what's NOT present
    not_confirmed = ["Run key", "Scheduled Task", "Service", "Startup folder"]

    return {
        "env_vars": sorted(set(env_vars)),
        "paths": sorted(set(paths)),
        "executables": sorted(set(executables)),
        "launched_payloads": sorted(set(launched_payloads)),
        "persistence_assessment": {"confirmed": confirmed, "not_confirmed": not_confirmed},
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
    minecraft_modules: dict | None = None,
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
        _cat_prio2 = {"url": 1, "credential_or_identity_field": 2, "dynamic_execution": 3, "cryptocurrency_address": 4, "discord_indicator": 5, "rpc_template": 6, "path": 7, "http_header": 8, "comms_indicator": 9, "sensitive_game_data": 10, "hex_or_contract": 11, "string": 12, "base64_blob": 13, "hex_decoded_binary": 14, "base64_decoded_binary": 15}
        for f in sorted(findings, key=lambda x: (_cat_prio2.get(x.category, 99), x.category, (x.decoded or "").lower())):
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
        _bsev2 = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for b in sorted(behaviors, key=lambda x: (_bsev2.get(behavior_severity(x.behavior), 9), x.behavior, x.file, x.line)):
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

    mm = minecraft_modules or {}
    if mm.get("detected"):
        out.append("")
        out.append("== Detected Minecraft Modules ==")
        out.append(f"Total modules: {mm.get('module_count', 0)}")
        cats = mm.get("categories", {})
        if cats:
            out.append(f"Categories: {', '.join(f'{k}({v})' for k, v in sorted(cats.items()))}")
        current_cat = ""
        for m in mm.get("modules", []):
            cat = m.get("category", "OTHER")
            if cat != current_cat:
                current_cat = cat
                out.append(f"  [{cat}]")
            out.append(f"    - {m['name']}: {m['description'] or '(no description)'}")

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
    minecraft_modules = payload.get("minecraft_modules", {}) or {}
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

    # ── Sort keys for HTML tables ──
    _html_cat_prio = {"url": 1, "credential_or_identity_field": 2, "dynamic_execution": 3, "cryptocurrency_address": 4, "discord_indicator": 5, "rpc_template": 6, "path": 7, "http_header": 8, "comms_indicator": 9, "sensitive_game_data": 10, "hex_or_contract": 11, "string": 12, "base64_blob": 13, "hex_decoded_binary": 14, "base64_decoded_binary": 15}
    _html_sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    rows_find = []
    for r in sorted(findings[:2000], key=lambda x: (_html_cat_prio.get(str(x.get("category","")), 99), str(x.get("category","")), (str(x.get("decoded","")) or "").lower())):
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
    for r in sorted(behaviors[:2000], key=lambda x: (_html_sev_order.get(str(x.get("severity","info")).lower(), 9), str(x.get("behavior","")), str(x.get("file","")), int(x.get("line",0) or 0))):
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
    for sig in sorted((jlab.get("signatures", []) or [])[:1000], key=lambda x: (_html_sev_order.get(str(x.get("severity","info")).lower(), 9), str(x.get("name","")))):
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

    # ── Windows Persistence / Staging ──
    # Build from findings/behaviors dicts (HTML uses dict payload, not dataclass objects)
    _win_findings_dicts = [{"decoded": str(f.get("decoded","")), "category": str(f.get("category",""))} for f in findings[:3000]]
    _win_beh_dicts = [{"behavior": str(b.get("behavior","")), "evidence": str(b.get("evidence",""))} for b in behaviors[:3000]]
    _win_env_vars = set()
    _win_paths = set()
    _win_exes = set()
    _win_payloads = set()
    _win_confirmed = set()
    _win_not_confirmed = set()
    for f in _win_findings_dicts:
        d = f["decoded"].lower()
        if d in {"localappdata", "appdata", "temp", "userprofile", "programdata"}:
            _win_env_vars.add(d.upper())
        if "ntprofileindex" in d:
            _win_paths.add(f["decoded"])
        if d in {"python.exe", "javaw.exe", "java.exe"}:
            _win_exes.add(d)
        if d.endswith(".py") and not d.startswith("--"):
            _win_payloads.add(d)
    for b in _win_beh_dicts:
        bid = b["behavior"]
        ev = (b["evidence"] or "").lower()
        if "persistence_filesystem_copy_relaunch_chain" in bid:
            _win_confirmed.add("cached runtime staging")
        if "persistence_detached_process_relaunch" in bid:
            _win_confirmed.add("detached payload execution")
        if "detached_process_runtime_indicator" in bid:
            _win_confirmed.add("detached process runtime tracking")
        if "timestamp" in ev:
            _win_confirmed.add("timestamp spoofing")
    _win_not_confirmed = {"Run key", "Scheduled Task", "Service", "Startup folder"}
    rows_win_html = []
    if _win_env_vars:
        rows_win_html.append(f"<tr><td class='meta-k'>Environment variables</td><td class='meta-v'>{', '.join(sorted(_win_env_vars))}</td></tr>")
    if _win_paths:
        rows_win_html.append(f"<tr><td class='meta-k'>Staging paths</td><td class='meta-v'>{', '.join(sorted(_win_paths))}</td></tr>")
    if _win_exes:
        rows_win_html.append(f"<tr><td class='meta-k'>Executables</td><td class='meta-v'>{', '.join(sorted(_win_exes))}</td></tr>")
    if _win_payloads:
        rows_win_html.append(f"<tr><td class='meta-k'>Launched payloads</td><td class='meta-v'>{', '.join(sorted(_win_payloads))}</td></tr>")
    if _win_confirmed:
        rows_win_html.append(f"<tr><td class='meta-k' style='color:#6fd89b'>Confirmed</td><td class='meta-v' style='color:#6fd89b'>{', '.join(sorted(_win_confirmed))}</td></tr>")
    if _win_not_confirmed:
        rows_win_html.append(f"<tr><td class='meta-k' style='color:#ff6b6b'>Not confirmed</td><td class='meta-v' style='color:#ff6b6b'>{', '.join(sorted(_win_not_confirmed))}</td></tr>")

    # ── Cryptocurrency Addresses ──
    rows_crypto_html = []
    for f in findings[:2500]:
        if (f or {}).get("category") == "cryptocurrency_address":
            rows_crypto_html.append(
                "<tr>"
                f"<td class='crypto-addr'>{_h(f.get('decoded', ''))}</td>"
                f"<td class='tight'>{_h(f.get('file', ''))}</td>"
                f"<td class='tight'>{_h(f.get('line', ''))}</td>"
                "</tr>"
            )

    # ── Discord / Webhook Indicators ──
    rows_discord_html = []
    for f in findings[:2500]:
        if (f or {}).get("category") == "discord_indicator":
            note = str(f.get("note", "") or "")
            if any(k in note.lower() for k in ("webhook", "token", "snowflake_id", "notification", "bot", "contextual")):
                signal = note.replace("source=string_scanner signal=", "").replace("source=comment_scanner signal=", "")
                rows_discord_html.append(
                    "<tr>"
                    f"<td class='tight'>{_h(signal[:50])}</td>"
                    f"<td>{_h(f.get('decoded', '')[:120])}</td>"
                    f"<td class='tight'>{_h(f.get('file', ''))}</td>"
                    f"<td class='tight'>{_h(f.get('line', ''))}</td>"
                    "</tr>"
                )
            if len(rows_discord_html) >= 40:
                break

    # ── Assembled C2 URLs ──
    url_assembly_html = payload.get("url_assembly", {}) or {}
    assembled_urls_html = url_assembly_html.get("assembled_urls", []) or []
    c2_domain_html = url_assembly_html.get("c2_domain", "")
    c2_source_html = url_assembly_html.get("c2_domain_source", "")
    rows_assembled_urls = []
    for entry in assembled_urls_html:
        rows_assembled_urls.append(
            "<tr>"
            f"<td class='tight'>{_h(entry.get('method', ''))}</td>"
            f"<td class='url-col'>{_h(entry.get('url', ''))}</td>"
            f"<td>{_h(entry.get('description', ''))}</td>"
            "</tr>"
        )

    # ── Infrastructure Probe Results ──
    infra_probe_html = payload.get("infra_probe", {}) or {}
    infra_results = infra_probe_html.get("results", []) or []
    rows_infra_html = []
    for r in infra_results:
        status = r.get("status", "?")
        status_class = "sev-high" if status == "live" else ("sev-medium" if status == "error" else "sev-info")
        dns = f" → {r.get('dns_ip','')}" if r.get('dns_resolved') else ""
        ct = f" [{r.get('content_type','')}]" if r.get('content_type') else ""
        err = f" — {r.get('error','')}" if r.get('error') else ""
        http_display = f"{r.get('http_status','')} {r.get('http_reason','')}".strip() or ""
        rows_infra_html.append(
            "<tr>"
            f"<td class='tight'><span class='sev {status_class}'>{_h(status)}</span></td>"
            f"<td class='url-col'>{_h(r.get('url',''))}{_h(dns)}{_h(ct)}{_h(err)}</td>"
            f"<td class='tight'>{_h(http_display)}</td>"
            "</tr>"
        )

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
    .behavior-table col.file-col {{ width:14ch; }}
    .behavior-table col.line-col {{ width:5ch; }}
    .behavior-table col.beh-col {{ width:32ch; }}
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
    .jlab-table col.id-col {{ width:6ch; }}
    .jlab-table col.name-col {{ width:22ch; }}
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
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table jlab-table'><colgroup><col class='sev-col'><col class='id-col'><col class='name-col'><col><col class='type-col'><col class='count-col'><col class='matches-col'></colgroup><thead><tr><th class='tight'>Severity</th><th class='tight'>ID</th><th>Name</th><th>Description</th><th class='tight'>Type</th><th class='tight'>Count</th><th>Matches (preview)</th></tr></thead><tbody>" + "".join(rows_jlab) + "</tbody></table></div>" if rows_jlab else "")
      + "</div>") if (jlab_overview_rows or rows_jlab) else ""}
    {("<div class='card'><h2 class='triage-title'>Stage2 Analysis</h2>"
      + ("<div class='meta-box'><table class='meta-table'>" + "".join(stage2_rows) + "</table></div>" if stage2_rows else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Native Entry (sample)</th></tr></thead><tbody>" + "".join(rows_stage2_native) + "</tbody></table></div>" if rows_stage2_native else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Type</th><th>Path</th><th>Evidence</th></tr></thead><tbody>" + "".join(rows_stage2_artifacts) + "</tbody></table></div>" if rows_stage2_artifacts else "")
      + "</div>") if (stage2_rows or rows_stage2_native or rows_stage2_artifacts) else ""}
    {("<div class='card'><h2 class='triage-title'>Assembled C2 URLs</h2>"
      + (f"<p style='color:#9dd5ff;margin:.4rem 0'>C2 domain: <strong>{_h(c2_domain_html)}</strong> (source: {_h(c2_source_html)})</p>" if c2_domain_html else "")
      + "<div class='table-wrap'><table class='smart-table'><thead><tr><th class='tight'>Method</th><th>URL</th><th>Description</th></tr></thead><tbody>"
      + "".join(rows_assembled_urls) + "</tbody></table></div>"
      + "</div>") if rows_assembled_urls else ""}
    {("<div class='card'><h2 class='triage-title'>Infrastructure Probe Results</h2>"
      "<div class='table-wrap'><table class='smart-table'><thead><tr><th class='tight'>Status</th><th>URL + Details</th><th class='tight'>HTTP</th></tr></thead><tbody>"
      + "".join(rows_infra_html) + "</tbody></table></div>"
      + "</div>") if rows_infra_html else ""}
    {("<div class='card'><h2 class='triage-title'>Windows Persistence / Staging</h2>"
      "<div class='meta-box'><table class='meta-table'><tbody>"
      + "".join(rows_win_html) + "</tbody></table></div>"
      + "</div>") if rows_win_html else ""}
    {("<div class='card'><h2 class='triage-title'>Blockchain Indicators</h2>"
      "<div class='table-wrap'><table class='smart-table'><thead><tr><th class='tight'>Indicator Type</th><th>Value</th></tr></thead><tbody>"
      + "".join(rows_blockchain) + "</tbody></table></div>"
      + "</div>") if rows_blockchain else ""}
    {("<div class='card'><h2 class='triage-title'>Cryptocurrency Addresses</h2>"
      "<div class='table-wrap'><table class='smart-table'><thead><tr><th>Address</th><th class='tight'>File</th><th class='tight'>Line</th></tr></thead><tbody>"
      + "".join(rows_crypto_html) + "</tbody></table></div>"
      + "</div>") if rows_crypto_html else ""}
    {("<div class='card'><h2 class='triage-title'>Discord / Webhook Indicators</h2>"
      "<div class='table-wrap'><table class='smart-table'><thead><tr><th class='tight'>Signal</th><th>Value</th><th class='tight'>File</th><th class='tight'>Line</th></tr></thead><tbody>"
      + "".join(rows_discord_html) + "</tbody></table></div>"
      + "</div>") if rows_discord_html else ""}
    {("<div class='card'><h2 class='triage-title'>Network Endpoint Assessment</h2>"
      + ("<div class='meta-box'><table class='meta-table'>" + "".join(net_rows) + "</table></div>" if net_rows else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Suspicious URLs</th></tr></thead><tbody>" + "".join(rows_net_suspicious) + "</tbody></table></div>" if rows_net_suspicious else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Unknown URLs</th></tr></thead><tbody>" + "".join(rows_net_unknown) + "</tbody></table></div>" if rows_net_unknown else "")
      + "</div>") if (net_rows or rows_net_suspicious or rows_net_unknown) else ""}
    {("<div class='card'><h2 class='triage-title'>Variant Detections</h2>"
      + ("<div class='table-wrap'><table class='smart-table'><thead><tr><th>Variant</th><th class='tight'>Confidence</th><th class='tight'>Matches</th></tr></thead><tbody>" + "".join(rows_variant) + "</tbody></table></div>" if rows_variant else "")
      + ("<div class='table-wrap' style='margin-top:.7rem;'><table class='smart-table'><thead><tr><th>Variant</th><th>Kind</th><th>Description</th><th>File</th><th class='tight'>Weight</th></tr></thead><tbody>" + "".join(rows_variant_matches) + "</tbody></table></div>" if rows_variant_matches else "")
      + "</div>") if (rows_variant or rows_variant_matches) else ""}
    {("<div class='card'><h2 class='triage-title'>Detected Minecraft Modules</h2>"
      + ("<p style='margin:.4rem 0'>Total modules: <strong>" + _h(minecraft_modules.get('module_count', 0)) + "</strong></p>" if minecraft_modules.get("detected") else "")
      + ("<p style='margin:.4rem 0'>Categories: " + _h(', '.join(f'{k}({v})' for k, v in sorted((minecraft_modules.get('categories', {}) or {}).items()))) + "</p>" if minecraft_modules.get("categories") else "")
      + ("<div class='table-wrap'><table class='smart-table'><thead><tr><th>Category</th><th>Name</th><th>Description</th></tr></thead><tbody>"
         + "".join(
             "<tr>"
             f"<td class='tight'><span class='cat-pill cat-neutral'>{_h(m.get('category', '?'))}</span></td>"
             f"<td>{_h(m.get('name', '?'))}</td>"
             f"<td>{_h(m.get('description', ''))}</td>"
             "</tr>"
             for m in minecraft_modules.get('modules', [])
         )
         + "</tbody></table></div>" if minecraft_modules.get("modules") else "")
      + "</div>") if minecraft_modules.get("detected") else ""}
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
    // ── Show-more / show-all toggle ──
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

    // ── Clickable header sorting for all smart-tables ──
    document.querySelectorAll("table.smart-table thead tr").forEach(function (headerRow) {{
      var table = headerRow.closest("table");
      var tbody = table.querySelector("tbody");
      if (!tbody || tbody.children.length < 2) return;
      var headers = headerRow.querySelectorAll("th");
      headers.forEach(function (th, colIdx) {{
        th.style.cursor = "pointer";
        th.title = "Click to sort";
        th.addEventListener("click", function () {{
          var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
          var asc = th.getAttribute("data-sort") !== "asc";
          // Reset all header indicators
          headers.forEach(function (h) {{ h.removeAttribute("data-sort"); h.style.color = ""; }});
          th.setAttribute("data-sort", asc ? "asc" : "desc");
          th.style.color = "#9dd5ff";
          rows.sort(function (a, b) {{
            var cellA = (a.children[colIdx] || {{}}).textContent || "";
            var cellB = (b.children[colIdx] || {{}}).textContent || "";
            // Numeric sort if both look numeric
            var numA = parseFloat(cellA.trim());
            var numB = parseFloat(cellB.trim());
            if (!isNaN(numA) && !isNaN(numB)) {{
              return asc ? numA - numB : numB - numA;
            }}
            return asc ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
          }});
          rows.forEach(function (row) {{ tbody.appendChild(row); }});
        }});
      }});
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


def _find_existing_decompiled_dirs(jar_candidates: List[Path]) -> dict[str, Path]:
    """Return dict of {jar_stem: existing_dir} for JARs that have a matching directory with .java files."""
    cwd = Path.cwd().resolve()
    existing: dict[str, Path] = {}
    for jar in jar_candidates:
        out_dir = (cwd / jar.stem).resolve()
        if out_dir.is_dir() and any(out_dir.rglob("*.java")):
            existing[jar.stem] = out_dir
    return existing


def _prompt_no_cfr_with_existing(
    jar_candidates: List[Path],
    existing_dirs: dict[str, Path],
    console=None,
) -> Path | None:
    """Prompt when no CFR jar is available but pre-existing decompiled folders exist.

    Returns the selected Path to scan, or None to cancel/fall through.
    """
    if RICH_AVAILABLE:
        ui_console = console or Console(stderr=True, width=_triage_ui_width())
        width = _triage_ui_width(ui_console)
        ui_console.print()
        ui_console.print(
            Panel(
                "[bold #C000FF]No CFR decompiler found.[/bold #C000FF]\n"
                "However, pre-existing decompiled source folders were detected.",
                border_style="#C000FF",
                width=width,
            )
        )
        table = Table(box=box.SIMPLE, show_edge=False, expand=False, padding=(0, 1))
        table.width = width - 4
        table.add_column("#", style="bold #C000FF", no_wrap=True)
        table.add_column("Decompiled folder", style="bold white", overflow="fold")
        idx_map: dict[int, Path] = {}
        for idx, jar in enumerate(jar_candidates, start=1):
            stem = jar.stem
            if stem in existing_dirs:
                label = f"{stem}/  (from {jar.name})"
                table.add_row(str(idx), label)
                idx_map[idx] = existing_dirs[stem]
        table.add_row("0", "Cancel — scan current directory instead")
        ui_console.print(
            Panel(
                table,
                border_style="#C000FF",
                width=width,
            )
        )
    else:
        idx_map = {}
        print("", file=sys.stderr)
        print("No CFR decompiler found.", file=sys.stderr)
        print("However, pre-existing decompiled source folders were detected:", file=sys.stderr)
        for idx, jar in enumerate(jar_candidates, start=1):
            stem = jar.stem
            if stem in existing_dirs:
                print(f"  {idx}. {stem}/  (from {jar.name})", file=sys.stderr)
                idx_map[idx] = existing_dirs[stem]
        print("  0. Cancel — scan current directory instead", file=sys.stderr)

    while True:
        print("Select a decompiled folder to scan: ", end="", file=sys.stderr, flush=True)
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
        if choice in idx_map:
            print("", file=sys.stderr)
            return idx_map[choice]
        print(f"Invalid selection. Enter 0-{len(jar_candidates)}.", file=sys.stderr)


def _prompt_cfr_needed(jar_candidates: List[Path], console=None) -> bool:
    """Inform the user that CFR is needed to decompile JARs, then ask whether to
    scan cwd anyway or exit.

    Returns True to continue scanning cwd, False to exit.
    """
    if RICH_AVAILABLE:
        ui_console = console or Console(stderr=True, width=_triage_ui_width())
        width = _triage_ui_width(ui_console)
        lines = [
            "[bold #C000FF]No CFR decompiler found.[/bold #C000FF]",
            "",
            f"Found [bold white]{len(jar_candidates)}[/bold white] JAR(s) to scan:",
        ]
        for jar in jar_candidates:
            lines.append(f"  • {jar.name}")
        lines += [
            "",
            "Place a CFR jar (e.g. [italic]cfr-0.152.jar[/italic]) in this directory to enable",
            "automatic decompilation, or point the tool at an already-decompiled folder:",
            "",
            f"  [dim]python java_triage.py ./{jar_candidates[0].stem}[/dim]  (if already extracted)",
            "",
            "Download CFR: [link=https://www.benf.org/other/cfr/]https://www.benf.org/other/cfr/[/link]",
        ]
        ui_console.print(
            Panel(
                "\n".join(lines),
                border_style="#C000FF",
                width=width,
            )
        )
    else:
        print("", file=sys.stderr)
        print("No CFR decompiler found.", file=sys.stderr)
        print(f"Found {len(jar_candidates)} JAR(s) to scan:", file=sys.stderr)
        for jar in jar_candidates:
            print(f"  - {jar.name}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Place a CFR jar (e.g. cfr-0.152.jar) in this directory to enable", file=sys.stderr)
        print("automatic decompilation, or point the tool at an already-decompiled folder:", file=sys.stderr)
        print(f"  python java_triage.py ./{jar_candidates[0].stem}  (if already extracted)", file=sys.stderr)
        print("", file=sys.stderr)
        print("Download CFR: https://www.benf.org/other/cfr/", file=sys.stderr)

    # Ask user whether to scan cwd anyway or exit
    while True:
        print("Scan current directory directly anyway? (y/N): ", end="", file=sys.stderr, flush=True)
        try:
            raw = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("", file=sys.stderr)
            return False
        if raw in ("", "n", "no"):
            print("", file=sys.stderr)
            return False
        if raw in ("y", "yes"):
            print("", file=sys.stderr)
            return True
        print("Please answer y or n.", file=sys.stderr)


def _prompt_reuse_decompiled_dir(jar: Path, out_dir: Path, console=None) -> bool:
    """Ask whether to reuse an existing decompiled directory or re-decompile.

    Returns True to reuse, False to re-decompile.
    """
    if RICH_AVAILABLE:
        ui_console = console or Console(stderr=True, width=_triage_ui_width())
        width = _triage_ui_width(ui_console)
        ui_console.print()
        ui_console.print(
            Panel(
                f"[bold white]{out_dir.name}/[/bold white] already exists for [bold white]{jar.name}[/bold white].",
                border_style="#C000FF",
                width=width,
            )
        )
        ui_console.print("  [bold #C000FF]1.[/bold #C000FF] Reuse existing decompiled folder")
        ui_console.print("  [bold #C000FF]2.[/bold #C000FF] Re-decompile (delete and extract fresh)")
        ui_console.print("  [bold #C000FF]0.[/bold #C000FF] Cancel")
    else:
        print("", file=sys.stderr)
        print(f"{out_dir.name}/ already exists for {jar.name}.", file=sys.stderr)
        print("  1. Reuse existing decompiled folder", file=sys.stderr)
        print("  2. Re-decompile (delete and extract fresh)", file=sys.stderr)
        print("  0. Cancel", file=sys.stderr)

    while True:
        print("Choose an option: ", end="", file=sys.stderr, flush=True)
        try:
            raw = input().strip()
        except (EOFError, KeyboardInterrupt):
            print("", file=sys.stderr)
            return True
        if raw == "1":
            print("", file=sys.stderr)
            return True
        if raw == "2":
            print("", file=sys.stderr)
            return False
        if raw == "0":
            print("", file=sys.stderr)
            return True
        print("Invalid choice. Enter 1, 2, or 0.", file=sys.stderr)


def maybe_prepare_cwd_jar_scan_root(initial_root: Path, show_progress: bool, progress_console=None) -> Path:
    cwd = Path.cwd().resolve()
    if initial_root != cwd:
        if initial_root.is_file() and initial_root.suffix.lower() in {".jar", ".zip"}:
            cfr = _find_cfr_jar(cwd)
            if cfr is None:
                progress(show_progress, "CFR jar not found; cannot decompile direct JAR target", progress_console)
                return initial_root
            return _prepare_single_jar_scan_root(initial_root, cwd, cfr, show_progress, progress_console)
        return initial_root

    cfr = _find_cfr_jar(cwd)

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

    # --- No CFR jar available ---
    if cfr is None:
        if not sys.stdin.isatty():
            progress(
                show_progress,
                "no CFR jar found and stdin is not interactive; scanning cwd directly",
                progress_console,
            )
            return initial_root

        existing_dirs = _find_existing_decompiled_dirs(jar_candidates)
        if existing_dirs:
            chosen = _prompt_no_cfr_with_existing(jar_candidates, existing_dirs, progress_console)
            if chosen is not None:
                progress(
                    show_progress,
                    f"using existing decompiled directory: {_display_report_path(chosen, cwd)}",
                    progress_console,
                )
                return chosen
            # User chose 0 (cancel) — fall through to scan cwd
            progress(
                show_progress,
                "no decompiled folder selected; scanning cwd directly",
                progress_console,
            )
            return initial_root

        # No existing decompiled folders — tell user CFR is needed and ask
        if not _prompt_cfr_needed(jar_candidates, progress_console):
            print("Scan cancelled. Place a CFR jar and try again.", file=sys.stderr)
            sys.exit(0)
        progress(
            show_progress,
            "CFR jar required for JAR decompilation; scanning cwd directly",
            progress_console,
        )
        return initial_root

    # --- CFR is available ---
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

    return _prepare_single_jar_scan_root(selected, cwd, cfr, show_progress, progress_console)


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
        try:
            console.print(Text.from_ansi(rendered), highlight=False)
        except UnicodeEncodeError:
            stream = sys.stderr if to_stderr else sys.stdout
            print("Java Triage - https://github.com/cev-api/Java-Triage", file=stream)
    else:
        stream = sys.stderr if to_stderr else sys.stdout
        try:
            print(rendered, file=stream)
        except UnicodeEncodeError:
            print("Java Triage - https://github.com/cev-api/Java-Triage", file=stream)


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
    url_assembly: dict | None = None,
    infra_probe: dict | None = None,
    minecraft_modules: dict | None = None,
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

    # ── Windows Persistence / Staging Indicators ──
    win_artifacts = _extract_windows_artifacts(findings, behaviors)
    if any(win_artifacts.values()):
        _print_section(console, "Windows Persistence / Staging Indicators")
        if win_artifacts.get("env_vars"):
            console.print(f"  Environment variables: [cyan]{', '.join(win_artifacts['env_vars'])}[/cyan]")
        if win_artifacts.get("paths"):
            console.print(f"  Staging paths: [yellow]{', '.join(win_artifacts['paths'])}[/yellow]")
        if win_artifacts.get("executables"):
            console.print(f"  Executables referenced: [magenta]{', '.join(win_artifacts['executables'])}[/magenta]")
        if win_artifacts.get("launched_payloads"):
            console.print(f"  Launched payloads: [red]{', '.join(win_artifacts['launched_payloads'])}[/red]")
        pa = win_artifacts.get("persistence_assessment", {})
        if pa.get("confirmed"):
            console.print(f"  [green]Confirmed:[/green] {', '.join(pa['confirmed'])}")
        if pa.get("not_confirmed"):
            console.print(f"  [red]Not confirmed:[/red] {', '.join(pa['not_confirmed'])}")

    _cat_prio = {"url": 1, "credential_or_identity_field": 2, "dynamic_execution": 3, "cryptocurrency_address": 4, "discord_indicator": 5, "rpc_template": 6, "path": 7, "http_header": 8, "comms_indicator": 9, "sensitive_game_data": 10, "hex_or_contract": 11, "string": 12, "base64_blob": 13, "hex_decoded_binary": 14, "base64_decoded_binary": 15}
    if findings:
        _print_section(console, "Decode + String Findings")
        t = Table(show_lines=False, expand=True)
        t.add_column("Category", style="magenta", max_width=22, no_wrap=True, overflow="ellipsis")
        t.add_column("Location", style="cyan", overflow="fold")
        t.add_column("Function", style="green")
        t.add_column("Decoded", style="white", overflow="fold")
        _cat_prio = {"url": 1, "credential_or_identity_field": 2, "dynamic_execution": 3, "cryptocurrency_address": 4, "discord_indicator": 5, "rpc_template": 6, "path": 7, "http_header": 8, "comms_indicator": 9, "sensitive_game_data": 10, "hex_or_contract": 11, "string": 12, "base64_blob": 13, "hex_decoded_binary": 14, "base64_decoded_binary": 15}
        for f in sorted(findings, key=lambda x: (_cat_prio.get(x.category, 99), x.category, (x.decoded or "").lower())):
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
        _bsev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for b in sorted(behaviors, key=lambda x: (_bsev.get(behavior_severity(x.behavior), 9), x.behavior, x.file, x.line)):
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

    mm = minecraft_modules or {}
    if mm.get("detected"):
        _print_section(console, "Detected Minecraft Modules")
        console.print(f"Total modules: [cyan]{mm.get('module_count', 0)}[/cyan]")
        cats = mm.get("categories", {})
        if cats:
            console.print(f"Categories: [yellow]{', '.join(f'{k}({v})' for k, v in sorted(cats.items()))}[/yellow]")
        mm_table = Table(show_header=True, box=box.SIMPLE, expand=True)
        mm_table.add_column("Category", style="magenta", no_wrap=True)
        mm_table.add_column("Name", style="bold white")
        mm_table.add_column("Description", style="green", overflow="fold")
        for m_item in mm.get("modules", []):
            mm_table.add_row(m_item.get("category", "?"), m_item.get("name", "?"), m_item.get("description", ""))
        console.print(mm_table)

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
            _jls = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            for sig in sorted((jl.get("signatures", []) or [])[:80], key=lambda x: (_jls.get(str(x.get("severity", "info")).lower(), 9), str(x.get("name", "")))):
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

    # ── Cryptocurrency Addresses ──
    crypto_findings = [f for f in findings if f.category == "cryptocurrency_address"]
    if crypto_findings:
        _print_section(console, "Cryptocurrency Addresses")
        ct = Table(show_header=True, box=box.SIMPLE, expand=True)
        ct.add_column("Address", style="bright_yellow")
        ct.add_column("Location", style="cyan")
        for f in crypto_findings:
            ct.add_row(f.decoded, f"{f.file}:{f.line}")
        console.print(ct)

    # ── Discord Webhook / Token Indicators ──
    discord_findings = [f for f in findings if f.category == "discord_indicator" and any(
        k in (f.note or "").lower() for k in ("webhook", "token", "snowflake_id", "notification")
    )]
    if discord_findings:
        _print_section(console, "Discord / Webhook Indicators")
        dt = Table(show_header=True, box=box.SIMPLE, expand=True)
        dt.add_column("Indicator", style="bright_magenta")
        dt.add_column("Value", style="white", overflow="fold")
        dt.add_column("Location", style="cyan")
        for f in discord_findings[:30]:
            signal = (f.note or "").replace("source=string_scanner signal=", "")
            dt.add_row(signal[:40], f.decoded[:80], f"{f.file}:{f.line}")
        console.print(dt)

    # ── Assembled C2 URLs (from url_assembly) ──
    ua = url_assembly or {}
    assembled = ua.get("assembled_urls", [])
    if assembled:
        _print_section(console, "Assembled C2 URLs")
        if ua.get("c2_domain"):
            console.print(f"C2 domain: [cyan]{ua.get('c2_domain')}[/cyan] (source: {ua.get('c2_domain_source', 'unknown')})")
        ua_table = Table(show_header=True, box=box.SIMPLE, expand=True)
        ua_table.add_column("Method", style="green", no_wrap=True)
        ua_table.add_column("URL", style="white", overflow="fold")
        ua_table.add_column("Description", style="yellow")
        for entry in assembled:
            ua_table.add_row(entry.get("method", ""), entry.get("url", ""), entry.get("description", ""))
        console.print(ua_table)

    # ── Infrastructure Probe Results (from infra_probe) ──
    ip = infra_probe or {}
    ip_results = ip.get("results", [])
    if ip_results:
        _print_section(console, "Infrastructure Probe Results")
        ip_summary = ip.get("summary", {})
        console.print(
            f"Probe summary: [green]{ip_summary.get('live',0)} live[/green], "
            f"[red]{ip_summary.get('dead',0)} dead[/red], "
            f"[yellow]{ip_summary.get('error',0)} errors[/yellow]"
        )
        ip_table = Table(show_header=True, box=box.SIMPLE, expand=True)
        ip_table.add_column("Status", style="red", no_wrap=True)
        ip_table.add_column("URL + Details", style="white", overflow="fold")
        ip_table.add_column("HTTP", style="cyan", no_wrap=True)
        for r in ip_results:
            status = r.get("status", "?")
            status_style = "[green]" if status == "live" else ("[yellow]" if status == "error" else "[red]")
            dns_info = f" -> {r.get('dns_ip','')}" if r.get('dns_resolved') else ""
            ct_info = f" [{r.get('content_type','')}]" if r.get('content_type') else ""
            err_info = f" - {r.get('error','')}" if r.get('error') else ""
            http_info = f"{r.get('http_status','')} {r.get('http_reason','')}".strip()
            ip_table.add_row(
                f"{status_style}{status}[/]",
                f"{r.get('url','')}{dns_info}{ct_info}{err_info}",
                http_info,
            )
        console.print(ip_table)

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


def _executive_summary_high_confidence_context(triage_payload: dict[str, Any]) -> str:
    summary = triage_payload.get("summary", {}) or {}
    runtime_c2 = triage_payload.get("runtime_c2", {}) or {}
    stage2 = triage_payload.get("stage2_analysis", {}) or {}
    assessments = triage_payload.get("assessment_summary", {}) or {}
    behaviors = triage_payload.get("behavior_findings", []) or []

    lines: List[str] = []
    vt = summary.get("verdict_tiers", {}) or {}
    lines.append(
        "Verdict tiers: confirmed_behavior={0} exposed_capability={1} suspicious_capability={2} library_noise={3}".format(
            vt.get("confirmed_behavior", 0),
            vt.get("exposed_capability", 0),
            vt.get("suspicious_capability", 0),
            vt.get("library_noise", 0),
        )
    )

    if runtime_c2.get("resolved"):
        lines.append(f"Resolved C2 domain: {runtime_c2.get('c2_base_url', '')}")
        if runtime_c2.get("exfil_endpoint"):
            lines.append(f"Exfil endpoint: {runtime_c2.get('exfil_endpoint')}")
        if runtime_c2.get("payload_endpoint"):
            lines.append(f"Payload endpoint: {runtime_c2.get('payload_endpoint')}")

    if stage2.get("enabled") or stage2.get("payload_url_resolved"):
        if stage2.get("payload_url_resolved"):
            lines.append(f"Stage-2 payload URL: {stage2.get('payload_url_resolved')}")
        if stage2.get("static_only_no_execution"):
            lines.append("Stage-2 analysis is static-only; no code execution was performed.")

    if assessments.get("counts"):
        counts = assessments.get("counts", {}) or {}
        lines.append(
            "Assessment counts: benign={0} needs_review={1} suspicious={2}".format(
                counts.get("benign", 0),
                counts.get("needs_review", 0),
                counts.get("suspicious", 0),
            )
        )

    high_confidence = []
    for item in behaviors:
        if not isinstance(item, dict):
            continue
        behavior = str(item.get("behavior", ""))
        if behavior.startswith("proof_") or behavior in {
            "two_payload_exfil_architecture",
            "multi_path_exfil_breakdown",
            "blockchain_dns_c2_resolver",
            "credential_exfiltration_post",
            "exfil_endpoint_prefiremc",
            "exfil_endpoint_submit_log",
            "payload_download_endpoint",
            "embedded_native_payload_loader",
            "staged_remote_jar_execution",
        }:
            high_confidence.append(item)

    if high_confidence:
        lines.append("High-confidence behaviors:")
        for item in sorted(
            high_confidence,
            key=lambda x: (str(x.get("severity", "")), str(x.get("behavior", "")), str(x.get("file", "")), int(x.get("line", 0) or 0)),
        )[:10]:
            lines.append(
                f"- [{item.get('severity', 'info')}] {item.get('behavior', '')}: {item.get('evidence', '')}"
            )

    caveats = triage_payload.get("contradiction_notes", []) or []
    if caveats:
        lines.append("Caveats:")
        for note in caveats[:5]:
            lines.append(f"- {note}")

    return "\n".join(lines)


def _force_malicious_verdict(triage_payload: dict[str, Any]) -> bool:
    summary = triage_payload.get("summary", {}) or {}
    runtime_c2 = triage_payload.get("runtime_c2", {}) or {}
    stage2 = triage_payload.get("stage2_analysis", {}) or {}
    behaviors = triage_payload.get("behavior_findings", []) or []
    behavior_names = {str(b.get("behavior", "")) for b in behaviors if isinstance(b, dict)}

    confirmed = int((summary.get("verdict_tiers", {}) or {}).get("confirmed_behavior", 0) or 0)
    if confirmed <= 0:
        return False

    if runtime_c2.get("resolved") and (runtime_c2.get("exfil_endpoint") or runtime_c2.get("payload_endpoint")):
        if behavior_names & {
            "two_payload_exfil_architecture",
            "multi_path_exfil_breakdown",
            "blockchain_dns_c2_resolver",
            "credential_exfiltration_post",
            "exfil_endpoint_prefiremc",
            "exfil_endpoint_submit_log",
            "payload_download_endpoint",
            "embedded_native_payload_loader",
            "staged_remote_jar_execution",
        }:
            return True

    if stage2.get("payload_url_resolved") and behavior_names & {
        "payload_download_endpoint",
        "embedded_native_payload_loader",
        "staged_remote_jar_execution",
    }:
        return True

    return False


def _reinforce_executive_summary_text(text: str, triage_payload: dict[str, Any]) -> str:
    normalized = _normalize_executive_summary_text(text)
    if not normalized:
        return ""
    if not _force_malicious_verdict(triage_payload):
        return normalized

    lines = normalized.splitlines()
    if lines:
        if lines[0].lower().startswith("verdict:"):
            lines[0] = "VERDICT: Malicious"
        else:
            lines.insert(0, "VERDICT: Malicious")
    else:
        lines = ["VERDICT: Malicious"]

    if any("cheat client" in line.lower() for line in lines[1:]):
        lines.insert(
            1,
            "- Cheat-client modules are present, but the resolved C2, staged payload path, and exfiltration architecture make this malware.",
        )

    return "\n".join(lines).strip()


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
        + "\n\nHIGH-CONFIDENCE FACTS:\n"
        + _executive_summary_high_confidence_context(triage_payload)
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
    return _reinforce_executive_summary_text(_extract_chat_completions_output_text(data), triage_payload)


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
        + "\n\nHIGH-CONFIDENCE FACTS:\n"
        + _executive_summary_high_confidence_context(triage_payload)
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
    return _reinforce_executive_summary_text(_extract_chat_completions_output_text(data), triage_payload)


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


def _show_interactive_prompt(
    url_assembly: dict,
    runtime_c2: dict,
    stage2_analysis: dict,
    all_findings: list,
) -> None:
    """Post-scan prompt: ask user whether to download + decrypt stage-2 payload.

    Shows assembled C2 URLs, then asks Y/N for download+decrypt.
    Also offers an optional probe. Simple, no auto-execution.
    """
    assembled = url_assembly.get("assembled_urls", [])
    c2_domain = url_assembly.get("c2_domain", "")
    cdn_urls = [e for e in assembled if "cdn" in e.get("url", "").lower() or "/e/" in e.get("url", "").lower()]
    cdn_url = cdn_urls[0]["url"] if cdn_urls else (runtime_c2.get("payload_endpoint", "") or "")

    if not assembled:
        return

    print()
    print("=" * 70)
    print("  POST-SCAN: Actionable Infrastructure")
    print("=" * 70)

    if c2_domain:
        print(f"\n  C2 domain: {c2_domain}")
        print(f"  Source: {url_assembly.get('c2_domain_source', 'unknown')}")

    print("\n  Assembled endpoints:")
    for entry in assembled:
        icon = ""
        if runtime_c2.get("resolved"):
            if runtime_c2.get("payload_endpoint") == entry["url"]:
                icon = "  \033[92m● PAYLOAD\033[0m"
            elif runtime_c2.get("exfil_endpoint") == entry["url"]:
                icon = "  \033[92m● EXFIL\033[0m"
        print(f"    {entry.get('method', '?')} {entry['url']}{icon}")

    fallback = url_assembly.get("fallback_domain", "")
    if fallback:
        print(f"\n  Fallback C2 domain: {fallback}")

    # ── Stage-2 download + decrypt prompt ──
    if cdn_url:
        print(f"\n  {'─'*50}")
        print(f"  \033[93mⓘ Stage-2 payload is available for download:\033[0m")
        print(f"    {cdn_url}")
        print(f"    Expected: AES-encrypted blob → decrypt → ZIP (python.exe + main.py)")
        print(f"    Decryption key is known from source code.")
        print(f"    \033[91mNO code will be executed. Static-only analysis.\033[0m")
        print()

        while True:
            try:
                choice = input("  Download + decrypt this stage-2 payload? [Y/n]: ").strip().lower()
                if choice in ("", "y", "yes"):
                    print(f"\n  \033[92mDownloading stage-2 payload...\033[0m")
                    try:
                        # Download
                        blob_path = Path("stage2_payload.bin")
                        req = request.Request(cdn_url, headers={"User-Agent": "java-triage/1.0"}, method="GET")
                        with request.urlopen(req, timeout=120) as resp, open(blob_path, "wb") as f:
                            shutil.copyfileobj(resp, f, length=1024 * 1024)
                        size = blob_path.stat().st_size
                        print(f"  Downloaded {size:,} bytes to {blob_path}")

                        # Decrypt
                        _aes_decrypt_stage2_blob(str(blob_path))
                    except Exception as exc:
                        print(f"  \033[91mDownload/decrypt failed: {exc}\033[0m")
                        import traceback
                        traceback.print_exc()
                    break
                elif choice in ("n", "no"):
                    print("  Skipped.")
                    break
                else:
                    print("  Please enter Y or N.")
            except EOFError:
                print("  Skipped.")
                break

    # ── Optional: probe endpoints ──
    if len(assembled) > 0:
        print()
        while True:
            try:
                choice = input("  Probe these endpoints (DNS + HTTP HEAD, Range: bytes=0-0 for CDN)? [y/N]: ").strip().lower()
                if choice in ("y", "yes"):
                    print(f"\n  Probing {len(assembled)} endpoints...\n")
                    probe_result = probe_live_endpoints(assembled, timeout=10)
                    for r in probe_result.get("results", []):
                        status = r.get("status", "?")
                        icon = "\033[92m● LIVE\033[0m" if status == "live" else (f"\033[93m○ HTTP {r.get('http_status','?')}\033[0m" if status == "error" else "\033[91m● DEAD\033[0m")
                        dns = f" → {r.get('dns_ip','')}" if r.get('dns_resolved') else ""
                        ct = f" [{r.get('content_type','')}]" if r.get('content_type') else ""
                        err = f" — {r.get('error','')}" if r.get('error') else ""
                        print(f"    {icon} {r['url']}{dns}{ct}{err}")
                    summary = probe_result.get("summary", {})
                    print(f"\n  {summary.get('live',0)} live, {summary.get('dead',0)} dead, {summary.get('error',0)} errors")
                    break
                elif choice in ("", "n", "no"):
                    break
                else:
                    print("  Please enter Y or N.")
            except EOFError:
                break

    print("=" * 70)


def _dispatch_post_scan_action(action: dict, stage2_analysis: dict, url_assembly: dict) -> None:
    """Execute a post-scan action chosen by the user.

    Currently supported:
      - scan_downloaded_stage2: re-launch java_triage on the downloaded JAR
      - download_stage2_payload / download_raw_blob: download to a path
      - probe_all_endpoints: DNS + HTTP probe (live, now implemented)
      - download_and_decrypt_stage2: download + AES decrypt (TODO)
    """
    action_id = action.get("id", "")

    if action_id == "scan_downloaded_stage2":
        jar_path = stage2_analysis.get("download_path", "")
        if not jar_path or not Path(jar_path).is_file():
            print(f"\n  \033[91mError: Downloaded file not found at {jar_path}\033[0m")
            return
        print(f"\n  \033[92mLaunching triage scan on stage-2 JAR:\033[0m")
        print(f"    {jar_path}")
        print()
        try:
            _run_inline_stage2_scan(jar_path)
        except Exception as exc:
            print(f"\n  \033[91mStage-2 scan failed: {exc}\033[0m")

    elif action_id in ("download_stage2_payload", "download_raw_blob"):
        url = action.get("url", "")
        if not url:
            print("\n  \033[91mError: No URL provided for download.\033[0m")
            return
        out_name = "stage2_payload.bin"
        print(f"\n  Downloading from: {url}")
        print(f"  Saving to: {out_name}")
        try:
            req = request.Request(url, headers={"User-Agent": "java-triage/1.0"}, method="GET")
            with request.urlopen(req, timeout=60) as resp, open(out_name, "wb") as f:
                shutil.copyfileobj(resp, f, length=1024 * 1024)
            size = Path(out_name).stat().st_size
            print(f"  \033[92mDownloaded {size:,} bytes to {out_name}\033[0m")
            print(f"  Re-run: java_triage.py \"{out_name}\"")
        except Exception as exc:
            print(f"  \033[91mDownload failed: {_friendly_network_error(exc)}\033[0m")

    elif action_id in ("download_and_decrypt_stage2", "decrypt_downloaded_blob"):
        # Determine blob path: either from the already-downloaded stage2 or from user download
        blob_path = action.get("download_path", "")
        if not blob_path:
            # Fall back to stage2_analysis download path
            blob_path = stage2_analysis.get("download_path", "")
        if not blob_path or not Path(blob_path).is_file():
            print(f"\n  \033[91mError: No downloaded blob found at {blob_path or '?'}\033[0m")
            return

        size = Path(blob_path).stat().st_size
        size_mb = size / (1024 * 1024)
        print(f"\n  \033[92mDecrypting AES-encrypted blob ({size_mb:.1f} MB)...\033[0m")
        print(f"  Source: {blob_path}")
        print(f"  AES key: dK9mT3nR7xQ2pL8wF4jH6yB1cN5gA0sZ...")
        print(f"  Cipher:  AES/CBC/NoPadding")
        print()

        try:
            _aes_decrypt_stage2_blob(blob_path)
        except Exception as exc:
            print(f"  \033[91mDecryption failed: {exc}\033[0m")

    elif action_id == "probe_all_endpoints":
        assembled = url_assembly.get("assembled_urls", [])
        if not assembled:
            print("\n  \033[91mNo assembled URLs to probe.\033[0m")
            return
        print(f"\n  Probing {len(assembled)} endpoints (DNS + HTTP HEAD, Range: bytes=0-0 for CDN)...")
        print("  This may take a few seconds per endpoint...\n")

        probe_result = probe_live_endpoints(assembled, timeout=10)
        results = probe_result.get("results", [])
        summary = probe_result.get("summary", {})

        for r in results:
            status = r.get("status", "?")
            if status == "live":
                icon = "\033[92m● LIVE\033[0m"
            elif status == "error":
                icon = f"\033[93m○ HTTP {r.get('http_status', '?')}\033[0m"
            else:
                icon = "\033[91m● DEAD\033[0m"

            dns = f" → {r.get('dns_ip', '?')}" if r.get("dns_resolved") else " (no DNS)"
            ct = f" [{r.get('content_type', '')}]" if r.get("content_type") else ""
            err = f" — {r.get('error', '')}" if r.get("error") else ""

            print(f"    {icon} {r['url']}{dns}{ct}{err}")

        print(f"\n  Summary: {summary.get('live', 0)} live, "
              f"{summary.get('dead', 0)} dead, "
              f"{summary.get('error', 0)} errors")

    else:
        print(f"\n  \033[93mAction '{action_id}' not implemented in interactive mode.\033[0m")


def _aes_decrypt_stage2_blob(blob_path_str: str) -> None:
    """Decrypt the AES/CBC/NoPadding encrypted stage-2 blob from Zenith malware.

    The decryption logic is reverse-engineered from hUvPFYp.java:
      1. Read the raw blob bytes
      2. Extract first 9 bytes (version/meta header), then IV = bytes 9-24 (16 bytes)
      3. The remaining bytes are the ciphertext
      4. Key: first 16 bytes of Base64.decoder.decode("dK9mT3nR7xQ2pL8wF4jH6yB1cN5gA0sZ12345678abc=")
         which is bytes 32-47 of the 48-byte decoded blob
      5. Decrypt with AES/CBC/NoPadding, strip PKCS5-style padding
      6. Write decrypted ZIP to disk
    """
    import base64 as _b64

    blob_path = Path(blob_path_str)
    if not blob_path.is_file():
        raise FileNotFoundError(f"Blob not found: {blob_path}")

    raw = blob_path.read_bytes()
    total = len(raw)

    # Step 1: Check for Fernet-style header (Base64-URL-encoded)
    if raw[:4] == b"gAAA":
        print("  Detected Fernet/Base64-URL encoding → decoding...")
        raw = _b64.urlsafe_b64decode(raw.decode("ascii"))
        total = len(raw)

    print(f"  Raw bytes after decode: {total:,}")

    # Step 2: Extract IV from header
    # Format: 9-byte header (version/flag byte + 8-byte salt) then 16-byte IV
    if total < 25:
        raise ValueError(f"Blob too small: {total} bytes (need at least 25)")

    iv = raw[9:25]
    ciphertext = raw[25:]
    print(f"  IV: {iv.hex()}")
    print(f"  Ciphertext: {len(ciphertext):,} bytes")

    # Step 3: Derive AES key from known Base64 encoded key
    b64_key = "dK9mT3nR7xQ2pL8wF4jH6yB1cN5gA0sZ12345678abc="
    try:
        decoded_key_bytes = _b64.urlsafe_b64decode(b64_key)
    except Exception:
        decoded_key_bytes = _b64.b64decode(b64_key)
    print(f"  Base64 key decoded: {len(decoded_key_bytes)} bytes")

    # hUvPFYp.java does: System.arraycopy(countRef, 16, v3, 0, 16)
    # So key is bytes 16-32 of the decoded key material
    aes_key = decoded_key_bytes[16:32]
    print(f"  AES key: {aes_key.hex()}")

    # Step 4: Try decryption
    def _do_aes_decrypt(key, iv, ct):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            d = cipher.decryptor()
            return d.update(ct) + d.finalize()
        except ImportError:
            try:
                from Crypto.Cipher import AES as AES_Crypto
                return AES_Crypto.new(key, AES_Crypto.MODE_CBC, iv).decrypt(ct)
            except ImportError:
                raise ImportError(
                    "AES decryption requires 'cryptography' or 'pycryptodome'. "
                    "Install with: pip install cryptography"
                )

    # Approach A: raw ciphertext (if blob was already binary)
    decrypted = _do_aes_decrypt(aes_key, iv, ciphertext)

    # Check if decrypted output looks like a ZIP
    if decrypted[:2] != b"PK":
        # Approach B: maybe blob was Base64-URL-encoded before AES layer
        print("  Raw decrypt didn't yield ZIP — trying Base64-URL decode of blob first...")
        try:
            raw_text = raw.decode("ascii").rstrip()
            b64_decoded = _b64.urlsafe_b64decode(raw_text + "==")
            # Re-extract IV from decoded bytes
            iv2 = b64_decoded[9:25]
            ct2 = b64_decoded[25:]
            decrypted = _do_aes_decrypt(aes_key, iv2, ct2)
        except Exception:
            pass

    # Final check
    if decrypted[:2] != b"PK":
        raise ValueError(
            f"Decryption produced non-ZIP output. First bytes: {decrypted[:16].hex()}. "
            "The AES key derivation or IV extraction may need adjustment."
        )

    # Strip PKCS5-style padding
    pad_len = decrypted[-1]
    if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
        decrypted = decrypted[:-pad_len]
        print(f"  PKCS5 padding stripped ({pad_len} bytes)")

    print(f"  Decrypted: {len(decrypted):,} bytes")

    # Step 5: Write output
    out_path = blob_path.with_suffix(".decrypted.zip")
    out_path.write_bytes(decrypted)
    print(f"  \033[92mDecrypted ZIP written to: {out_path}\033[0m")
    print(f"  \033[92mSize: {out_path.stat().st_size:,} bytes\033[0m")
    print()
    print(f"  To scan the stage-2 payload:")
    print(f"    java_triage.py \"{out_path}\" --no-auto-decrypt")


def _run_inline_stage2_scan(jar_path: str) -> None:
    """Decompile and scan a stage-2 JAR inline using the existing tool pipeline.

    Creates a temp decompile directory, runs CFR, then scans the result.
    Skips auto-decrypt/decipher since stage-2 payloads are already raw.
    """
    jar = Path(jar_path)
    if not jar.is_file():
        raise FileNotFoundError(f"JAR not found: {jar_path}")

    # ── Find CFR JAR ──
    cfr_candidates = sorted(Path().glob("cfr*.jar")) + sorted(Path().glob("cfr*.jar_"))
    if not cfr_candidates:
        raise FileNotFoundError("No CFR JAR found in current directory. Place cfr.jar next to java_triage.py.")

    cfr_jar = cfr_candidates[0]

    # ── Create output directory ──
    out_dir = jar.parent / f"{jar.stem}_stage2_triage"
    if out_dir.exists():
        idx = 2
        while (jar.parent / f"{jar.stem}_stage2_triage_{idx}").exists():
            idx += 1
        out_dir = jar.parent / f"{jar.stem}_stage2_triage_{idx}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Decompiling with CFR to: {out_dir}")
    print(f"  This may take a moment for large JARs...")

    # ── Run CFR ──
    java_home = os.environ.get("JAVA_HOME", "")
    java_bin = Path(java_home) / "bin" / "java.exe" if java_home else "java"
    cmd = [
        str(java_bin), "-jar", str(cfr_jar),
        str(jar),
        "--outputdir", str(out_dir),
        "--caseinsensitivefs", "true",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0 and "This jar has no source" not in result.stderr:
            print(f"  ⚠ CFR exited {result.returncode}: {result.stderr[:200]}")
    except subprocess.TimeoutExpired:
        print("  ⚠ CFR timed out after 5 minutes — partial decompile may be available")
    except Exception as e:
        print(f"  ⚠ CFR failed: {e}")

    # ── Count recovered files ──
    java_files = sorted(out_dir.rglob("*.java"))
    print(f"  Recovered {len(java_files)} Java source files")

    if not java_files:
        print("  \033[93mNo Java sources recovered — stage-2 may be a native binary or heavily obfuscated.\033[0m")
        return

    # ── Quick inline scan ──
    print(f"\n  {'─'*50}")
    print(f"  Stage-2 Quick Triage Report")
    print(f"  {'─'*50}")

    findings: list = []
    behaviors: list = []
    for jf in java_files[:200]:  # Cap at 200 files for inline scan
        try:
            text = jf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(jf.relative_to(out_dir))

        # Quick string scan
        from re import finditer
        for m in STRING_ANY_LITERAL_RE.finditer(text):
            decoded = _unescape_java_literal(m.group(1)).strip()
            if len(decoded) < 4:
                continue
            low = decoded.lower()
            if URL_RE.match(decoded):
                findings.append(f"    url: {decoded[:100]}")
            elif COMMAND_LITERAL_RE.search(decoded):
                findings.append(f"    command: {decoded[:80]}")
            elif any(k in low for k in ("webhook", "discord", "token", "steal", "exfil", "c2", "beacon")):
                findings.append(f"    suspicious: {decoded[:80]}")

        # Quick behavior scan
        low_text = text.lower()
        if "processbuilder" in low_text:
            behaviors.append(f"    command_execution: {rel}")
        if any(k in low_text for k in ("httpurlconnection", "httpclient", "url.openconnection")):
            behaviors.append(f"    network_io: {rel}")
        if "secretkeyspec" in low_text:
            behaviors.append(f"    crypto: {rel}")

    if findings:
        print(f"  String findings ({len(findings)}):")
        for f in sorted(set(findings))[:30]:
            print(f"  {f}")
    if behaviors:
        print(f"\n  Behavior indicators ({len(behaviors)}):")
        for b in sorted(set(behaviors))[:20]:
            print(f"  {b}")

    print(f"\n  For full analysis, re-run:")
    print(f"    java_triage.py \"{out_dir}\" --no-auto-decrypt")
    print(f"  {'─'*50}")


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
    p.add_argument(
        "--decipher-codebase",
        action="store_true",
        help="Produce a deciphered copy with all XOR-obfuscated getBytes/toCharArray strings replaced by decoded literals, then scan both copies",
    )
    p.add_argument(
        "--decipher-only",
        metavar="PATH",
        help="Decipher a single .java file and write decoded strings to JSON (no scan)",
    )
    args = p.parse_args()

    root = resolve_target(args.target)
    initial_target = root
    show_progress = not args.no_progress
    pref_width = max(80, int(args.rich_width))
    stdout_encoding = (getattr(sys.stdout, "encoding", None) or "").lower()
    stderr_encoding = (getattr(sys.stderr, "encoding", None) or "").lower()
    stdout_unicode_ok = "utf" in stdout_encoding
    stderr_unicode_ok = "utf" in stderr_encoding or not stderr_encoding
    progress_console = Console(stderr=False, width=pref_width) if (RICH_AVAILABLE and stdout_unicode_ok) else None
    report_console = Console(width=pref_width) if (RICH_AVAILABLE and stdout_unicode_ok) else None
    rich_progress_mode = bool(RICH_AVAILABLE and progress_console is not None and show_progress)
    phase_logs = show_progress

    # Show banner immediately so users always see identity/header first.
    if rich_progress_mode:
        print_banner(progress_console, to_stderr=False)
    else:
        print_banner(None, to_stderr=True)
    scan_beginning_printed = False
    if show_progress:
        _print_scan_beginning(progress_console if rich_progress_mode else None)
        scan_beginning_printed = True

    progress(phase_logs, f"target resolved to: {_display_report_path(root, Path.cwd().resolve())}", progress_console)

    if not root.exists():
        print(f"error: target does not exist: {root}", file=sys.stderr)
        return 2
    if not root.is_dir() and root.suffix.lower() not in {".jar", ".zip"}:
        print(f"error: target is not a directory: {root}", file=sys.stderr)
        return 2

    # ── Decipher-only mode: single-file decode, no scan ──
    if args.decipher_only:
        return _run_decipher_only(args.decipher_only)

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

    if show_progress and not scan_beginning_printed:
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
    deciphered_root: Path | None = None
    decipher_stats: dict | None = None
    scan_targets: List[tuple[Path, str]] = [(scan_root, "")]
    eskid_root = _scan_root_has_eskid_profile(scan_root)
    if eskid_root:
        progress(
            phase_logs,
            "eSkid/protected_by_eskid profile detected; enabling guarded source scan + class constant-pool fallback",
            progress_console,
        )
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
        java_list = list(iter_java_files(target_root, include_pathological=True))
        class_list = list(iter_class_files(target_root))
        root_key = str(target_root.resolve())
        target_java_counts[root_key] = len(java_list)
        target_class_counts[root_key] = len(class_list)
        target_finding_counts[root_key] = 0
        fallback_class_list = [p for p in class_list if _is_fallback_class_path(p)]
        if java_list and fallback_class_list:
            target_scan_mode[root_key] = "java_guarded_plus_class_constant_pool"
        else:
            target_scan_mode[root_key] = "java" if java_list else ("class_constant_pool_fallback" if class_list else "none")
        for file_path in java_list:
            file_jobs.append((file_path, target_root, prefix))
        if fallback_class_list:
            for class_path in fallback_class_list:
                class_jobs.append((class_path, target_root, prefix))
        elif not java_list and class_list:
            for class_path in class_list:
                class_jobs.append((class_path, target_root, prefix))

    progress(phase_logs, "dumping post-prep strings and AES candidates", progress_console)
    string_dump_stats = produce_post_deobf_string_dump(scan_root, show_progress, progress_console)
    progress(phase_logs, "mapping invokedynamic bootstrap methods", progress_console)
    invokedynamic_bootstrap_stats = produce_invokedynamic_bootstrap_map(scan_root, show_progress, progress_console)

    # ── Produce and add deciphered copy if requested ──
    # Auto-decipher is ON by default when no explicit flags override it
    _auto_decipher = (
        (not args.decipher_codebase)
        and (not user_decrypt_mode)
        and (not args.no_auto_decrypt)
        and (not args.no_rescan_after_decrypt)
        and (not eskid_root)
    )
    _do_decipher = bool(args.decipher_codebase or _auto_decipher)
    if _do_decipher and not args.no_rescan_after_decrypt:
        deciphered_root, decipher_stats = produce_deciphered_copy(
            scan_root, show_progress, progress_console
        )
        if decipher_stats.get("files_changed", 0) > 0:
            progress(
                phase_logs,
                f"deciphered copy ready: {decipher_stats['strings_replaced']} strings replaced in "
                f"{decipher_stats['files_changed']} files -> {deciphered_root}",
                progress_console,
            )
            # Add as scan target — use resolved path for consistent keying
            d_java = list(iter_java_files(deciphered_root, include_pathological=True))
            d_class = list(iter_class_files(deciphered_root))
            d_key = str(deciphered_root.resolve())
            target_java_counts[d_key] = len(d_java)
            target_class_counts[d_key] = len(d_class)
            target_finding_counts[d_key] = 0
            d_mode = "java" if d_java else ("class_constant_pool_fallback" if d_class else "none")
            target_scan_mode[d_key] = d_mode
            for file_path in d_java:
                file_jobs.append((file_path, deciphered_root, "deciphered"))
            if not d_java and d_class:
                for class_path in d_class:
                    class_jobs.append((class_path, deciphered_root, "deciphered"))
            scan_targets.append((deciphered_root, "deciphered"))
        else:
            progress(
                phase_logs,
                "decipher pass found no XOR-obfuscated strings to replace; skipping deciphered copy",
                progress_console,
            )

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
    behavior_findings.extend(detect_decoded_finding_behaviors(all_findings))
    mc_modules = detect_minecraft_modules(scan_root)

    progress(show_progress, "Scan Complete; Finalizing Findings", progress_console)

    for target_root, prefix in scan_targets:
        behavior_findings.extend(_apply_prefix_behaviors(discover_structural_behaviors(target_root), prefix))
        behavior_findings.extend(_apply_prefix_behaviors(detect_token_source_sink_behaviors(target_root), prefix))
        behavior_findings.extend(_apply_prefix_behaviors(detect_reachability_proof_chains(target_root), prefix))
        behavior_findings.extend(_apply_prefix_behaviors(detect_two_payload_exfil_architecture(target_root), prefix))
        behavior_findings.extend(_apply_prefix_behaviors(detect_persistence_relaunch_chains(target_root), prefix))
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

    # ── Post-processing: when Minecraft hack modules are detected, suppress
    #     benign identity-access findings that are expected in any client mod
    #     (session/username/UUID/token reads are normal mod behavior, not malware).
    if mc_modules.get("detected"):
        _BENIGN_IDENTITY_BEHAVIORS = {
            "minecraft_username_access",
            "minecraft_uuid_access",
            "minecraft_session_access",
            "minecraft_gameprofile_access",
            "minecraft_access_token_access",
            "minecraft_session_id_access",
            "token_field_getter_passthrough",
            "capability_token_access",
            "minecraft_session_file_access",
        }
        _BENIGN_MODULE_CONTEXT_BEHAVIORS = {
            # These behaviors look suspicious in isolation, but in the context of
            # a client mod (especially one with account managers, API integrations,
            # analytics), they are expected functionality.
            "possible_minecraft_identity_exfiltration",
            "proof_token_source_to_network_sink",
            "dataflow_token_to_network_sink",
            "possible_access_token_exfiltration",
            "assessment_needs_review_access_token_read_without_destination",
            "assessment_suspicious_possible_credential_exfiltration",
        }
        before_count = len(behavior_findings)
        behavior_findings = [
            b for b in behavior_findings
            if b.behavior not in _BENIGN_IDENTITY_BEHAVIORS
            and b.behavior not in _BENIGN_MODULE_CONTEXT_BEHAVIORS
        ]
        progress(
            show_progress,
            f"suppressed {before_count - len(behavior_findings)} benign identity-access findings "
            f"(detected {mc_modules['module_count']} hack modules — these are expected in a client mod)",
            progress_console,
        )

    # Initialize runtime C2 state before any downstream classification uses it.
    runtime_c2 = {"attempted": False, "resolved": False}
    behavior_names = {b.behavior for b in behavior_findings}
    if (
        runtime_c2.get("resolved")
        and runtime_c2.get("exfil_endpoint")
        and runtime_c2.get("payload_endpoint")
        and behavior_names & {"two_payload_exfil_architecture", "multi_path_exfil_breakdown", "blockchain_dns_c2_resolver"}
    ):
        behavior_findings.append(
            BehaviorFinding(
                file=".",
                line=1,
                behavior="proof_staged_blockchain_c2_exfil_chain",
                evidence=(
                    f"Resolved blockchain-backed C2 domain {runtime_c2.get('c2_base_url')} and assembled staged "
                    f"endpoints ({runtime_c2.get('exfil_endpoint')} + {runtime_c2.get('payload_endpoint')}); "
                    "paired with tiered exfiltration behavior this is a confirmed malware delivery chain."
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
    url_assembly: dict = {"c2_domain": "", "assembled_urls": [], "endpoints": []}
    infra_probe: dict = {"probed": False, "results": []}
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
        "aes_payload_decrypted": False,
        "aes_payload_note": "AES decryption requires the full ciphertext bytes from the C2 download endpoint. "
                           "If the download succeeded, the AES key/IV must be extracted from decoded strings "
                           "and passed to the offline aes_cbc_nopadding_decrypt() helper.",
    }
    if not args.no_network:
        progress(show_progress, "Resolving Runtime C2 From On-Chain Config", progress_console)
        runtime_c2 = resolve_runtime_c2(all_findings)
        if runtime_c2.get("resolved"):
            progress(show_progress, f"Runtime C2 Resolved: {runtime_c2.get('c2_base_url')}", progress_console)
        else:
            progress(show_progress, f"Runtime C2 Unresolved: {runtime_c2.get('error', 'unknown error')}", progress_console)

    # ── Assemble full C2 URLs from resolved domain + decoded path fragments ──
    url_assembly = assemble_c2_urls(all_findings, runtime_c2)
    if url_assembly.get("assembled_urls"):
        progress(
            show_progress,
            f"C2 URL Assembly: {len(url_assembly['assembled_urls'])} endpoints assembled for {url_assembly.get('c2_domain', '?')}",
            progress_console,
        )

    # ── Stage-2 download is DEFERRED to the interactive prompt ──
    # --analyze-stage2 resolves the payload URL but does NOT auto-download.
    # The user is prompted at the end: "Do you want to download + decrypt the stage-2 payload?"
    # This avoids silently downloading malware payloads without user consent.
    if args.no_network and args.analyze_stage2:
        stage2_analysis["error"] = "stage2 analysis requires network access; rerun without --no-network"
    stage2_analysis["payload_url_resolved"] = runtime_c2.get("payload_endpoint", "")

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
                summary["xor_decrypted_count"] = max(
                    int(deobf_stats.get("stringdecrypt_xor_replaced", 0)),
                    sum(1 for f in all_findings if "key_prefix_xor" in (f.note or "") or "full_xor" in (f.note or "")),
                )
                summary["decrypted_string_count"] = int(
                    deobf_stats.get("stringdecrypt_other_replaced", 0)
                ) + int(deobf_stats.get("load_replaced", 0))
                summary["reconstructed_strings"] = sum(
                    1 for f in all_findings if "key_prefix_xor_stringbuilder" in (f.note or "")
                )
                if decipher_stats:
                    summary["xor_decrypted_count"] = max(
                        summary["xor_decrypted_count"],
                        int(decipher_stats.get("strings_replaced", 0)),
                    )
                build_prog.advance(build_task)

            blockchain = extract_blockchain_indicators(all_findings)
            cwd_report = Path.cwd().resolve()
            payload = {
                "root": _display_report_path(scan_root, cwd_report),
                "scan_roots": [_display_report_path(x[0], cwd_report) for x in scan_targets],
                "scan_diagnostics": {
                    _display_report_path(tr, cwd_report): {
                        "java_files": target_java_counts.get(str(tr.resolve()), 0),
                        "class_files": target_class_counts.get(str(tr.resolve()), 0),
                        "finding_count": target_finding_counts.get(str(tr.resolve()), 0),
                        "scan_mode": target_scan_mode.get(str(tr.resolve()), "unknown"),
                    }
                    for tr, _prefix in scan_targets
                },
                "target_metadata": target_metadata,
                "scan_mode": "post_decryption_only" if decrypt_mode else "standard",
                "deobfuscation": deobf_stats if deobf_stats else {},
                "decipher": decipher_stats if decipher_stats else {},
                "string_dump": string_dump_stats,
                "invokedynamic_bootstrap": invokedynamic_bootstrap_stats,
                "summary": summary,
                "assessment_summary": summarize_assessments(behavior_findings),
                "verdict_tiers": summarize_verdict_tiers(behavior_findings),
                "contradiction_notes": build_contradiction_notes(behavior_findings),
                "reconstructed_strings": [
                    {
                        "decoded": f.decoded,
                        "file": f.file,
                        "line": f.line,
                        "confidence": "high" if f.category != "string" else "medium",
                        "category": f.category,
                    }
                    for f in all_findings
                    if "key_prefix_xor_stringbuilder" in (f.note or "")
                ],
                "runtime_c2": runtime_c2,
                "url_assembly": url_assembly,
                "infra_probe": infra_probe,
                "ratter_scanner": ratter_scanner,
                "jlab_static_scan": jlab_static_scan,
                "network_endpoint_assessment": network_endpoint_assessment,
                "variant_detections": variant_detections,
                "raw_string_detections": raw_string_detections,
                "heuristic_detections": heuristic_detections,
                "minecraft_modules": mc_modules,
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
                minecraft_modules=mc_modules,
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
            summary["xor_decrypted_count"] = max(
                summary["xor_decrypted_count"],
                int(deobf_stats.get("stringdecrypt_xor_replaced", 0)),
            )
            summary["decrypted_string_count"] = max(
                summary["decrypted_string_count"],
                int(deobf_stats.get("stringdecrypt_other_replaced", 0))
                + int(deobf_stats.get("load_replaced", 0)),
            )
        if decipher_stats:
            summary["xor_decrypted_count"] = max(
                summary["xor_decrypted_count"],
                int(decipher_stats.get("strings_replaced", 0)),
            )

        blockchain = extract_blockchain_indicators(all_findings)
        cwd_report = Path.cwd().resolve()
        payload = {
            "root": _display_report_path(scan_root, cwd_report),
            "scan_roots": [_display_report_path(x[0], cwd_report) for x in scan_targets],
            "scan_diagnostics": {
                _display_report_path(tr, cwd_report): {
                    "java_files": target_java_counts.get(str(tr.resolve()), 0),
                    "class_files": target_class_counts.get(str(tr.resolve()), 0),
                    "finding_count": target_finding_counts.get(str(tr.resolve()), 0),
                    "scan_mode": target_scan_mode.get(str(tr.resolve()), "unknown"),
                }
                for tr, _prefix in scan_targets
            },
            "target_metadata": target_metadata,
            "scan_mode": "post_decryption_only" if decrypt_mode else "standard",
            "deobfuscation": deobf_stats if deobf_stats else {},
            "decipher": decipher_stats if decipher_stats else {},
            "string_dump": string_dump_stats,
            "invokedynamic_bootstrap": invokedynamic_bootstrap_stats,
            "summary": summary,
            "assessment_summary": summarize_assessments(behavior_findings),
            "verdict_tiers": summarize_verdict_tiers(behavior_findings),
            "contradiction_notes": build_contradiction_notes(behavior_findings),
            "reconstructed_strings": [
                {
                    "decoded": f.decoded,
                    "file": f.file,
                    "line": f.line,
                    "confidence": "high" if f.category != "string" else "medium",
                    "category": f.category,
                }
                for f in all_findings
                if "key_prefix_xor_stringbuilder" in (f.note or "")
            ],
            "runtime_c2": runtime_c2,
            "ratter_scanner": ratter_scanner,
            "jlab_static_scan": jlab_static_scan,
            "network_endpoint_assessment": network_endpoint_assessment,
            "variant_detections": variant_detections,
            "raw_string_detections": raw_string_detections,
            "heuristic_detections": heuristic_detections,
            "minecraft_modules": mc_modules,
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
            minecraft_modules=mc_modules,
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
            url_assembly,
            infra_probe,
            minecraft_modules=mc_modules,
        )
    else:
        try:
            print(text_output_with_banner)
        except UnicodeEncodeError:
            safe_text = text_output_with_banner.encode(
                getattr(sys.stdout, "encoding", None) or "utf-8",
                errors="replace",
            ).decode(getattr(sys.stdout, "encoding", None) or "utf-8", errors="replace")
            print(safe_text)
    progress(show_progress, "done", progress_console)

    # ── Interactive follow-up prompt ──
    _show_interactive_prompt(url_assembly, runtime_c2, stage2_analysis, all_findings)

    try:
        input("\nPress Enter to quit...")
    except EOFError:
        pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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




def progress(enabled: bool, message: str, console=None) -> None:
    if not enabled:
        return
    if console is not None:
        console.print(message)
    else:
        print(message)


def _friendly_network_error(exc: Exception) -> str:
    if isinstance(exc, error.HTTPError):
        return f"HTTP {exc.code}: {exc.reason}"
    if isinstance(exc, error.URLError):
        return f"Network error: {exc.reason}"
    return str(exc)


def _read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _build_source_index(root: Path) -> dict:
    java_files = list(root.rglob("*.java"))
    rel_paths = [str(p.relative_to(root)).replace("\\", "/") for p in java_files]
    texts = {rel: _read_text_safe(root / rel) for rel in rel_paths}
    simple_to_rel: dict[str, List[str]] = {}
    for rel in rel_paths:
        simple_to_rel.setdefault(Path(rel).stem, []).append(rel)
    return {"rel_paths": rel_paths, "texts": texts, "simple_to_rel": simple_to_rel}


def find_line(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1
__all__ = [name for name in globals() if not name.startswith("__")]

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
from .decoding import *
from .minecraft import _trace_minecraft_data_flow, detect_minecraft_modules

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

    # Only confident, unambiguous obfuscator/packer signatures — never bare
    # substrings (e.g. "r8", "stringer") which appear inside decompiled names,
    # render helpers, or comments and cause false positives.
    _OBFUSCATOR_MARKER_PATTERNS = [
        (r"\ballatorixdemo\b", "Allatori"),
        (r"\bzelixklassmaster\b", "Zelix KlassMaster"),
        (r"\bdasho\b", "DashO"),
        (r"\byguard\b", "yGuard"),
        (r"\bproguard\b", "ProGuard"),
        (r"\bstringer\b", "Stringer"),
        (r"-libraryjars", "ProGuard config"),
        (r"-keepattributes", "ProGuard config"),
    ]
    obf_markers = [name for pat, name in _OBFUSCATOR_MARKER_PATTERNS if re.search(pat, low)]
    if obf_markers:
        out.append(
            BehaviorFinding(
                file=rel,
                line=1,
                behavior="obfuscator_or_packer_marker",
                evidence="Contains explicit obfuscator/packer marker strings: " + ", ".join(obf_markers),
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
        or "method_5477()" in text
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
    # Only real method-dispatch arrays (Method/MethodHandle/Class) that are then
    # invoked reflectively count.  "new Object[]" / "new String[]" are ordinary
    # varargs (String.format, printf) and "index" is a common loop counter.
    if (
        ("new Method[" in text or "new MethodHandle[" in text or "MethodHandle[]" in text or "new Class[]" in text)
        and (".invoke(" in text or ".getMethod(" in text or ".getDeclaredMethod(" in text)
    ):
        out.append(
            BehaviorFinding(
                file=rel,
                line=find_line(text, "new Method["),
                behavior="obf_array_indirect_dispatch_token_access",
                evidence="Uses a Method/MethodHandle/Class dispatch array invoked reflectively to obscure call targets",
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
                # Yarn 1.21+ obfuscated player-position accessors (Entity.getX/getY/getZ)
                "method_23317()", "method_23318()", "method_23321()",
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

    # ── Anti-forensics / self-tamper primitives ──
    if not is_vendor_lib:
        # NTFS USN journal flood: mass metadata churn on temp files via a worker
        # pool (setLastModifiedTime + dos:archive toggles) to bury forensic
        # evidence of file activity (e.g. self-replacing a cheat/mod JAR).
        if (
            "Files.setLastModifiedTime(" in text
            and "dos:archive" in text
            and "Files.createTempFile(" in text
            and any(p in text for p in ["newWorkStealingPool", "newFixedThreadPool", "newCachedThreadPool"])
            and "awaitTermination(" in text
        ):
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "Files.setLastModifiedTime("),
                    behavior="usn_journal_flood",
                    evidence="Floods the NTFS USN journal by repeatedly rewriting timestamps and dos:archive attributes on temp files — anti-forensics to hide file modifications",
                )
            )

        # File timestamp forgery: restoring/setting lastModified on a file
        # derived from the running JAR path (covers up self-replacement / drops).
        if "setLastModified(" in text and any(p in text for p in ["getCodeSource", "getProtectionDomain", "getLocation"]):
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "setLastModified("),
                    behavior="file_timestamp_forgery",
                    evidence="Restores/sets the lastModified timestamp of a file derived from the running JAR path — timestamp forgery to hide file modification",
                )
            )

        # Self-overwrite downloader: HTTP download written back over the
        # currently-running JAR path (self-replacement to cover the mod's tracks).
        if (
            ("HttpURLConnection" in text or "URLConnection" in text or "openConnection(" in text)
            and ("getInputStream(" in text or "openStream(" in text)
            and "FileOutputStream(" in text
            and any(p in text for p in ["getCodeSource", "getProtectionDomain", "getCurrentJarPath", "getCurrentJar"])
        ):
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, "FileOutputStream("),
                    behavior="self_jar_overwrite_downloader",
                    evidence="Downloads remote bytes and writes them over the running JAR path (getCodeSource/getProtectionDomain) — self-replacement/self-overwrite evasion",
                )
            )

        # In-memory forensic wipe: clearing module/setting identity fields so a
        # captured memory dump no longer shows the client's fingerprints.
        if ".setName(null)" in text and ".setDescription(null)" in text and ".getSettings().clear()" in text:
            out.append(
                BehaviorFinding(
                    file=rel,
                    line=find_line(text, ".setName(null)"),
                    behavior="in_memory_forensic_wipe",
                    evidence="Wipes module/setting name/description fields and clears settings in memory — reduces forensic residue in memory dumps",
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
        has_mc_token = any(x in low for x in ["method_1674", "getaccesstoken", "func_148254_d", "field_1983", "field_148258_c"])
        has_mc_identity = any(x in low for x in ["method_1676", "method_1673", "method_44717"])
        # "socket(" (a constructor call) instead of bare "socket" avoids import noise.
        has_net_sink = any(
            x in low
            for x in ["httpurlconnection", "httpclient", "okhttpclient", "getoutputstream", "url.openconnection", "socket("]
        )
        if has_mc_token and has_net_sink:
            add("MC access token reference alongside network sink — verify exfiltration", 25)
        elif has_mc_identity and has_net_sink:
            add("MC username/UUID referenced alongside network activity — verify destination", 15)
        if ("getmethod(" in low or "getdeclaredmethod(" in low) and ".invoke(" in low and (
            has_mc_token or "method_1548" in low
        ) and has_net_sink:
            add("MC session theft via reflection", 30)
        if "processbuilder" in low:
            add("ProcessBuilder usage (command execution)", 10)
        if ("httpurlconnection" in low or "httpclient" in low or "urlconnection" in low) and (
            "readallbytes(" in low or "tobytearray(" in low
        ):
            add("HTTP download to byte array", 10)
        if (not is_vendor_lib) and any(
            x in low for x in ["base64.getdecoder", "base64.getencoder", "getdecoder().decode", "getencoder().encodetostring"]
        ):
            add("Base64 encoding/decoding (actual decoder/encoder usage)", 10)
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
        # \\bncrypt requires a word boundary, so "encryptedstring" does NOT match
        # (the substring "ncrypt" inside a longer identifier never matches \\bncrypt).
        if re.search(r"\\bncrypt", low) or any(x in low for x in ["cryptunprotectdata", "cryptprotectdata", "crypt32util", "dpapi"]):
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
                if any(k in low for k in ("token", "authorization", "api_key", "bearer ")):
                    category = "credential_or_identity_field"
                elif any(k in low for k in ("webhook", "discord", "telegram", "api.telegram.org", "pastebin", "ngrok")):
                    category = "comms_indicator"
                else:
                    category = "string"
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
        "usn_journal_flood",
        "file_timestamp_forgery",
        "self_jar_overwrite_downloader",
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
        "in_memory_forensic_wipe",
        "dataflow_coordinates_to_network_sink",
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
    if any(
        ("self-overwrite" in (getattr(b, "behavior", ""))) or b.behavior in {"self_jar_overwrite_downloader"}
        for b in behaviors
    ):
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


# File, class, and archive scan plumbing shared by the CLI.
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
        or low == "vineflower.jar"
        or low.startswith("vineflower-")
        or low.startswith("forgeflower-")
        or low.startswith("quiltflower-")
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


def _normalize_decompiler_name(name: str | None) -> str:
    low = (name or "auto").strip().lower()
    if low in {"auto", "default", ""}:
        return "auto"
    if low == "cfr":
        return "cfr"
    if low in {"vineflower", "fernflower", "forgeflower", "quiltflower"}:
        return "vineflower"
    return "auto"


def _find_vineflower_jar(cwd: Path) -> Path | None:
    direct_names = ("vineflower.jar", "fernflower.jar")
    for name in direct_names:
        direct = cwd / name
        if direct.is_file():
            return direct
    candidates = sorted(
        [
            p for p in cwd.glob("*.jar")
            if p.is_file() and any(tok in p.name.lower() for tok in ("vineflower", "fernflower", "forgeflower", "quiltflower"))
        ],
        key=lambda p: p.name.lower(),
    )
    return candidates[0] if candidates else None


def _decompiler_from_path(path: Path) -> dict:
    low = path.name.lower()
    if "vineflower" in low or "fernflower" in low or "forgeflower" in low or "quiltflower" in low:
        return {"kind": "vineflower", "label": "Vineflower", "path": path}
    return {"kind": "cfr", "label": "CFR", "path": path}


def _find_decompiler_jar(cwd: Path, preferred: str | None = "auto") -> dict | None:
    preferred = _normalize_decompiler_name(preferred)
    if preferred == "cfr":
        p = _find_cfr_jar(cwd)
        return _decompiler_from_path(p) if p else None
    if preferred == "vineflower":
        p = _find_vineflower_jar(cwd)
        return _decompiler_from_path(p) if p else None

    for finder in (_find_cfr_jar, _find_vineflower_jar):
        p = finder(cwd)
        if p:
            return _decompiler_from_path(p)
    return None


def _latest_vineflower_download() -> tuple[str, str]:
    api_url = "https://api.github.com/repos/Vineflower/vineflower/releases/latest"
    try:
        req = request.Request(api_url, headers={"User-Agent": "java-triage/1.0"})
        with request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        for asset in payload.get("assets", []) or []:
            name = str(asset.get("name", ""))
            low = name.lower()
            if low.endswith(".jar") and "slim" not in low and "sources" not in low and "javadoc" not in low:
                url = str(asset.get("browser_download_url", ""))
                if url:
                    return name, url
    except Exception:
        pass
    return "vineflower-1.12.0.jar", "https://github.com/Vineflower/vineflower/releases/download/1.12.0/vineflower-1.12.0.jar"


def _download_file(url: str, dest: Path, show_progress: bool, progress_console=None) -> tuple[bool, str]:
    tmp = dest.with_suffix(dest.suffix + ".download")
    try:
        req = request.Request(url, headers={"User-Agent": "java-triage/1.0"})
        with request.urlopen(req, timeout=60) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            got = 0
            with tmp.open("wb") as fh:
                while True:
                    chunk = resp.read(1024 * 256)
                    if not chunk:
                        break
                    fh.write(chunk)
                    got += len(chunk)
                    if total and show_progress and got == len(chunk):
                        progress(show_progress, f"downloading {dest.name} ({_human_size(total)})", progress_console)
        tmp.replace(dest)
        return True, ""
    except Exception as exc:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        return False, _friendly_network_error(exc)


def _download_decompiler_jar(
    cwd: Path,
    preferred: str | None = "auto",
    show_progress: bool = True,
    progress_console=None,
) -> dict | None:
    preferred = _normalize_decompiler_name(preferred)
    if preferred == "auto":
        preferred = "cfr"
    if preferred == "vineflower":
        filename, url = _latest_vineflower_download()
        label = "Vineflower"
    else:
        filename = "cfr-0.152.jar"
        url = "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
        label = "CFR"
    dest = cwd / filename
    if dest.is_file():
        return _decompiler_from_path(dest)
    progress(show_progress, f"{label} decompiler missing; downloading {filename}", progress_console)
    ok, err = _download_file(url, dest, show_progress, progress_console)
    if not ok:
        progress(show_progress, f"{label} download failed: {err}", progress_console)
        return None
    progress(show_progress, f"{label} ready: {dest.name}", progress_console)
    return _decompiler_from_path(dest)


def _decompiler_command(decompiler: dict | Path, jar_path: Path, out_dir: Path) -> list[str]:
    spec = _decompiler_from_path(decompiler) if isinstance(decompiler, Path) else decompiler
    tool_path = Path(spec["path"])
    if spec.get("kind") == "vineflower":
        return ["java", "-jar", str(tool_path), str(jar_path), str(out_dir)]
    return [
        "java", "-jar", str(tool_path), str(jar_path),
        "--outputdir", str(out_dir),
        "--renameillegalidents", "true",
        "--renamedupmembers", "true",
    ]


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
    decompiler: dict | Path,
    show_progress: bool,
    progress_console=None,
) -> Path:
    selected = selected.resolve()
    # Deferred import: these prompt/report helpers live in reporting.py, which
    # itself imports this module — resolve at call time to avoid an import cycle.
    from .reporting import _prompt_reuse_decompiled_dir, _display_report_path
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

    spec = _decompiler_from_path(decompiler) if isinstance(decompiler, Path) else decompiler
    cp = _run_subprocess_with_progress(
        _decompiler_command(spec, decompile_jar, out_dir),
        f"{spec.get('label', 'Decompiler')} decompiling {decompile_jar.name}",
        show_progress,
        progress_console,
    )
    if cp.returncode != 0:
        err = (cp.stderr or cp.stdout or "").strip()
        print(f"error: {spec.get('label', 'Decompiler')} decompilation failed for {decompile_jar.name}", file=sys.stderr)
        if err:
            print(err, file=sys.stderr)
        return cwd

    extracted_classes = _extract_class_files_from_jar(fallback_class_jar, out_dir)
    if extracted_classes:
        progress(show_progress, f"extracted {extracted_classes} class file(s) for constant-pool fallback", progress_console)
    if not any(out_dir.rglob("*.java")) and extracted_classes == 0:
        print(f"error: {spec.get('label', 'Decompiler')} did not produce Java source or fallback classes in {out_dir}", file=sys.stderr)
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
    decompiler: dict | Path,
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
    spec = _decompiler_from_path(decompiler) if isinstance(decompiler, Path) else decompiler
    cp = _run_subprocess_with_progress(
        _decompiler_command(spec, work_jar, out_dir),
        f"{spec.get('label', 'Decompiler')} decompiling {work_jar.name}",
        show_progress,
        progress_console,
    )
    if cp.returncode != 0:
        err = (cp.stderr or cp.stdout or "").strip()
        label = spec.get("label", "Decompiler")
        return False, f"{label} failed for {work_jar.name}: {err}" if err else f"{label} failed for {work_jar.name}"
    extracted_classes = _extract_class_files_from_jar(fallback_class_jar, out_dir)
    if not any(out_dir.rglob("*.java")) and extracted_classes == 0:
        return False, f"{spec.get('label', 'Decompiler')} produced no Java sources or fallback classes for {work_jar.name}"
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
    # Deferred import: _triage_ui_width lives in reporting.py (which imports this
    # module); resolve at call time to avoid an import cycle.
    from .reporting import _triage_ui_width
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
    decompiler = _find_decompiler_jar(Path.cwd().resolve())
    if decompiler is None:
        progress(show_progress, "nested dropped-jar scan skipped: no decompiler jar found in cwd", progress_console)
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

        ok, err = _decompile_jar_with_cfr(jar_path, preferred, decompiler, show_progress, progress_console)
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
    decompiler = _find_decompiler_jar(Path.cwd().resolve())
    if decompiler is None:
        progress(show_progress, "embedded archive scan skipped: no decompiler jar found in cwd", progress_console)
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

            ok, err = _decompile_jar_with_cfr(jar_out, out_dir, decompiler, show_progress, progress_console)
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
__all__ = [name for name in globals() if not name.startswith("__")]

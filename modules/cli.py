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

from .models import *
from .decoding import *
from .minecraft import *
from .behaviors import *
from .reporting import *

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

    Creates a temp decompile directory, runs the configured decompiler, then scans the result.
    Skips auto-decrypt/decipher since stage-2 payloads are already raw.
    """
    jar = Path(jar_path)
    if not jar.is_file():
        raise FileNotFoundError(f"JAR not found: {jar_path}")

    decompiler = _find_decompiler_jar(Path.cwd().resolve())
    if decompiler is None:
        decompiler = _download_decompiler_jar(Path.cwd().resolve(), "auto", True, None)
    if decompiler is None:
        raise FileNotFoundError("No Java decompiler found. Place CFR or Vineflower next to java_triage.py.")

    # ── Create output directory ──
    out_dir = jar.parent / f"{jar.stem}_stage2_triage"
    if out_dir.exists():
        idx = 2
        while (jar.parent / f"{jar.stem}_stage2_triage_{idx}").exists():
            idx += 1
        out_dir = jar.parent / f"{jar.stem}_stage2_triage_{idx}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Decompiling with {decompiler.get('label', 'Decompiler')} to: {out_dir}")
    print(f"  This may take a moment for large JARs...")

    # ── Run decompiler ──
    java_home = os.environ.get("JAVA_HOME", "")
    java_bin = Path(java_home) / "bin" / "java.exe" if java_home else "java"
    cmd = _decompiler_command(decompiler, jar, out_dir)
    cmd[0] = str(java_bin)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0 and "This jar has no source" not in result.stderr:
            print(f"  Decompiler exited {result.returncode}: {result.stderr[:200]}")
    except subprocess.TimeoutExpired:
        print("  Decompiler timed out after 5 minutes; partial decompile may be available")
    except Exception as e:
        print(f"  Decompiler failed: {e}")

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
        "--decompiler",
        choices=("auto", "cfr", "vineflower", "fernflower"),
        default="auto",
        help="Decompiler for JAR/ZIP targets (default: auto; FernFlower is handled via Vineflower)",
    )
    p.add_argument(
        "--no-decompiler-download",
        action="store_true",
        help="Do not auto-download CFR/Vineflower when no local decompiler jar is found",
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

    prepared_root = maybe_prepare_cwd_jar_scan_root(
        root,
        show_progress,
        progress_console,
        preferred_decompiler=args.decompiler,
        allow_decompiler_download=not args.no_decompiler_download,
    )
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

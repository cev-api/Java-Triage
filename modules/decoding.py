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




# CLI-facing decoding and string scan helpers.
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
__all__ = [name for name in globals() if not name.startswith("__")]

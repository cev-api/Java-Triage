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
from .behaviors import *

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
        _cat_prio2 = {"url": 1, "credential_or_identity_field": 2, "dynamic_execution": 3, "reconstructed_string": 4, "cryptocurrency_address": 5, "discord_indicator": 6, "rpc_template": 7, "path": 8, "http_header": 9, "comms_indicator": 10, "sensitive_game_data": 11, "hex_or_contract": 12, "string": 13, "base64_blob": 14, "hex_decoded_binary": 15, "base64_decoded_binary": 16}
        for f in sorted(findings, key=lambda x: (_cat_prio2.get(x.category, 99), x.category, (x.decoded or "").lower())):
            if f.category == "reconstructed_string":
                continue
            note = f" [{f.note}]" if f.note else ""
            out.append(f"[{f.category}] {f.file}:{f.line} ({f.function}) -> {f.decoded}{note}")

    aes_keys = [b for b in behaviors if str(b.behavior) == "aes_key_recovered"]
    if aes_keys:
        out.append("")
        out.append("== AES Keys Recovered ==")
        seen_aes = set()
        for b in aes_keys:
            key = (b.file, b.line, b.evidence)
            if key in seen_aes:
                continue
            seen_aes.add(key)
            out.append(f"- {b.file}:{b.line} -> {b.evidence}")

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
            decoy_note = " [DECOY / anti-analysis marker]" if runtime_c2.get("onchain_decoy") else ""
            out.append(f"Resolved: yes via {runtime_c2.get('rpc_used')}")
            out.append(f"On-chain C2 base URL: {runtime_c2.get('c2_base_url')}{decoy_note}")
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
    out.append(f"AES decrypted strings: {summary.get('aes_decrypted_count', 0)}")
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
    _html_cat_prio = {"url": 1, "credential_or_identity_field": 2, "dynamic_execution": 3, "reconstructed_string": 4, "cryptocurrency_address": 5, "discord_indicator": 6, "rpc_template": 7, "path": 8, "http_header": 9, "comms_indicator": 10, "sensitive_game_data": 11, "hex_or_contract": 12, "string": 13, "base64_blob": 14, "hex_decoded_binary": 15, "base64_decoded_binary": 16}
    _html_sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def line_context_cell(row: dict, label: Any = None) -> str:
        """Render a compact line label for secondary indicator tables."""
        return _h(row.get("line", "") if label is None else label)

    rows_find = []
    for r in sorted(findings[:2000], key=lambda x: (_html_cat_prio.get(str(x.get("category","")), 99), str(x.get("category","")), (str(x.get("decoded","")) or "").lower())):
        idx = len(rows_find)
        cat = str(r.get("category", ""))
        if cat == "reconstructed_string":
            continue
        row_class = "row-high" if cat_class(cat) == "cat-danger" else ""
        decoded_class = "decoded-high" if cat_class(cat) == "cat-danger" else ""
        hidden_attr = " style='display:none' data-findings-extra='1'" if idx >= findings_limit else ""
        context_id = f"finding-context-{idx}"
        context = str(r.get("context", "") or "")
        toggle = (
            f"<button type='button' class='context-toggle' data-context-target='{context_id}' "
            f"aria-expanded='false'>▶ {_h(r.get('line', ''))}</button>"
            if context else _h(r.get("line", ""))
        )
        rows_find.append(
            f"<tr class='{row_class}'{hidden_attr}>"
            f"<td class='tight'>{_h(r.get('file', ''))}</td>"
            f"<td class='tight'>{toggle}</td>"
            f"<td class='func-col'>{_h(r.get('function', ''))}</td>"
            f"<td class='cat-col'><span class='cat-pill {cat_class(cat)}'>{_h(cat)}</span></td>"
            f"<td class='{decoded_class}'>{_h(r.get('decoded', ''))}</td>"
            "</tr>"
            + (
                f"<tr id='{context_id}' class='source-context-row' style='display:none'>"
                f"<td colspan='5'><pre>{_h(context)}</pre></td></tr>"
                if context else ""
            )
        )
    rows_aes = []
    seen_aes = set()
    for aes_idx, r in enumerate(behaviors):
        if str(r.get("behavior", "")) != "aes_key_recovered":
            continue
        key = (r.get("file", ""), r.get("line", ""), r.get("evidence", ""))
        if key in seen_aes:
            continue
        seen_aes.add(key)
        context = str(r.get("context", "") or "")
        context_id = f"aes-context-{aes_idx}"
        toggle = (
            f"<button type='button' class='context-toggle' data-context-target='{context_id}' aria-expanded='false'>▶ {_h(r.get('line', ''))}</button>"
            if context else _h(r.get("line", ""))
        )
        rows_aes.append(
            f"<tr><td class='location-col'>{_h(r.get('file', ''))}:{toggle}</td>"
            f"<td class='key-col'>{_h(r.get('evidence', ''))}</td></tr>"
            + (
                f"<tr id='{context_id}' class='source-context-row' style='display:none'><td colspan='2'><pre>{_h(context)}</pre></td></tr>"
                if context else ""
            )
        )
    rows_reconstructed = []
    for recon_idx, r in enumerate((payload.get("reconstructed_strings", []) or [])[:1000]):
        category = str(r.get("category", "reconstructed_string") or "reconstructed_string")
        note = str(r.get("note", "") or "")
        context = str(r.get("context", "") or "")
        context_id = f"reconstructed-context-{recon_idx}"
        toggle = (
            f"<button type='button' class='context-toggle' data-context-target='{context_id}' aria-expanded='false'>▶ {_h(r.get('line', ''))}</button>"
            if context else _h(r.get("line", ""))
        )
        method = note.replace("source=string_reconstruction ", "").replace("source=", "")
        rows_reconstructed.append(
            f"<tr><td class='tight'>{_h(r.get('file', ''))}</td>"
            f"<td class='tight'>{toggle}</td>"
            f"<td class='func-col'>{_h(r.get('function', ''))}</td>"
            f"<td class='decoded-high'>{_h(r.get('decoded', ''))}</td>"
            f"<td class='method-col'>{_h(category)}<br><span class='table-empty'>{_h(method)}</span></td></tr>"
            + (
                f"<tr id='{context_id}' class='source-context-row' style='display:none'><td colspan='5'><pre>{_h(context)}</pre></td></tr>"
                if context else ""
            )
        )
    rows_beh = []
    for r in sorted(behaviors[:2000], key=lambda x: (_html_sev_order.get(str(x.get("severity","info")).lower(), 9), str(x.get("behavior","")), str(x.get("file","")), int(x.get("line",0) or 0))):
        idx = len(rows_beh)
        sev = str(r.get("severity", "info") or "info").strip().lower()
        row_class = f"row-{sev}" if sev in {"critical", "high", "medium", "low", "info"} else ""
        evidence_class = "behavior-evidence-high" if sev in {"critical", "high"} else ("behavior-evidence-medium" if sev == "medium" else "")
        hidden_attr = " style='display:none' data-behavior-extra='1'" if idx >= behavior_limit else ""
        context_id = f"behavior-context-{idx}"
        context = str(r.get("context", "") or "")
        toggle = (
            f"<button type='button' class='context-toggle' data-context-target='{context_id}' "
            f"aria-expanded='false'>▶ {_h(r.get('line', ''))}</button>"
            if context else _h(r.get("line", ""))
        )
        rows_beh.append(
            f"<tr class='{row_class}'{hidden_attr}>"
            f"<td class='tight'><span class='sev sev-{_h(sev)}'>{_h(sev)}</span></td>"
            f"<td class='tight'>{_h(r.get('file', ''))}</td>"
            f"<td class='tight'>{toggle}</td>"
            f"<td>{_h(r.get('behavior', ''))}</td>"
            f"<td class='{evidence_class}'>{_h(r.get('evidence', ''))}</td>"
            "</tr>"
            + (
                f"<tr id='{context_id}' class='source-context-row' style='display:none'>"
                f"<td colspan='5'><pre>{_h(context)}</pre></td></tr>"
                if context else ""
            )
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
    for crypto_idx, f in enumerate(findings[:2500]):
        if (f or {}).get("category") == "cryptocurrency_address":
            context = str(f.get("context", "") or "")
            context_id = f"crypto-context-{crypto_idx}"
            toggle = (
                f"<button type='button' class='context-toggle' data-context-target='{context_id}' aria-expanded='false'>▶ {_h(f.get('line', ''))}</button>"
                if context else _h(f.get("line", ""))
            )
            rows_crypto_html.append(
                "<tr>"
                f"<td class='crypto-addr'>{_h(f.get('decoded', ''))}</td>"
                f"<td class='tight'>{_h(f.get('file', ''))}</td>"
                f"<td class='tight'>{toggle}</td>"
                "</tr>"
                + (f"<tr id='{context_id}' class='source-context-row' style='display:none'><td colspan='3'><pre>{_h(context)}</pre></td></tr>" if context else "")
            )

    # ── Discord / Webhook Indicators ──
    rows_discord_html = []
    for discord_idx, f in enumerate(findings[:2500]):
        if (f or {}).get("category") == "discord_indicator":
            note = str(f.get("note", "") or "")
            if any(k in note.lower() for k in ("webhook", "token", "snowflake_id", "notification", "bot", "contextual")):
                signal = note.replace("source=string_scanner signal=", "").replace("source=comment_scanner signal=", "")
                context = str(f.get("context", "") or "")
                context_id = f"discord-context-{discord_idx}"
                toggle = (
                    f"<button type='button' class='context-toggle' data-context-target='{context_id}' aria-expanded='false'>▶ {_h(f.get('line', ''))}</button>"
                    if context else _h(f.get("line", ""))
                )
                rows_discord_html.append(
                    "<tr>"
                    f"<td class='tight'>{_h(signal[:50])}</td>"
                    f"<td>{_h(f.get('decoded', '')[:120])}</td>"
                    f"<td class='tight'>{_h(f.get('file', ''))}</td>"
                    f"<td class='tight'>{toggle}</td>"
                    "</tr>"
                    + (f"<tr id='{context_id}' class='source-context-row' style='display:none'><td colspan='4'><pre>{_h(context)}</pre></td></tr>" if context else "")
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
    .wrap {{ width:min(1900px,98vw); margin:1.25rem auto; }}
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
    .finding-context summary {{ cursor:pointer; color:#9dd5ff; text-decoration:underline dotted; }}
    .finding-context pre {{ margin-top:.5rem; width:min(100%,1100px); max-height:42rem; text-align:left; }}
    .context-toggle {{ border:0; padding:0; background:none; color:#9dd5ff; text-decoration:underline dotted; cursor:pointer; font:inherit; }}
    .source-context-row td {{ padding:.7rem 1rem 1rem; background:rgba(4,15,26,.72); }}
    .source-context-row pre {{ width:100%; max-width:none; max-height:42rem; white-space:pre; overflow:auto; }}
    .findings-controls {{ margin-top:.55rem; display:flex; gap:.5rem; align-items:center; flex-wrap:wrap; }}
    .btn-link {{ display:inline-block; text-decoration:none; background:linear-gradient(120deg,#1ca4db,#58d5ff); color:#062134; border:none; border-radius:9px; padding:.45rem .75rem; font-weight:700; cursor:pointer; }}
    .table-empty {{ color:var(--muted); }}
    .findings-table col.file-col {{ width:24ch; }}
    .findings-table col.line-col {{ width:7ch; }}
    .findings-table col.func-col {{ width:16ch; }}
    .findings-table col.cat-col {{ width:15ch; }}
    .reconstructed-table col.file-col {{ width:28ch; }}
    .reconstructed-table col.line-col {{ width:7ch; }}
    .reconstructed-table col.func-col {{ width:20ch; }}
    .reconstructed-table col.method-col {{ width:24ch; }}
    .reconstructed-table td.func-col, .reconstructed-table td.method-col {{ white-space:normal; overflow-wrap:anywhere; word-break:normal; }}
    .aes-table col.location-col {{ width:32ch; }}
    .aes-table td.key-col {{ white-space:normal; overflow-wrap:anywhere; word-break:break-word; }}
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
    {(("<div class='card'><h2 class='triage-title'>AES Keys Recovered</h2><div class='table-wrap'><table class='smart-table aes-table'><colgroup><col class='location-col'><col></colgroup><thead><tr><th>Location</th><th>Key material</th></tr></thead><tbody>" + "".join(rows_aes) + "</tbody></table></div></div>" if rows_aes else "")
      + "<div class='card'><h2 class='triage-title'>Decoded Findings</h2>"
      "<div class='table-wrap'><table class='smart-table findings-table'><colgroup><col class='file-col'><col class='line-col'><col class='func-col'><col class='cat-col'><col></colgroup><thead><tr><th class='tight'>File</th><th class='tight'>Line</th><th class='func-col'>Function</th><th class='cat-col'>Category</th><th>Decoded / Context</th></tr></thead><tbody>"
      + "".join(rows_find) + "</tbody></table></div>"
      + ("<div class='findings-controls' data-findings-controls='1' data-kind='findings' data-limit='200' data-step='200'><button type='button' class='btn-link findings-more-btn'>Show 200 more</button><button type='button' class='btn-link findings-all-btn'>Show all</button><div class='table-empty findings-toggle-status'>Showing first 200 of " + _h(len(rows_find)) + " rows.</div></div>" if len(rows_find) > findings_limit else "")
      + "</div>") if rows_find else ""}
     {( "<div class='card'><h2 class='triage-title'>Reconstructed Strings</h2><div class='table-wrap'><table class='smart-table reconstructed-table'><colgroup><col class='file-col'><col class='line-col'><col class='func-col'><col><col class='method-col'></colgroup><thead><tr><th>File</th><th>Line</th><th>Function</th><th>Resolved string</th><th class='method-col'>Method</th></tr></thead><tbody>" + "".join(rows_reconstructed) + "</tbody></table></div></div>" if rows_reconstructed else "")}
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
    document.querySelectorAll(".context-toggle").forEach(function (button) {{
      button.addEventListener("click", function () {{
        var target = document.getElementById(button.getAttribute("data-context-target"));
        if (!target) return;
        var open = target.style.display !== "none";
        target.style.display = open ? "none" : "table-row";
        button.setAttribute("aria-expanded", open ? "false" : "true");
        button.textContent = (open ? "▶ " : "▼ ") + button.textContent.slice(2);
      }});
    }});
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
    """Prompt when no decompiler jar is available but pre-existing decompiled folders exist.

    Returns the selected Path to scan, or None to cancel/fall through.
    """
    if RICH_AVAILABLE:
        ui_console = console or Console(stderr=True, width=_triage_ui_width())
        width = _triage_ui_width(ui_console)
        ui_console.print()
        ui_console.print(
            Panel(
                "[bold #C000FF]No decompiler jar found.[/bold #C000FF]\n"
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
        print("No decompiler jar found.", file=sys.stderr)
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
    """Inform the user that a decompiler is needed, then ask whether to
    scan cwd anyway or exit.

    Returns True to continue scanning cwd, False to exit.
    """
    if RICH_AVAILABLE:
        ui_console = console or Console(stderr=True, width=_triage_ui_width())
        width = _triage_ui_width(ui_console)
        lines = [
            "[bold #C000FF]No Java decompiler found.[/bold #C000FF]",
            "",
            f"Found [bold white]{len(jar_candidates)}[/bold white] JAR(s) to scan:",
        ]
        for jar in jar_candidates:
            lines.append(f"  • {jar.name}")
        lines += [
            "",
            "Place CFR or Vineflower in this directory to enable",
            "automatic decompilation, or point the tool at an already-decompiled folder:",
            "",
            f"  [dim]python java_triage.py ./{jar_candidates[0].stem}[/dim]  (if already extracted)",
            "",
            "Supported: CFR or Vineflower/FernFlower.",
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
        print("No Java decompiler found.", file=sys.stderr)
        print(f"Found {len(jar_candidates)} JAR(s) to scan:", file=sys.stderr)
        for jar in jar_candidates:
            print(f"  - {jar.name}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Place CFR or Vineflower in this directory to enable", file=sys.stderr)
        print("automatic decompilation, or point the tool at an already-decompiled folder:", file=sys.stderr)
        print(f"  python java_triage.py ./{jar_candidates[0].stem}  (if already extracted)", file=sys.stderr)
        print("", file=sys.stderr)
        print("Supported: CFR or Vineflower/FernFlower.", file=sys.stderr)

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


def maybe_prepare_cwd_jar_scan_root(
    initial_root: Path,
    show_progress: bool,
    progress_console=None,
    preferred_decompiler: str | None = "auto",
    allow_decompiler_download: bool = True,
) -> Path:
    cwd = Path.cwd().resolve()
    if initial_root != cwd:
        if initial_root.is_file() and initial_root.suffix.lower() in {".jar", ".zip"}:
            decompiler = _find_decompiler_jar(cwd, preferred_decompiler)
            if decompiler is None and allow_decompiler_download:
                decompiler = _download_decompiler_jar(cwd, preferred_decompiler, show_progress, progress_console)
            if decompiler is None:
                progress(show_progress, "no decompiler jar found; cannot decompile direct JAR target", progress_console)
                return initial_root
            return _prepare_single_jar_scan_root(initial_root, cwd, decompiler, show_progress, progress_console)
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

    decompiler = _find_decompiler_jar(cwd, preferred_decompiler)
    if decompiler is None and allow_decompiler_download:
        decompiler = _download_decompiler_jar(cwd, preferred_decompiler, show_progress, progress_console)

    # --- No decompiler jar available ---
    if decompiler is None:
        if not sys.stdin.isatty():
            progress(
                show_progress,
                "no decompiler jar found and stdin is not interactive; scanning cwd directly",
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

        # No existing decompiled folders — tell user a decompiler is needed and ask.
        if not _prompt_cfr_needed(jar_candidates, progress_console):
            print("Scan cancelled. Place CFR/Vineflower in this folder or allow auto-download.", file=sys.stderr)
            sys.exit(0)
        progress(
            show_progress,
            "decompiler required for JAR decompilation; scanning cwd directly",
            progress_console,
        )
        return initial_root

    # --- A decompiler is available ---
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

    return _prepare_single_jar_scan_root(selected, cwd, decompiler, show_progress, progress_console)


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
            if f.category == "reconstructed_string":
                continue
            decoded = f.decoded if not f.note else f"{f.decoded} [{f.note}]"
            t.add_row(f.category, f"{f.file}:{f.line}", f.function, decoded)
        console.print(t)

    aes_keys = [
        b for b in behaviors
        if str(b.behavior) == "aes_key_recovered"
    ]
    if aes_keys:
        _print_section(console, "AES Keys Recovered")
        key_table = Table(show_lines=False, box=box.SIMPLE, expand=True)
        key_table.add_column("Location", style="cyan")
        key_table.add_column("Key", style="yellow", overflow="fold")
        seen_aes = set()
        for b in aes_keys:
            key = (b.file, b.line, b.evidence)
            if key in seen_aes:
                continue
            seen_aes.add(key)
            key_table.add_row(f"{b.file}:{b.line}", b.evidence)
        console.print(key_table)

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
            decoy_note = " [DECOY / anti-analysis marker]" if runtime_c2.get("onchain_decoy") else ""
            console.print(f"[green]Resolved:[/green] yes via {runtime_c2.get('rpc_used')}")
            console.print(f"On-chain C2 base URL: {runtime_c2.get('c2_base_url')}{decoy_note}")
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
    s.add_row("AES decrypted strings", str(summary.get("aes_decrypted_count", 0)))
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

# Report filenames and executive summary generation.
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

    url_assembly = triage_payload.get("url_assembly", {}) or {}
    real_domain = url_assembly.get("c2_domain", "") or ""
    if real_domain:
        lines.append(f"Resolved C2 domain: {real_domain} (source: {url_assembly.get('c2_domain_source', '')})")
        for ep in url_assembly.get("assembled_urls", []) or []:
            lines.append(f"Assembled endpoint ({ep.get('method', '?')}): {ep.get('url', '')}")
    elif runtime_c2.get("resolved"):
        decoy_note = " [DECOY / anti-analysis marker]" if runtime_c2.get("onchain_decoy") else ""
        lines.append(f"Resolved C2 domain: {runtime_c2.get('c2_base_url', '')}{decoy_note}")
        if runtime_c2.get("exfil_endpoint"):
            lines.append(f"Exfil endpoint: {runtime_c2.get('exfil_endpoint')}")
        if runtime_c2.get("payload_endpoint"):
            lines.append(f"Payload endpoint: {runtime_c2.get('payload_endpoint')}")

    # Surface any AES key material recovered from the sample.
    aes_keys = [b for b in behaviors if str(b.get("behavior", "")) == "aes_key_recovered"]
    seen_keys: set[str] = set()
    for b in aes_keys:
        ev = str(b.get("evidence", ""))
        if not ev or ev in seen_keys:
            continue
        seen_keys.add(ev)
        lines.append(f"Recovered AES key: {ev}")

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
        with urlopen_with_proxy(req, timeout=90) as resp:
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
        with urlopen_with_proxy(req, timeout=90) as resp:
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
__all__ = [name for name in globals() if not name.startswith("__")]

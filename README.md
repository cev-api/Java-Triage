# Java Triage

![1](https://i.imgur.com/UI2YkSr.png)
![2](https://i.imgur.com/jBc8bNq.png)
![3](https://i.imgur.com/kJiw9Uh.png)
![4](https://i.imgur.com/QelAGpR.png)

`java_triage.py` is a static triage tool for suspicious Java codebases.

It recursively scans `.java` files, deobfuscates known string call patterns, scans suspicious string literals, surfaces behavioral indicators, finds suspicious artifact files, and can optionally resolve runtime C2 hints from on-chain config data.

## Features

- Deobfuscates `StringDecrypt.decrypt(new byte[]{...})` calls (multi-pass rewrite).
- Deobfuscates `load(new int[]{...}, new int[]{...}, k1, k2)` patterns (multi-pass rewrite).
- Includes deterministic length-seeded XOR-stream candidate support used by common Java obfuscators.
- Tracks deobfuscation stats (seen/replaced/unresolved, per-family counts, pass count).
- Scans plain Java string literals for suspicious indicators (URLs, command execution strings, payload paths, encoded blobs, and keyword signals).
- Detects Discord indicators, including bot tokens, webhook URLs, and snowflake IDs (guiQld/channel/user/role/application).
- Detects additional comms indicators, including Telegram bot tokens/API patterns and generic non-Discord webhook patterns.
- Detects additional encoded literals (Base64/Base32/hex/XOR-recovered text where possible).
- Classifies decoded strings (URL, RPC templates, credential fields, paths, crypto-related values, etc.).
- Flags behavior indicators such as:
  - dynamic class loading/invocation
  - HTTP payload download and exfiltration patterns
  - native payload extraction/loading
  - command execution and dropper/elevation helpers
  - CMSTP/UAC bypass and Defender tampering indicators
- Splits assessment behavior findings into:
  - `benign`
  - `needs_review`
  - `suspicious`
- Assigns behavior severities (`critical`/`high`/`medium`/`low`/`info`) and reports severity counts.
- Adds a metadata preface (`Basic Properties`, `JAR Info`, `Bundle Info`) to text/rich reports.
- Optionally enriches metadata with `Vhash`, `SSDEEP`, `TLSH`, `TrID`, and `Magika` when local tools/libraries are available.
- Identifies suspicious artifacts (`*.jar.*`, large opaque `.dat`/`.bin`, embedded resource payloads).
- Produces:
  - human-readable text output (with optional rich terminal tables)
  - machine-readable JSON output

## Default Deobfuscation Behavior

By default, running:

```bash
python java_triage.py <target>
```

will:

1. copy `<target>` to a deobfuscated working folder in the current directory
2. rewrite supported obfuscated string calls in that copy
3. scan the rewritten tree (post-decryption scan mode)

Auto output folder naming:

- `<target_name>_deobfuscated`
- if it exists: `<target_name>_deobfuscated_2`, `_3`, etc.

## String + Discord Coverage

String literal scanning (`"text"` style) includes:
- URLs and endpoint-like strings
- command/lolbin patterns (`cmd.exe`, `powershell`, `cmstp`, etc.)
- path/payload indicators (`.exe`, `.dll`, `.jar`, `.dat`, `.bin`, temp/appdata paths)
- high-entropy encoded blobs (base64/hex-like literals)
- suspicious keywords (`token`, `authorization`, `webhook`, `defender`, etc.)

Behavior scanning also includes:
- environment variable access (`System.getenv`)
- dynamic class loading via `URLClassLoader` (with extra signal if remote HTTP hosts are present)
- local Minecraft session/account file path references (`session.json`, `launcher_accounts.json`, `.minecraft`) with optional exfiltration context

Discord-focused detection includes:
- bot tokens
- webhook URLs (`discord.com/api/webhooks/...`)
- snowflake IDs (`17-20` digit IDs)
- contextual IDs in literals containing labels like `guild_id`, `channel_id`, `user_id`, `role_id`, `application_id`

## Inspiration

I saw this on [YouTube](https://www.youtube.com/watch?v=bsZJo49RaBE):

![Loser](https://i.imgur.com/mlxkzbL.png)

It was yet another super obvious Minecraft account stealer/trojan using a fake video to entice fools to lose their accounts.

This led me to make this Python app to quickly triage such obvious distributions. Turns out yes, it does steal your Minecraft credentials and sends it to a Discord webhook, obfuscated behind another API. It then downloads another trojan which using JNIC (poorly) extracts a Windows binary for a second payload. Given that payload wasn't also Java my interest stopped there for now.

Update: Mediafire has added a warning in response to this repo, how nice of them!

![Media](https://i.imgur.com/nTrHgDA.png)

## Requirements

- Python 3.9+ recommended
- Optional: [`rich`](https://pypi.org/project/rich/) for enhanced terminal output
- Optional CLI tools for metadata enrichment: `ssdeep`, `tlsh`, `trid`, `vhash`
- Optional Python package for metadata enrichment: [`magika`](https://pypi.org/project/magika/)

## Installation

No package install is required for the script itself.

```bash
# optional, for rich UI output
pip install rich

# optional, for magika metadata enrichment
pip install magika
```

## Usage

```bash
python java_triage.py [target]
```

### Examples

```bash
# Scan current directory
python java_triage.py

# Scan a specific unpacked source tree
python java_triage.py ./sample_project

# Disable default auto-decrypt copy/rewrite and scan source directly
python java_triage.py ./sample_project --no-auto-decrypt

# Explicitly write decrypted copy to a chosen path, then scan it
python java_triage.py ./sample_project --decrypt-codebase-out ./sample_project_deobf

# Rewrite in-place (destructive to target tree)
python java_triage.py ./sample_project --decrypt-codebase-in-place

# Rewrite only; skip post-decrypt triage scan
python java_triage.py ./sample_project --no-rescan-after-decrypt

# JSON output to stdout
python java_triage.py ./sample_project --json

# Save JSON report
python java_triage.py ./sample_project --json --out report.json

# Disable any network lookups during analysis
python java_triage.py ./sample_project --no-network

# Wider rich output
python java_triage.py ./sample_project --rich-width 220
```

## CLI Options

- `target`: folder to scan (default: current directory)
- `--json`: emit JSON instead of text
- `--out <path>`: write output to file
- `--no-progress`: disable progress messages
- `--no-network`: disable runtime C2 resolution over network
- `--rich-width <int>`: preferred rich console width for progress/final report rendering (default: `120`, minimum effective width: `80`)
- `--decrypt-codebase-in-place`: rewrite supported encrypted string calls in target tree directly
- `--decrypt-codebase-out <path>`: copy tree to `<path>`, rewrite there, then scan that rewritten tree
- `--no-rescan-after-decrypt`: perform rewrite stage only and exit
- `--no-auto-decrypt`: disable default auto-decrypt copy/rewrite behavior

## Output

Text output includes:
- Basic Properties (hashes + optional enrichments if available)
- JAR Info (manifest + archive metadata)
- Bundle Info (bundle counts, timestamps, extensions/types)
- Decode + string findings
  - includes source line numbers (`file:line`)
  - includes explicit decrypted categories:
    - `xor_decrypted_string`
    - `decrypted_string`
- Assessment findings (`benign`, `needs_review`, `suspicious`)
- Behavioral findings (with severity)
- Artifact findings
- Runtime C2 resolution status
- Summary counts (including high-risk findings, high-risk behaviors, assessment counts, category totals, behavior severity totals)
- Decryption-aware summary counters:
  - `XOR decrypted strings`
  - `Other decrypted strings`
  - populated from deobfuscation rewrite stats in decrypt mode

Rich output includes:
- startup banner shown before staged processing
- deobfuscation progress stage and scanning progress stage before final report
- wider, expanded tables (`expand=True`) with folded long text
- dedicated metadata sections (`Basic Properties`, `JAR Info`, `Bundle Info`)
- dedicated `Assessment Findings` table
- `Behavioral Findings` with risk column
- `Decode + String Findings` category column width constrained for better readability

JSON output structure:

```json
{
  "root": "scanned/path",
  "scan_mode": "post_decryption_only",
  "deobfuscation": {
    "calls_seen": 0,
    "replaced": 0,
    "unresolved": 0,
    "stringdecrypt_xor_replaced": 0,
    "stringdecrypt_other_replaced": 0,
    "load_calls_seen": 0,
    "load_replaced": 0,
    "load_unresolved": 0,
    "passes_run": 0
  },
  "target_metadata": {
    "basic_properties": {},
    "jar_info": {},
    "bundle_info": {}
  },
  "summary": {
    "xor_decrypted_count": 0,
    "decrypted_string_count": 0,
    "high_risk_behavior_count": 0,
    "behavior_severity_counts": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "assessment_counts": {
      "benign": 0,
      "needs_review": 0,
      "suspicious": 0
    }
  },
  "assessment_summary": {
    "counts": {
      "benign": 0,
      "needs_review": 0,
      "suspicious": 0
    },
    "findings": {
      "benign": [],
      "needs_review": [],
      "suspicious": []
    }
  },
  "runtime_c2": {},
  "findings": [],
  "behavior_findings": [
    {
      "severity": "info"
    }
  ],
  "artifact_findings": []
}
```

## Notes and Limits

- This is a triage helper, not a full malware sandbox or decompiler.
- The deobfuscation stage is deterministic and heuristic-based; unsupported custom routines may still remain unresolved.
- Behavioral detections are signature/heuristic based and may produce false positives or miss novel techniques.
- Network-based runtime C2 resolution (`eth_call`) is best-effort and may fail due to missing indicators, RPC issues, or decoding variance.
- Metadata enrichments (`SSDEEP`/`TLSH`/`TrID`/`Magika`/`Vhash`) are best-effort and only appear when dependencies are present.
- Do NOT rely on this as a means to ensure your safety with any java application.

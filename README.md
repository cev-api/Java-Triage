# Java Triage

![1](https://i.imgur.com/5qDhgi3.png)
![2](https://i.imgur.com/u7tBJCW.png)

`java_triage.py` is a static triage tool for suspicious Java codebases.

It recursively scans `.java` files, decodes specific integer-array string obfuscation patterns, scans suspicious string literals, surfaces behavioral indicators, finds suspicious artifact files, and can optionally resolve runtime C2 hints from on-chain config data.

## Features

- Decodes `load(new int[]{...}, new int[]{...}, k1, k2)` string obfuscation patterns.
- Scans plain Java string literals for suspicious indicators (URLs, command execution strings, payload paths, encoded blobs, and keyword signals).
- Detects Discord indicators, including bot tokens, webhook URLs, and snowflake IDs (guild/channel/user/role/application).
- Detects additional encoded literals (Base64/Base32/hex/XOR-recovered text where possible).
- Classifies decoded strings (URL, RPC templates, credential fields, paths, crypto-related values, etc.).
- Flags behavior indicators such as:
  - dynamic class loading/invocation
  - HTTP payload download and exfiltration patterns
  - native payload extraction/loading
  - command execution and dropper/elevation helpers
  - CMSTP/UAC bypass and Defender tampering indicators
- Identifies suspicious artifacts (`*.jar.*`, large opaque `.dat`/`.bin`, embedded resource payloads).
- Produces:
  - human-readable text output (with optional rich terminal tables)
  - machine-readable JSON output

## String + Discord Coverage

String literal scanning (`"text"` style) includes:
- URLs and endpoint-like strings
- command/lolbin patterns (`cmd.exe`, `powershell`, `cmstp`, etc.)
- path/payload indicators (`.exe`, `.dll`, `.jar`, `.dat`, `.bin`, temp/appdata paths)
- high-entropy encoded blobs (base64/hex-like literals)
- suspicious keywords (`token`, `authorization`, `webhook`, `defender`, etc.)

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

## Installation

No package install is required for the script itself.

```bash
# optional, for rich UI output
pip install rich
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

# JSON output to stdout
python java_triage.py ./sample_project --json

# Save JSON report
python java_triage.py ./sample_project --json --out report.json

# Disable any network lookups during analysis
python java_triage.py ./sample_project --no-network
```

## CLI Options

- `target`: folder to scan (default: current directory)
- `--json`: emit JSON instead of text
- `--out <path>`: write output to file
- `--no-progress`: disable progress messages
- `--no-network`: disable runtime C2 resolution over network

## Output

Text output includes:
- Decode + string findings
- Behavioral findings
- Artifact findings
- Runtime C2 resolution status
- Summary counts (including high-risk finding count and category totals)

JSON output structure:

```json
{
  "root": "scanned/path",
  "summary": {},
  "runtime_c2": {},
  "findings": [],
  "behavior_findings": [],
  "artifact_findings": []
}
```

## Notes and Limits

- This is a triage helper, not a full malware sandbox or decompiler.
- Behavioral detections are signature/heuristic based and may produce false positives or miss novel techniques.
- Network-based runtime C2 resolution (`eth_call`) is best-effort and may fail due to missing indicators, RPC issues, or decoding variance.
- Do NOT rely on this as a means to ensure your safety with any java application.

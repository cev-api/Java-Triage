# Java Triage

![1](https://i.imgur.com/UI2YkSr.png)
![2](https://i.imgur.com/jBc8bNq.png)
![3](https://i.imgur.com/kJiw9Uh.png)
![4](https://i.imgur.com/QelAGpR.png)

`java_triage.py` is a static triage tool for suspicious Java codebases, decompiled JARs, and Minecraft mods.

It can decompile JARs with CFR, rewrite supported obfuscated string patterns, scan suspicious strings and behaviors, identify suspicious artifacts, resolve runtime C2 hints from on-chain config data, optionally inspect a resolved stage-2 JAR in static-only mode, and produce Rich console, JSON, and HTML reports.

## Features

- Decompiles JARs with CFR as part of the workflow when scanning from a directory containing a target JAR and a local CFR JAR.
- Deobfuscates `StringDecrypt.decrypt(new byte[]{...})` calls with multi-pass rewrite support.
- Deobfuscates `load(new int[]{...}, new int[]{...}, k1, k2)` patterns.
- Includes deterministic length-seeded XOR-stream candidate support used by common Java obfuscators.
- Tracks deobfuscation stats such as seen, replaced, unresolved, per-family counts, and pass count.
- Scans plain Java string literals for suspicious indicators including URLs, command execution strings, payload paths, encoded blobs, and keywords.
- Reconstructs additional obfuscation patterns from source, including split `String[]` fragments, printable `byte[]` or `char[]` literals, and reversed `StringBuilder(...).reverse().toString()` forms.
- Detects Discord indicators, including bot tokens, webhook URLs, and snowflake IDs.
- Detects Discord Chromium encrypted-token marker payloads (`dQw4w9WgXcQ:<base64>`) and classifies them as credential-theft context.
- Detects additional comms indicators, including Telegram bot tokens, Telegram API patterns, and generic non-Discord webhook patterns.
- Detects additional encoded literals such as Base64, Base32, hex, and XOR-recovered text where possible.
- Classifies decoded strings into categories such as URLs, RPC templates, credential fields, paths, and crypto-related values.
- Falls back to `.class` constant-pool scanning when decompiled `.java` sources are unavailable.
- Expands scan roots by unpacking nested dropped JARs and embedded Base32 archive resources for recursive triage.
- Flags behavior indicators such as:
  - dynamic class loading or invocation
  - HTTP payload download and exfiltration patterns
  - native payload extraction or loading
  - command execution and dropper or elevation helpers
  - CMSTP, UAC bypass, and Defender tampering indicators
- Adds explicit heavy-obfuscation, decompiler-failure, and class-fallback diagnostic behaviors.
- Splits assessment behavior findings into `benign`, `needs_review`, and `suspicious`.
- Assigns behavior severities (`critical`, `high`, `medium`, `low`, `info`) and reports severity counts.
- Adds metadata sections such as `Basic Properties`, `JAR Info`, and `Bundle Info`.
- Optionally enriches metadata with `Vhash`, `SSDEEP`, `TLSH`, `TrID`, and `Magika` when local tools or libraries are available.
- Identifies suspicious artifacts such as `*.jar.*`, large opaque `.dat` or `.bin`, and embedded resource payloads.
- Optionally downloads a resolved stage-2 payload JAR and performs static-only archive and content triage without executing code.
- Extracts blockchain indicators from decoded strings such as contracts, selectors, RPC hosts, and RPC URLs.
- Detects known malware variants, runs raw string detections, and applies cross-variant heuristics.
- Queries the free RatterScanner API for discovered SHA256 hashes.
- Produces:
  - human-readable console output with optional Rich tables and progress bars
  - machine-readable JSON output
  - standalone HTML reports

## Default Workflow

By default, running:

```bash
python java_triage.py <target>
```

will:

1. Resolve the target folder or use the current directory.
2. If applicable, decompile a selected JAR with CFR into a working source folder.
3. Run a quick obfuscation-density probe on the scan root.
4. If supported obfuscated call patterns are detected, copy the target to a deobfuscated working folder and rewrite supported string calls there.
5. Scan the resulting source tree.
6. Optionally resolve runtime C2 hints, perform stage-2 static analysis, and enrich results with RatterScanner.
7. Render the Rich console report and write JSON and HTML reports by default.

If the probe does **not** detect any supported obfuscated call patterns, no deobfuscated copy is created and the source tree is scanned directly.

Current default probe threshold:
- Total `StringDecrypt.decrypt(...)` + `load(new int[]{...})` calls >= `1`

Auto output folder naming for rewritten trees:

- `<target_name>_deobfuscated`
- if it exists: `<target_name>_deobfuscated_2`, `_3`, etc.

Default report naming:

- scanning `ExampleMod` writes `ExampleMod.json` and `ExampleMod.html`
- scanning `example.jar` writes `example.json` and `example.html`

## String + Discord Coverage

String literal scanning includes:
- URLs and endpoint-like strings
- Command and LOLBin patterns such as `cmd.exe`, `powershell`, and `cmstp`
- Path and payload indicators such as `.exe`, `.dll`, `.jar`, `.dat`, `.bin`, and temp or appdata paths
- High-entropy encoded blobs
- Suspicious keywords such as `token`, `authorization`, `webhook`, and `defender`

Behavior scanning also includes:
- Environment variable access (`System.getenv`)
- Dynamic class loading via `URLClassLoader`
- Local Minecraft session or account file path references such as `session.json`, `launcher_accounts.json`, and `.minecraft`
- Possible identity exfiltration when username or UUID reads appear alongside outbound HTTP activity

Discord-focused detection includes:
- Bot tokens
- Webhook URLs (`discord.com/api/webhooks/...`)
- Snowflake IDs (`17-20` digit IDs)
- Contextual IDs in literals containing labels like `guild_id`, `channel_id`, `user_id`, `role_id`, and `application_id`
- Encrypted Chromium token marker blobs (`dQw4w9WgXcQ:<base64>`) commonly used in token-stealer chains

## Minecraft Session and Identity Detection

To reduce false positives, session or account path detection requires:

- the token to appear inside a Java string literal such as `session.json`, `launcher_accounts.json`, or `.minecraft`
- file I/O usage in the same file such as `new File(`, `Paths.get(`, `Files.read...`, `FileInputStream(`, or `FileReader(`

This helps avoid import-only or UI text being misclassified as file access. If outbound HTTP is also present in that file, an additional high-severity signal is raised for possible exfiltration.

The scanner also flags a high-severity indicator when user identifiers are read and outbound HTTP appears in the same file:

- Username reads: `method_1676()`, `getName()`, `getUsername()`
- UUID reads: `method_44717()`, `GameProfile.getId()`, `Session.getUuid()`, and mapped or Yarn variants
- Outbound HTTP markers: discovered host URLs, `HttpClient.send(...)`, `OkHttpClient.newCall(...)`, `HttpURLConnection`

If any username or UUID read appears with outbound HTTP, the tool emits `possible_minecraft_identity_exfiltration` with the source location and evidence.

Expanded alias coverage includes:

- Session presence or access: `method_1548()`, `getSession()`, `getUser()`, `net.minecraft.client.util.Session`, `new Session(...)`
- Username access: `method_1676()`, `getName()`, `getUsername()`
- UUID access: `method_44717()`, `getProfileId()`, `getUuid()`, `GameProfile.getId()`
- Token access: `method_1674()`, `getAccessToken()`, `session.getAccessToken()`

## Inspiration

I saw this on [YouTube](https://www.youtube.com/watch?v=bsZJo49RaBE):

![Loser](https://i.imgur.com/mlxkzbL.png)

It was yet another super obvious Minecraft account stealer or trojan using a fake video to entice fools to lose their accounts.

This led me to make this Python app to quickly triage such distributions. The sample I was looking at stole Minecraft credentials, sent them to a Discord webhook through another API, and then downloaded another trojan which extracted a Windows binary as a second payload.

Update: Mediafire later added a warning in response to this repo.

![Media](https://i.imgur.com/nTrHgDA.png)

## Requirements

- Python 3.10+ recommended
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

For a full list of options at any time:

```bash
python java_triage.py --help
```

### Examples

```bash
# Scan current directory
python java_triage.py

# Scan a specific unpacked source tree
python java_triage.py ./sample_project

# Disable default auto-decrypt copy or rewrite behavior
python java_triage.py ./sample_project --no-auto-decrypt

# Explicitly write a decrypted copy to a chosen path, then scan it
python java_triage.py ./sample_project --decrypt-codebase-out ./sample_project_deobf

# Rewrite in-place
python java_triage.py ./sample_project --decrypt-codebase-in-place

# Rewrite only, then skip the post-decrypt triage scan
python java_triage.py ./sample_project --no-rescan-after-decrypt

# Disable JSON output
python java_triage.py ./sample_project --no-json

# Save JSON report to a custom file
python java_triage.py ./sample_project --out report.json

# Disable HTML report output
python java_triage.py ./sample_project --no-html

# Save HTML report to a custom file
python java_triage.py ./sample_project --html-out report.html

# Disable all network lookups during analysis
python java_triage.py ./sample_project --no-network

# Disable stage-2 static analysis
python java_triage.py ./sample_project --no-analyze-stage2

# Wider rich output
python java_triage.py ./sample_project --rich-width 220
```

## CLI Options

- `target`: folder to scan (default: current directory)
- `--json`: emit JSON output (enabled by default)
- `--no-json`: emit text or Rich output instead of JSON
- `--out <path>`: write output to file
- `--html`: also emit an HTML report (enabled by default)
- `--no-html`: disable HTML report output
- `--html-out <path>`: write HTML report to a custom file
- `--no-progress`: disable progress messages
- `--no-network`: disable runtime C2 resolution and related network lookups
- `--analyze-stage2`: after resolving a runtime payload endpoint, download the stage-2 JAR and perform static-only analysis (enabled by default)
- `--no-analyze-stage2`: disable stage-2 static analysis
- `--rich-width <int>`: preferred Rich console width for progress and final report rendering
- `--decrypt-codebase-in-place`: rewrite supported encrypted string calls in the target tree directly
- `--decrypt-codebase-out <path>`: copy the tree to `<path>`, rewrite there, then scan that rewritten tree
- `--no-rescan-after-decrypt`: perform rewrite only and exit
- `--no-auto-decrypt`: disable opportunistic auto-decrypt probe and rewrite behavior

## Output

Text and Rich output include:
- Basic Properties, JAR Info, and Bundle Info
- Decode and string findings
- Assessment findings (`benign`, `needs_review`, `suspicious`)
- Behavioral findings with severity
- Artifact findings
- Runtime C2 resolution status
- Stage-2 Analysis status
- Blockchain Indicators
- Network Endpoint Assessment
- Variant Detections
- Raw String Detections
- Heuristic Detections
- RatterScanner results
- Summary counts and verdict layers

JSON output includes the full scan payload, including:
- `target_metadata`
- `runtime_c2`
- `stage2_analysis`
- `blockchain_indicators`
- `network_endpoint_assessment`
- `variant_detections`
- `raw_string_detections`
- `heuristic_detections`
- `ratter_scanner`
- `findings`
- `behavior_findings`
- `artifact_findings`
- `summary`

HTML output is a standalone styled report and includes:
- top-level summary cards and overall assessment
- executive summary, when available
- expanded metadata and enrichment sections
- omission of categories that are completely empty

## Executive Summary

If `OPENAI_API_KEY` is set, the tool sends the triage JSON to the OpenAI Responses API and asks for a concise executive summary describing the likely flow, capabilities, risks, and goals of the scanned application or malware.

If no API key is present, the tool behaves as if this feature does not exist and does not mention AI or GPT in the output.

## Notes and Limits

- This is a triage helper, not a full malware sandbox or decompiler.
- The deobfuscation stage is deterministic and heuristic-based; unsupported custom routines may still remain unresolved.
- Class-constant fallback mode provides useful indicators but less semantic context than full source scanning.
- Behavioral and signature detections are heuristic-based and may produce false positives or miss novel techniques.
- Network-based runtime C2 resolution and stage-2 enrichment are best-effort and may fail due to missing indicators, DNS failure, RPC issues, or decoding variance.
- Metadata enrichments such as `SSDEEP`, `TLSH`, `TrID`, `Magika`, and `Vhash` are best-effort and only appear when dependencies are available.
- Nested archive or payload extraction is heuristic and best-effort; highly custom packers may still evade static expansion.
- Do **not** rely on this tool alone to determine whether a Java application is safe.

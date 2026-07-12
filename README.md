# Java Triage

![1](https://i.imgur.com/Dwdt1FS.png)

`java_triage.py` is a static triage tool for suspicious Java codebases, decompiled JARs, and Minecraft mods.

It can decompile JARs with CFR (including hostile/eSkid-protected samples), rewrite supported obfuscated string patterns, produce deciphered copies with XOR strings replaced, scan suspicious strings and behaviors, identify suspicious artifacts, resolve runtime C2 hints from on-chain config data, assemble full C2 URLs from decoded fragments, optionally inspect a resolved stage-2 JAR in static-only mode (including AES decryption of encrypted blobs), probe live infrastructure, query external enrichment APIs (RatterScanner and JLab static scan), and produce Rich console, JSON, and HTML reports.

Under the hood, it combines bytecode-aware decompilation, constant-pool fallback scanning, `invokedynamic` / `BootstrapMethods` mapping, heuristic string recovery, and behavior classification into one triage pass.

## Features

### Static Analysis
- Decompiles JARs with CFR when available.
- Falls back to `.class` constant-pool scanning when source is missing or hostile.
- Handles eSkid/protected samples, malformed archives, nested dropped JARs, and embedded Base32 archive resources.
- Maps `invokedynamic` / `BootstrapMethods` sites and records suspicious bootstrap owners.
- Produces a post-deobfuscation string dump with AES key candidate detection.

### Triage Signals
- Scores literals, decoded strings, and file behaviors separately before collapsing them into verdict tiers.
- Tracks source locations, family breakdowns, and replacement counts for supported decryptor patterns.
- Suppresses obvious bundled-library noise so the high-signal findings stay visible.

### Deobfuscation & String Recovery
- Rewrites `StringDecrypt.decrypt(new byte[]{...})` and `load(new int[]{...}, new int[]{...}, k1, k2)` patterns.
- Supports deterministic XOR-stream decoding used by common obfuscators.
- Deciphers XOR-obfuscated `getBytes("ISO-8859-1")` and `toCharArray()` strings in whole-codebase or single-file mode.
- Recovers split strings, printable byte/char arrays, reversed `StringBuilder` literals, and inline Skidfuscator-style XOR patterns.
- Tracks replace counts, unresolved values, pass counts, and family breakdowns.

### Detection Coverage
- Scans literals, comments, and decoded strings for URLs, payload paths, encoded blobs, command execution, persistence clues, and suspicious keywords.
- Detects Discord, Telegram, webhook, and cryptocurrency indicators.
- Traces Minecraft session, username, UUID, and access-token reads into network/write sinks.
- Flags multi-payload exfiltration, self-copy + detached re-launch persistence, and staged dropper behavior.
- Classifies findings and behaviors into severity and verdict tiers, while suppressing obvious bundled-library noise.
- Emits methodology behaviors for obfuscation patterns, token-harvest vectors, and decompiler-failure diagnostics.

### Minecraft Coverage
- Detects session/account file references such as `session.json`, `launcher_accounts.json`, and `.minecraft`.
- Flags possible Minecraft identity exfiltration when user identifiers appear alongside outbound HTTP activity.
- Recognizes Minecraft client module packs via `addModule(...)` registration and Wurst-style `HackList` / `*Hack` patterns.
- Exposes module metadata, category counts, and Minecraft-specific behavior IDs in the report.

### Infrastructure & Enrichment
- Resolves runtime C2 from on-chain Ethereum/Polygon `eth_call` data.
- Assembles full C2 URLs from decoded fragments and probes endpoints without downloading payloads.
- Supports optional stage-2 static-only analysis and an interactive download/decrypt prompt.
- Enriches results with RatterScanner when network access is allowed. JLab public static scan uploads are temporarily disabled while the service is offline.
- Extracts blockchain indicators, custom header fingerprints, and payload/persistence endpoint clues.

### Reporting & UX
- Produces Rich console output, JSON, and standalone HTML reports.
- Includes banner rendering, Unicode-safe output handling, summary cards, and sortable HTML tables.
- Adds metadata sections such as `Basic Properties`, `JAR Info`, and `Bundle Info`.
- Optionally enriches metadata with `Vhash`, `SSDEEP`, `TLSH`, `TrID`, and `Magika`.
- Identifies suspicious artifacts such as embedded payloads, large opaque blobs, and archive-like resources.

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
- scanning a directory such as `example_project` writes `example_project.json` and `example_project.html`

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

## Minecraft Client Module Coverage

Java Triage now also looks beyond individual session/token reads and tries to recognize Minecraft client module packs and utility clients.

It does this by:

- locating module manager patterns such as repeated `addModule(SomeClass.class)` registration
- extracting module metadata from the referenced source classes
- falling back to Wurst-style `HackList` / `*Hack` patterns when module registration is not present

When a module pack is detected, the report includes:

- module name
- description
- category
- source file
- aggregate category counts

This data is also exposed in JSON under `minecraft_modules`, and the HTML/Rich reports render a dedicated module summary when detection succeeds.

## JLab Static Scan Enrichment

> **Temporarily disabled:** JLab has shut down, so Java Triage will not upload files to its static-scan API. The integration is retained in the codebase for re-enablement when the service returns.

When enabled, Java Triage will attempt to upload the original source JAR/ZIP to:

- `https://jlab.threat.rip/api/public/static-scan`

Behavior details:

- Temporarily disabled, including when `--jlab-static-scan` is supplied
- Requires network access (disabled by `--no-network`)
- Upload target priority:
  - source JAR metadata path/name fallback for directory scans that originated from a JAR
  - scan root file if internal analysis root resolves to a `.jar`/`.zip`
- Size and format guardrails:
  - only `.jar`/`.zip` are uploaded
  - max upload size handled by the tool: `50 MB`

Returned data is stored under `jlab_static_scan` in JSON and rendered in Rich/HTML reports, including:

- upload metadata (filename, size, status)
- rate-limit metadata when available
- matched signature count and signature rows (severity, id, name, description, type, count, match preview)

## Executive Summary

The tool can generate an AI executive summary using either OpenAI or DeepSeek.

- `OPENAI_API_KEY`: enables OpenAI Chat Completions
- `DEEPSEEK_API_KEY`: enables DeepSeek Chat Completions
- `TRIAGE_LLM_PROVIDER`: optional provider selector:
  - `auto` (default): tries OpenAI first, then DeepSeek
  - `openai`: use only OpenAI
  - `deepseek`: use only DeepSeek
- `TRIAGE_OPENAI_MODEL`: OpenAI model override (default: `gpt-4.1-mini`)
- `TRIAGE_DEEPSEEK_MODEL`: DeepSeek model override (default: `deepseek-v4-flash`)
  - Common values: `deepseek-v4-flash`, `deepseek-v4-pro`
- `TRIAGE_DEEPSEEK_REASONING_EFFORT`: DeepSeek reasoning effort (default: `high`)

If neither API key is present, the tool behaves as if this feature does not exist and does not mention AI in the output.

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

New here? Start with the beginner guide: [BEGINNER_GUIDE.md](BEGINNER_GUIDE.md)

This project assumes Windows and PowerShell in the examples below.

```powershell
python java_triage.py [target]
```

`target` is a directory path (or omitted for current directory).

For a full list of options at any time:

```powershell
python java_triage.py --help
```

### Examples

```powershell
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

# JLab static scan uploads are currently disabled
python java_triage.py ./sample_project

# Wider rich output
python java_triage.py ./sample_project --rich-width 220

# Decipher a single .java file (no full scan)
python java_triage.py --decipher-only ./sample_project/suspicious/Helper.java

# Produce a deciphered copy + scan both
python java_triage.py ./sample_project --decipher-codebase
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
- `--jlab-static-scan`: reserved for JLab public static scan uploads; currently disabled while JLab is offline
- `--no-jlab-static-scan`: disable JLab public static scan lookup (the default while the service is offline)
- `--analyze-stage2`: after resolving a runtime payload endpoint, download the stage-2 JAR and perform static-only analysis (enabled by default)
- `--no-analyze-stage2`: disable stage-2 static analysis
- `--rich-width <int>`: preferred Rich console width for progress and final report rendering
- `--decrypt-codebase-in-place`: rewrite supported encrypted string calls in the target tree directly
- `--decrypt-codebase-out <path>`: copy the tree to `<path>`, rewrite there, then scan that rewritten tree
- `--no-rescan-after-decrypt`: perform rewrite only and exit
- `--no-auto-decrypt`: disable opportunistic auto-decrypt probe and rewrite behavior
- `--decipher-codebase`: produce a deciphered copy of the target with all XOR-obfuscated `getBytes`/`toCharArray` strings replaced by decoded literals, then scan both copies (enabled by default; disable with `--no-auto-decrypt` or `--no-rescan-after-decrypt`)
- `--decipher-only <path>`: decipher a single `.java` file and write decoded strings to JSON (no scan)
- `--rich-width <int>`: preferred Rich console width for progress and final report rendering

## Methodology Behavior IDs

The following behavior IDs were added for explicit methodology coverage and can be searched directly in JSON output:

- `obf_xor_encoded_name_access`
- `obf_base64_encoded_name_access`
- `obf_caesar_encoded_name_access`
- `obf_methodhandle_token_access`
- `obf_lambdametafactory_token_access`
- `obf_array_indirect_dispatch_token_access`
- `obf_split_reassembled_name_access`
- `obf_unsafe_field_token_access`
- `obf_varhandle_field_token_access`
- `obf_stackwalker_indirect_access`
- `obf_int_array_encoded_name_access`
- `obf_classloader_bypass_token_access`
- `token_class_sweep_static_field_harvest`
- `token_spin_race_window_harvest`
- `token_yggdrasil_internal_probe`
- `token_process_commandline_harvest`
- `token_processhandle_commandline_probe`
- `token_runtime_mxbean_arg_probe`
- `token_system_property_auth_probe`
- `token_environment_auth_probe`
- `token_sun_java_command_probe`
- `token_jdk_internal_process_probe`
- `dataflow_token_to_network_sink`
- `dataflow_username_to_network_sink`
- `dataflow_uuid_to_network_sink`
- `token_bootstrap_constructor_capture`
- `token_authlib_deep_hook_access`
- `token_connection_authorization_header_probe`
- `token_urlconnection_requests_unsafe_probe`
- `token_connection_spin_race_header_harvest`
- `blockchain_dns_c2_resolver`
- `raw_socket_http_post_client`
- `proof_minecraft_token_raw_socket_exfil_chain`
- `two_payload_exfil_architecture`
- `persistence_filesystem_copy_relaunch_chain`
- `persistence_detached_process_relaunch`
- `c2_fallback_domain`
- `payload_download_endpoint`
- `persistence_install_directory`
- `python_executable_reference`
- `python_script_reference`
- `exfil_endpoint_prefiremc`
- `exfil_endpoint_submit_log`
- `python_subprocess_argument_chain`
- `detached_process_runtime_indicator`
- `minecraft_coordinate_exfiltration`
- `discord_webhook_url_reassembly`
- `multi_path_exfil_breakdown`
- `inline_xor_string_decoder`
- `sensitive_game_data_comment`

The `decipher` section in JSON reports contains counts of XOR strings replaced and files changed when `--decipher-codebase` is used (enabled by default).

## Output

Text and Rich output include:
- Basic Properties, JAR Info, and Bundle Info
- Cryptocurrency Addresses
- Discord / Webhook Indicators
- Windows Persistence / Staging Indicators
- Decode and string findings (sorted by category priority)
- Assessment findings (`benign`, `needs_review`, `suspicious`)
- Behavioral findings (sorted by severity)
- Artifact findings
- Network Endpoint Assessment
- Runtime C2 Resolution
- Assembled C2 URLs
- Infrastructure Probe Results
- Blockchain Indicators
- Variant Detections
- Raw String Detections
- Heuristic Detections
- RatterScanner results
- JLab static scan results (sorted by severity)
- Stage-2 Analysis status
- Interactive post-scan download + decrypt prompt
- Summary counts and verdict layers

JSON output includes the full scan payload, including:
- `target_metadata`
- `scan_diagnostics` (per-scan-root breakdown of java_files, class_files, finding_count, scan_mode)
- `runtime_c2`
- `url_assembly` (assembled C2 URLs with domain, method, path, description)
- `infra_probe` (live probe results per endpoint)
- `stage2_analysis`
- `blockchain_indicators`
- `network_endpoint_assessment`
- `variant_detections`
- `raw_string_detections`
- `heuristic_detections`
- `ratter_scanner`
- `jlab_static_scan`
- `decipher` (XOR string replacement stats)
- `deobfuscation`
- `string_dump` (post-prep string dump stats)
- `invokedynamic_bootstrap` (indy/bootstrap mapping stats)
- `findings`
- `behavior_findings`
- `artifact_findings`
- `reconstructed_strings` (StringBuilder-reassembled XOR strings)
- `minecraft_modules`
- `summary`

HTML output is a standalone styled report and includes:
- top-level summary cards and overall assessment
- executive summary, when available
- expanded metadata and enrichment sections
- clickable column headers for sorting tables
- omission of categories that are completely empty

## Notes and Limits

- This is a triage helper, not a full malware sandbox or decompiler.
- The deobfuscation stage is deterministic and heuristic-based; unsupported custom routines may still remain unresolved.
- Class-constant fallback mode provides useful indicators but less semantic context than full source scanning.
- Behavioral and signature detections are heuristic-based and may produce false positives or miss novel techniques.
- Network-based runtime C2 resolution and stage-2 enrichment are best-effort and may fail due to missing indicators, DNS failure, RPC issues, or decoding variance.
- External API enrichments (RatterScanner/JLab) are best-effort and may fail due to network issues, API errors, rate limits, or response format changes.
- JLab public scan is an external experimental endpoint; response fields and behavior may change over time.
- Metadata enrichments such as `SSDEEP`, `TLSH`, `TrID`, `Magika`, and `Vhash` are best-effort and only appear when dependencies are available.
- Nested archive or payload extraction is heuristic and best-effort; highly custom packers may still evade static expansion.
- Do **not** rely on this tool alone to determine whether a Java application is safe.

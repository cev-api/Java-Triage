# Java Triage

![1](https://i.imgur.com/Dwdt1FS.png)

`java_triage.py` is a static triage tool for suspicious Java codebases, decompiled JARs, and Minecraft mods.

It can decompile JARs with CFR (including hostile/eSkid-protected samples), rewrite supported obfuscated string patterns, produce deciphered copies with XOR strings replaced, scan suspicious strings and behaviors, identify suspicious artifacts, resolve runtime C2 hints from on-chain config data, assemble full C2 URLs from decoded fragments, optionally inspect a resolved stage-2 JAR in static-only mode (including AES decryption of encrypted blobs), probe live infrastructure, query external enrichment APIs (RatterScanner and JLab static scan), and produce Rich console, JSON, and HTML reports.

## Features

### Decompilation & JAR Handling
- Decompiles JARs with CFR as part of the workflow when scanning from a directory containing a target JAR and a local CFR JAR.
- **Hostile-JAR resilience**: handles eSkid/protected_by_eskid samples with class-only fast paths, app-only decompile JAR filtering, malformed entry normalization (trailing slash class entries, impossible Windows filenames), and constant-pool fallback scanning.
- **Invokedynamic bootstrap mapping**: parses JVM class files to map all `invokedynamic`/`BootstrapMethods` sites, flags suspicious non-JDK bootstrap owners, and tracks string/byte[]/class return categories.
- **Post-deobfuscation string dump**: writes a comprehensive string dump (JSON + TXT) for hostile samples, with AES key candidate detection (raw/hex/base64 key material identification).
- Falls back to `.class` constant-pool scanning when decompiled `.java` sources are unavailable.
- Expands scan roots by unpacking nested dropped JARs and embedded Base32 archive resources for recursive triage.

### Deobfuscation
- Deobfuscates `StringDecrypt.decrypt(new byte[]{...})` calls with multi-pass rewrite support.
- Deobfuscates `load(new int[]{...}, new int[]{...}, k1, k2)` patterns.
- Includes deterministic length-seeded XOR-stream candidate support used by common Java obfuscators (magic=1313161813, mul=73244475).
- **Decipher mode** (`--decipher-codebase`): produces a deciphered copy where all XOR-obfuscated `getBytes("ISO-8859-1")` and `toCharArray()` patterns are replaced with their decoded string literals. Handles both JDK-style calls and CFR-style bare `byte[]`/`char[]` assignment patterns. Enabled by default (auto-decipher).
- **Single-file decipher** (`--decipher-only PATH`): decodes all XOR strings in a single `.java` file and outputs categorized JSON.
- **Skidfuscator-style inline XOR decoder**: decodes `byte[] arr = "XORstring"` first-byte-key XOR patterns with `arr[0] & 0xFF` key length extraction.
- Tracks deobfuscation stats such as seen, replaced, unresolved, per-family counts, and pass count.
- Scans plain Java string literals for suspicious indicators including URLs, command execution strings, payload paths, encoded blobs, and keywords.
- Reconstructs additional obfuscation patterns from source, including split `String[]` fragments, printable `byte[]` or `char[]` literals, reversed `StringBuilder(...).reverse().toString()` forms, and `StringBuilder`-based XOR string reconstruction.
- **Java comment scanning**: extracts `//` and `/* */` comments and flags self-documenting malware comments (coordinate exfil, stealer labels, webhook mentions, C2 references).
- Detects Discord indicators, including bot tokens, webhook URLs, snowflake IDs, contextual guild/channel/user IDs, and `"Discord Notification"` keyword patterns in decoded strings.
- Detects Discord Chromium encrypted-token marker payloads (`dQw4w9WgXcQ:<base64>`) and classifies them as credential-theft context.
- **Discord webhook URL reassembly detection**: identifies XOR-fragmented webhook URLs where the path + snowflake ID are assembled at runtime from obfuscated fragments.
- Detects additional comms indicators, including Telegram bot tokens, Telegram API patterns, and generic non-Discord webhook patterns.
- **Bitcoin/cryptocurrency address detection**: Base58 P2PKH/P2SH + Bech32 regex, dedicated `cryptocurrency_address` category.
- Detects additional encoded literals such as Base64, Base32, hex, and XOR-recovered text where possible.
- Performs a full XOR string decoding pass over all `getBytes("ISO-8859-1")` and `toCharArray()` prefixed-key patterns, capturing complete decoded strings — including JSON payload templates, User-Agent strings, static UUIDs, and persistence paths — rather than only filtering to "interesting" candidates.
- **Inline first-byte-key XOR decode**: catches Skidfuscator-style inline `byte[]/char[]` XOR patterns where the first byte encodes key length.
- Suppresses false-positive domain hits for file extensions (`.exe`, `.dll`, `.jar`, `.png`, `.json`, etc.) via `_DOMAIN_FALSE_POSITIVE_EXTENSIONS`.
- Traces Minecraft session/token/identity API calls through variable assignments to network/write sinks (data flow tracer), emitting specific `dataflow_*` behavior findings when a source-to-sink path is confirmed.
- Detects multi-payload exfiltration architectures where malware sends tiered POST requests — e.g. a lightweight prefire beacon followed by a separate full-credential profile POST. Now with richer `multi_path_exfil_breakdown` detailing exactly which data types flow to which endpoints.
- Detects self-copy + detached re-launch persistence chains: JAR resolves its own path → copies to LOCALAPPDATA → spawns javaw.exe detached → survives game shutdown.
- **Windows Persistence / Staging section**: dedicated report section showing environment variables, staging paths, executables, launched payloads, and confirmed/not-confirmed persistence mechanisms.
- Classifies decoded strings into categories such as URLs, RPC templates, credential fields, paths, crypto-related values, Discord indicators, cryptocurrency addresses, and more.
- **Rich string classifier**: catches Windows persistence paths (`\microsoft\`, `NtProfileIndex`), `%ENV%` variables, executable references (`.exe`, `.py`), CLI flags, custom HTTP headers, stealer log strings, CDN indicators, and TLS trust-all patterns.
- Flags behavior indicators such as:
  - dynamic class loading or invocation
  - HTTP payload download and exfiltration patterns
  - native payload extraction or loading
  - command execution and dropper or elevation helpers
  - CMSTP, UAC bypass, and Defender tampering indicators
- Adds explicit methodology detections for obfuscated token/session access patterns and token-harvest vectors, including:
  - XOR/Base64/Caesar decoded names, MethodHandles, LambdaMetafactory, array-indirect dispatch, split-name reconstruction, Unsafe/VarHandle access, StackWalker indirection, integer-array encoded names, and classloader-bypass access
  - class-sweep token harvest, spin-race window harvest, Yggdrasil internal probing, and process-argument/system-property/environment token probing paths
- Adds explicit heavy-obfuscation, decompiler-failure, and class-fallback diagnostic behaviors.
- Splits assessment behavior findings into `benign`, `needs_review`, and `suspicious`.
- Assigns behavior severities (`critical`, `high`, `medium`, `low`, `info`) and reports severity counts.
- Adds verdict-tier grading: `confirmed_behavior`, `exposed_capability`, `suspicious_capability`, and `library_noise`.
- Emits contradiction/caveat notes when evidence is exposure-only (for example token access without proven automatic exfiltration).
- Suppresses or down-weights generic heuristic noise inside known bundled libraries (for example Gson, Java-WebSocket, SLF4J).
- Adds metadata sections such as `Basic Properties`, `JAR Info`, and `Bundle Info`.
- Optionally enriches metadata with `Vhash`, `SSDEEP`, `TLSH`, `TrID`, and `Magika` when local tools or libraries are available.
- Identifies suspicious artifacts such as `*.jar.*`, large opaque `.dat` or `.bin`, embedded resource payloads, and Base32-encoded embedded ZIP/JAR archives.

### Infrastructure & C2
- Resolves runtime C2 from on-chain Ethereum/Polygon `eth_call` data (smart contract → domain resolution).
- **Assembles full C2 URLs** from the resolved blockchain domain + decoded path fragments (`/shard/prefireMc`, `/shard/submitMinecraftLog`, CDN paths, etc.).
- **Live infrastructure probing**: DNS resolution + HTTP HEAD (or `Range: bytes=0-0` for CDN) on all assembled endpoints. Never downloads payloads.
- **Interactive post-scan prompt**: presents actionable C2 infrastructure, offers Y/N download + AES decryption of stage-2 encrypted blobs, and optional endpoint probing.
- **Stage-2 AES decryption**: reverse-engineered `AES/CBC/NoPadding` decryption of Zenith malware's encrypted stage-2 blob using the known key derivation (`hUvPFYp.java` → `System.arraycopy(countRef, 16, ...)`). Outputs the decrypted ZIP for static inspection only.
- Detects custom C2 HTTP header fingerprints (e.g., `X-Edge-Cache-Revalidate`, `stale-if-error`, `X-Runtime-Env`).
- Detects fallback C2 domains, payload download endpoints, and persistence install directories from decoded strings.
- Detects Python subprocess argument chains and detached process runtime indicators.
- Optionally downloads a resolved stage-2 payload JAR and performs static-only archive and content triage without executing code.
- Extracts blockchain indicators from decoded strings such as contracts, selectors, RPC hosts, and RPC URLs.
- Detects known malware variants, runs raw string detections, and applies cross-variant heuristics.
- Queries the free RatterScanner API for discovered SHA256 hashes.
- Queries the JLab public static scan API by uploading the source JAR/ZIP (when available) and includes matched signature results.
- Produces:
  - human-readable console output with optional Rich tables and progress bars
  - machine-readable JSON output
  - standalone HTML reports with clickable sortable columns
- Interactive post-scan prompt for optional stage-2 payload download + AES decryption
- Optional live infrastructure probing (DNS + HTTP HEAD) via post-scan prompt
- **Gradient banner**: renders the ASCII art banner with a purple-to-lavender color gradient in ANSI-compatible terminals.
- **Unicode-safety**: detects whether stdout/stderr support UTF-8 and adjusts Rich rendering accordingly to avoid broken output.

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
6. Optionally resolve runtime C2 hints, perform stage-2 static analysis, and enrich results with RatterScanner and JLab static scan.
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

## JLab Static Scan Enrichment

When enabled, Java Triage will attempt to upload the original source JAR/ZIP to:

- `https://jlab.threat.rip/api/public/static-scan`

Behavior details:

- Enabled by default (`--jlab-static-scan`)
- Can be disabled with `--no-jlab-static-scan`
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

```bash
python java_triage.py [target]
```

`target` is a directory path (or omitted for current directory).

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

# Disable JLab static scan enrichment
python java_triage.py ./sample_project --no-jlab-static-scan

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
- `--jlab-static-scan`: upload source JAR/ZIP to JLab public static scan API and include matched signature results (enabled by default)
- `--no-jlab-static-scan`: disable JLab public static scan lookup
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

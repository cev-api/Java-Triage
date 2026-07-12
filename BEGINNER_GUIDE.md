# Java Triage Beginner Guide

This is the "start here" guide for people who are new to the tool.

This guide assumes you are on Windows and using PowerShell.

If you only read one thing, read this:

1. Install Python.
2. Make sure `cfr-0.152.jar` is in the same folder as `java_triage.py`.
3. Put the files you want to inspect in a separate folder.
4. Run the tool on that folder.
5. Read the JSON and HTML reports, not just the console text.

## What This Tool Does

`java_triage.py` is a static triage tool for suspicious Java projects, JARs, and Minecraft mods.

It can:

- decompile JARs with CFR
- recover some obfuscated strings
- scan for suspicious URLs, commands, payloads, tokens, and persistence behavior
- generate console, JSON, and HTML reports

It does not execute the sample. It is meant for static inspection only.

## Before You Start

Use a throwaway folder or a VM if you are working with unknown files.

Safe habits:

- do not double-click unknown JARs
- do not run unknown `.exe`, `.bat`, `.cmd`, `.ps1`, or `.jar` files
- do not point the tool at your whole Downloads folder unless you really mean to
- keep suspicious samples in their own folder

## 1. Install Python

Install Python 3.10 or newer.

On Windows, the easiest path is:

1. Go to https://www.python.org/downloads/
2. Download the latest Python 3 release for Windows
3. Run the installer
4. Check `Add Python to PATH`
5. Finish the install

Quick check:

```powershell
python --version
```

If that prints a version like `Python 3.12.x`, you are good.

If `python` is not recognized, install again and make sure `Add Python to PATH` was enabled.

If `python` still does not work, try:

```powershell
py --version
```

On many Windows PCs, `py` works even when `python` does not.

## 2. Get CFR

This repo already includes `cfr-0.152.jar`, so most people do not need to install anything else.

`CFR` is the decompiler this tool uses to turn compiled Java `.class` files or `.jar` files back into readable source code. The name stands for `Class File Reader`.

That JAR should stay beside `java_triage.py` so the tool can find it.

If you need to download it yourself, get it from the official CFR home page:

https://www.benf.org/other/cfr/

Download the current JAR from there and place it in the same folder as `java_triage.py` with the same name:

```text
<your-workspace>\cfr-0.152.jar
```

The important part is that the script and CFR JAR are together in the same directory. If the JAR is missing, the tool may still run, but decompiling JARs will be much worse.

## 3. Put Files In The Right Place

Best practice: create a separate working folder for each sample or project.

Examples:

- `<your-workspace>\samples\mymod`
- `<your-workspace>\samples\suspicious_jar`
- `<your-workspace>\samples\project_root`

Inside that folder, put the files you want to inspect:

- a single `.jar`
- an unpacked Java source tree
- a folder containing Java files

Do not mix unrelated samples in the same folder if you want clean results.

## 4. Run The Tool

Open PowerShell in the repo folder and run:

```powershell
python java_triage.py <target>
```

Examples:

```powershell
# Scan a folder
python java_triage.py .\samples\mymod

# Scan the current folder
python java_triage.py

# Scan a single unpacked project
python java_triage.py .\samples\suspicious_jar
```

If you do not pass a target, the script scans the current directory.

## 5. What Happens Automatically

By default, the tool tries to help you avoid hand work:

- it looks for JARs and decompiles them with CFR when possible
- it probes for supported obfuscation patterns
- it may create a rewritten or deobfuscated copy in a new output folder
- it scans the result and writes reports

If the sample is not obfuscated in a supported way, the tool usually just scans the source tree directly.

## 6. Recommended Safe Flags

If you are inspecting unknown samples, these are the safest habits:

```powershell
python java_triage.py .\samples\mymod --no-network
```

That disables live network lookups.

Other useful safety choices:

- `--no-analyze-stage2` stops the tool from trying to fetch a second-stage payload
- JLab static-scan uploads are temporarily disabled while the service is offline
- `--no-auto-decrypt` disables automatic rewrite/decrypt behavior

For the most cautious first pass, start with `--no-network`.

## 7. Where Output Goes

The tool usually writes reports next to the scan target or into the current working folder, depending on the options you use.

Typical outputs:

- `*.json` for computer-readable results
- `*.html` for a browsable report
- console output for a quick overview
- deobfuscated or deciphered folders when rewrite features are used

Examples of output folders:

- `<target>_deobfuscated`
- `<target>_deobfuscated_2`
- `<target>_deciphered`

If a folder already exists, the tool may add `_2`, `_3`, and so on.

## 8. How To Read The Results

Start with the summary first.

What to look for:

- `benign` usually means nothing very suspicious was found
- `needs_review` means there are interesting indicators but not enough for a strong conclusion
- `suspicious` means the tool found behavior or strings that deserve closer inspection

High-value sections in the report:

- suspicious URLs or endpoints
- Discord webhooks or tokens
- command execution strings like `powershell`, `cmd.exe`, or `curl`
- persistence behavior
- payload download or stage-2 indicators
- Minecraft account, session, UUID, or access-token references
- decoded strings that were hidden by obfuscation

If you want the shortest possible answer to "is this bad?", check:

1. overall verdict
2. high-severity findings
3. behavior findings
4. raw and decoded strings
5. report artifacts and extracted URLs

## 9. What The Outputs Mean

Console output is good for a quick pass, but the JSON and HTML reports are where the useful detail lives.

JSON is best when you want to:

- grep for specific indicators
- feed results into another tool
- compare scans over time

HTML is best when you want to:

- click through findings comfortably
- sort tables
- review the scan without reading raw JSON

If the report includes:

- `runtime_c2`: the tool found a likely runtime command-and-control hint
- `url_assembly`: the tool reconstructed a full URL from pieces
- `infra_probe`: the tool tried to test a live endpoint
- `stage2_analysis`: the tool looked at a second-stage payload
- `decipher`: the tool replaced supported XOR-obfuscated strings

## 10. Good First Scan Pattern

If you are brand new, do this first:

```powershell
python java_triage.py .\samples\my-sample --no-network
```

Then open the generated HTML report and look at:

- overall verdict
- high-severity findings
- decoded strings
- suspicious URLs
- behavior evidence

After that, if you trust the environment and want deeper enrichment, rerun without `--no-network`.

## 11. Common Mistakes

- Pointing the tool at the wrong folder and scanning too much at once
- Forgetting that the tool may create extra output folders
- Assuming "no findings" means "safe"
- Running unknown code instead of inspecting it
- Leaving network features on when you want a strictly offline first pass

## 12. If Something Looks Wrong

If the tool fails or the report looks incomplete:

- check that Python is installed and available on PATH
- check that `cfr-0.152.jar` is still beside `java_triage.py`
- try a smaller target folder
- try `--no-network`
- try scanning the unpacked source tree instead of the original archive

## Quick Example

```powershell
cd "<your-workspace>"
python java_triage.py .\samples\mymod --no-network
```

Then open the generated `.html` report and use the `.json` file if you want to search or automate.

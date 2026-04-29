# cs2sign Usage Guide

Build and usage notes for `cs2sign.exe`.

The executable opens `cs2.exe` with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` and reads memory with `ReadProcessMemory`.

## What This Repository Contains

| Tool | Location | Purpose |
|------|----------|---------|
| Runtime scanner | `cs2sign\` | Scans a running `cs2.exe` for byte signatures |
| IDA plugin | `tools\ida\cs2_sig_dumper.py` | Generates fresh `*_signatures.json` files from DLLs opened in IDA |
| Read-only dumpers | `cs2sign.exe --dump-*` | Dumps schemas, interfaces, known offsets, and run info externally |
| SDK generator | `cs2sign.exe --emit-sdk` | Generates C++, C#, Rust, Zig, and IDA output from schema JSON |

## Build

Requirements:

- Windows
- Visual Studio 2025 or MSVC Build Tools with Windows SDK
- x64 target

Build the scanner:

```powershell
.\scripts\build.ps1 -Configuration Release -Platform x64
```

Scanner output path:

```text
cs2sign\x64\Release\cs2sign.exe
```

## Basic Usage

Run without arguments to open the interactive menu:

```powershell
.\cs2sign\x64\Release\cs2sign.exe
```

The menu offers:

1. Full workflow: scan signatures, run read-only dumpers, then generate SDK files.
2. Signature scan only.
3. Read-only dump only.
4. Generate SDK from existing `dump\schemas`.
5. Exit.

Before selecting a workflow, choose the console output mode. `Show detailed console logs` keeps progress output visible. `Bad Apple mode` hides logs and plays the embedded ASCII animation while scanner/dumpers run. `Q`, `Esc`, `Enter`, and `Space` stop only the animation; the selected workflow keeps running. When the dump is ready, the animation keeps looping and shows `Dump ready - press Space to view results`; `Space` opens the final summary.

Then choose the signature source. `GitHub signatures` downloads the current JSON pack from `signatures/index.json`. `Local mode` loads `*_signatures.json` files next to the exe.

For command-line or CI usage, pass explicit flags as shown below.

## Scan GitHub Signatures

GitHub is the normal scan source:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-pause
```

The downloaded files are cached under `%LOCALAPPDATA%\cs2sign\signatures` and validated against sha256 hashes from `signatures\index.json`.

To refresh the GitHub signature pack after generating new IDA JSON files, run:

```powershell
.\scripts\update-signatures.ps1
```

## Scan Local IDA Signatures

Put generated files such as `client_signatures.json` and `engine2_signatures.json` next to `cs2sign.exe`, then run:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --local-signatures --no-pause
```

Scan signatures from a specific directory:

```powershell
.\cs2sign\x64\Release\cs2sign.exe .\signatures --no-pause
```

Scan one JSON file:

```powershell
.\cs2sign\x64\Release\cs2sign.exe .\client_signatures.json --no-pause
```

## Generate Signatures With IDA

1. Open a CS2 DLL in IDA, for example `client.dll`.
2. Wait until IDA finishes analysis.
3. Run `tools\ida\cs2_sig_dumper.py`.
4. The plugin detects the loaded DLL name automatically.
5. For GitHub mode, run `.\scripts\update-signatures.ps1` after generating all module JSON files. For Local mode, put the generated `*_signatures.json` file next to `cs2sign.exe` or in a signatures directory.

Generated files:

```text
client_signatures.json
client_signatures.hpp
client_signature_report.json
client_signature_manifest.json
```

The JSON file is used by `cs2sign.exe`. The HPP file is reference output.
The report file summarizes generated/failed signatures, symbol categories, quality buckets, and failure samples.
The manifest file stores richer function metadata used for future post-update migration.

The IDA plugin starts with the `balanced` filter preset: CRT/STL/runtime symbols and thunks are skipped, while module exports and non-runtime library symbols are kept.

Available presets:

```powershell
$env:CS2SIG_FILTER_PRESET = "balanced" # default
$env:CS2SIG_FILTER_PRESET = "clean"    # stricter, fewer signatures
$env:CS2SIG_FILTER_PRESET = "broad"    # includes runtime and thunks
```

Category switches can be set before starting IDA:

```powershell
$env:CS2SIG_INCLUDE_RUNTIME = "1"
$env:CS2SIG_INCLUDE_THUNKS = "1"
$env:CS2SIG_INCLUDE_LIBRARY = "0"
```

Optional migration mode can be enabled through environment variables before starting IDA:

```powershell
$env:CS2SIG_MIGRATION_MODE = "1"
$env:CS2SIG_OLD_SIGNATURES_JSON = ".\old\client_signatures.json"
$env:CS2SIG_OLD_MANIFEST_JSON = ".\old\client_signature_manifest.json"
```

When migration mode is enabled, the plugin also writes:

```text
client_migrated_signatures.json
client_migration_report.json
```

Migration output is separate. Check `confidence`, `method`, and `quality` before replacing the normal signature file.

## Read-Only Dumpers

Run every read-only dumper and skip signature scanning:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --dump-all --output .\dump --no-pause
```

Run only schemas:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --dump-schemas --dump-info --output .\dump --no-pause
```

Run only known offsets:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --dump-offsets --dump-info --output .\dump --no-pause
```

Run only interfaces:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --dump-interfaces --dump-info --output .\dump --no-pause
```

Read-only dumper output:

```text
dump\dump_info.json
dump\interfaces.json
dump\interfaces.hpp
dump\offsets.json
dump\offsets.hpp
dump\schemas\<module>.json
dump\schemas\<module>.hpp
```

If one dumper fails after a CS2 update, the other dumpers still run. The failure is recorded in `dump_info.json`.

Generate SDK files from an existing schema dump:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --emit-sdk --output .\dump --no-pause
```

This command reads `dump\schemas\*.json` and does not require CS2 to be running.

## CLI Options

| Option | Description |
|--------|-------------|
| `--json-only` | Compatibility alias: keep built-in signatures disabled |
| `--legacy-signatures` | Also load legacy hardcoded signatures from `CS2Signatures.h` |
| `--remote-signatures` | Download generated JSON signatures from the GitHub index (default) |
| `--remote-signatures-url <url>` | Override the GitHub signature index URL |
| `--local-signatures` | Use `*_signatures.json` files from the exe/current directory |
| `--no-signatures` | Skip signature scanning and run only selected dumpers |
| `--dump-all` | Run schemas, interfaces, offsets, and info dumpers |
| `--dump-schemas` | Dump Source 2 schema classes, fields, enums, and metadata |
| `--dump-interfaces` | Dump interface registry entries from loaded modules |
| `--dump-offsets` | Dump curated known offsets through pattern scanning |
| `--dump-info` | Write timestamp, module list, build number, and dumper status |
| `--emit-sdk` | Generate `dump\sdk\cpp`, `csharp`, `rust`, `zig`, and `ida.h` from schema JSON |
| `--output <dir>` | Set read-only dumper output directory |
| `--no-pause` | Exit without waiting for a key press |
| `--help` | Print help text |

## Output Files

### `cs2_signatures.json`

Written by the signature scanner. Contains every loaded signature, whether it was found, the resolved address, scan stats, IDA-style pattern text, C++ code-style pattern text, and health metadata.

The `status` field is one of:

```text
found
missing
optional_missing
```

Required signatures affect update health. Optional signatures are still reported, but missing optional signatures do not make the dump unhealthy.

### `dump\offsets.json`

Written by `--dump-offsets`. Contains curated offsets such as `dwEntityList`, `dwGlobalVars`, `dwViewMatrix`, and `dwBuildNumber`.

### `dump\interfaces.json`

Written by `--dump-interfaces`. Contains interface names grouped by module and their resolved instance RVAs when available.

### `dump\schemas\<module>.json`

Written by `--dump-schemas`. Contains classes, fields, field offsets, enums, inheritance names, and schema metadata such as `MNetworkVarNames` and `MNetworkChangeCallback`.

### `dump\sdk\cpp\<module>.hpp`

Written by `--emit-sdk`. Contains packed C++ structs with padding, typed primitive fields where safe, original schema type comments, and `static_assert` checks for class size and field offsets.

### `dump\sdk\csharp\<module>.cs`

Written by `--emit-sdk`. Contains C# enum definitions and field offset constants.

### `dump\sdk\rust\<module>.rs`

Written by `--emit-sdk`. Contains Rust typed enum constants and field offset constants.

### `dump\sdk\zig\<module>.zig`

Written by `--emit-sdk`. Contains Zig typed enum constants and field offset constants.

### `dump\sdk\ida.h`

Written by `--emit-sdk`. Single C-style header intended for IDA local types import.

### `dump\dump_info.json`

Written by `--dump-info`. Contains timestamp, process ID, loaded modules, build number when available, and status for each dumper.

### `dump\update_report.json`

Written on every run. Contains an update health summary: required and optional signature counts, validation errors, read-only dumper status, SDK status, build number when available, and loaded modules.

Signature health is based on required signatures. Optional misses are shown for review, not counted as a hard failure.

## Recommended Workflow After a CS2 Update

1. Build the scanner.
2. Start CS2.
3. Run:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --dump-all --output .\dump --no-pause
```

4. Generate SDK files:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --emit-sdk --output .\dump --no-pause
```

5. Open updated DLLs in IDA.
6. Run `tools\ida\cs2_sig_dumper.py` for each module you care about.
7. Run `.\scripts\update-signatures.ps1` to refresh `signatures\index.json` and the repository signature pack.
8. Commit and push the updated `signatures\` directory if you want normal users to receive it through GitHub mode.
9. Run a local verification scan:

```powershell
.\cs2sign\x64\Release\cs2sign.exe .\signatures --no-pause
```

10. Check `dump\update_report.json`. If health is `degraded` or `bad`, inspect the failed offsets/signatures before publishing the dump.

## Troubleshooting

### `Failed to attach to cs2.exe`

Make sure CS2 is running. If the process still cannot be opened, check account permissions and whether another security product blocks read access.

### `No *_signatures.json files found`

GitHub signatures are the normal source. In Local mode, place generated `*_signatures.json` files next to `cs2sign.exe` or pass a directory path. Use `--legacy-signatures` only when testing the old hardcoded set.

### A known offset says `pattern not found`

The pattern is probably outdated for the current CS2 build. Re-check the pattern in IDA and update the curated pattern entry.

### Schemas fail but offsets/interfaces still work

Dumpers are isolated, so one broken category does not stop the others. Check `dump_info.json` for the exact failure.

### Generated files are missing from Git

Generated output is ignored. Commit source files, docs, and the published `signatures/` pack.

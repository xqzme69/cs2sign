# cs2sign

Read-only Counter-Strike 2 signature scanner and dumper.

`cs2sign` opens a running `cs2.exe` process with read rights, loads byte-pattern signatures, scans memory and writes results to JSON. It can also dump Source 2 schemas, interfaces and generate SDKs in multiple languages.

## Why this exists

I got tired of manually updating signatures every time a new CS2 build dropped.
Started with a small personal tool, then decided to make something more complete.

Bad Apple mode was added simply because "why not". Terminal animations are tradition.

If something doesn't work on your setup - open an issue, I'll look at it.

The repo contains the C++ scanner, the IDA signature plugin, read-only dumpers, and multi-language SDK generator.

## Features

- Pulls generated `*_signatures.json` files from `signatures/index.json` on GitHub.
- Uses WinHTTP with timeouts and retries for remote signature downloads.
- Local mode loads `*_signatures.json` files next to the executable.
- Accepts one signature JSON file or a directory path as input.
- Supports IDA-style patterns such as `48 89 5C 24 ? 57`.
- Filters scans by module when JSON entries include a `module` field.
- Supports generated `address_offset` values so signatures can match inside a function but still resolve to the function start.
- Uses `ReadProcessMemory` for target memory access.
- Can dump Source 2 schemas, interface registries, curated known offsets, and `dump_info.json` in read-only mode.
- Generates C++, C#, Rust, Zig, and IDA SDK output from schema dumps.
- Includes resolver assembly notes in `docs/asm/`.
- Tracks important maintainer targets in `tools/targets/cs2_targets.json`.
- Embeds curated known offset patterns from `tools/targets/known_offsets.json` into the executable.
- Includes a small Rust signature index checker in `tools/sigindex-checker/`.
- CI verifies the signature manifest, Windows build, SDK generation, and generated C#/Rust/Zig syntax.
- Writes schema metadata such as `MNetworkVarNames` and `MNetworkChangeCallback` when available.

## Build

Requirements:

- Windows
- Visual Studio 2025 or MSVC build tools with Windows SDK
- x64 build target

Build from PowerShell:

```powershell
.\scripts\build.ps1 -Configuration Release -Platform x64
```

Or directly with MSBuild:

```powershell
msbuild .\cs2sign\cs2sign.vcxproj /p:Configuration=Release /p:Platform=x64 /m
```

The executable is written to:

```text
cs2sign\x64\Release\cs2sign.exe
```

## Usage

Start CS2 first, then run:

```powershell
.\cs2sign\x64\Release\cs2sign.exe
```

Running the executable without arguments opens the menu. It asks for console output mode, signature source, and workflow.

`Bad Apple mode` hides scan/dump logs and plays the embedded ASCII animation while work is running. `Q`, `Esc`, `Enter`, and `Space` stop the animation only. When the dump is ready, the animation keeps looping and shows `Dump ready - press Space to view results`; `Space` opens the final summary.

GitHub signatures are the normal source. Pick Local mode when you want to test JSON files next to the exe.

Scan signatures from a directory:

```powershell
.\cs2sign\x64\Release\cs2sign.exe .\signatures
```

Scan one JSON file:

```powershell
.\cs2sign\x64\Release\cs2sign.exe .\client_signatures.json
```

Useful options:

```text
--remote-signatures
                   Download generated JSON signatures from the GitHub index (default).
--remote-signatures-url <url>
                   Override the GitHub signature index URL.
--local-signatures Use *_signatures.json files from the exe/current directory.
--no-signatures    Skip signature scanning and run only selected dumpers.
--dump-all         Run read-only schemas, interfaces, offsets, and dump_info.
--dump-schemas     Dump Source 2 schema classes/enums through ReadProcessMemory.
--dump-interfaces  Dump Source 2 interface registries through CreateInterface exports.
--dump-offsets     Dump curated known offsets through module pattern scanning.
--dump-info        Write dump_info.json with timestamp, modules, and dumper status.
--emit-sdk         Generate SDK files from dump\schemas.
--output <dir>     Output directory for read-only dumpers (default: dump).
--fail-on-degraded Exit non-zero when update health is bad or degraded.
--no-pause         Exit immediately instead of waiting for a key press.
--version          Show cs2sign version.
--help             Show usage.
```

Example for scripts/CI:

```powershell
.\cs2sign\x64\Release\cs2sign.exe .\signatures --fail-on-degraded --no-pause
```

Run only the read-only dumpers:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --dump-all --output .\dump --no-pause
```

Generate SDK files from an existing schema dump. CS2 does not need to be running for this command:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --emit-sdk --output .\dump --no-pause
```

Headless IDA runs can set `CS2SIG_OUTPUT_DIR` to choose where `*_signatures.json` files are written. Set `CS2SIG_HEADLESS=1` to exit IDA with a process exit code after the script finishes. Set `CS2SIG_NO_CPP=1`, `CS2SIG_NO_REPORT=1`, and `CS2SIG_NO_MANIFEST=1` for JSON-only automation.

## Input Format

`*_signatures.json` entries are expected to look like this:

```json
{
  "FunctionName": {
    "pattern": "48 89 5C 24 ? 57 48 83 EC 20",
    "module": "client",
    "rva": "0x1832550",
    "pattern_rva": "0x1832550",
    "pattern_offset": 0,
    "address_offset": 0,
    "length": 10,
    "display_name": "FunctionName",
    "category": "game",
    "quality": "good",
    "importance": "required",
    "required": true,
    "confidence": 100,
    "source": "ida_plugin",
    "source_project": "cs2sign"
  }
}
```

Only `pattern` is required. `ida_pattern` is accepted as a fallback, and `code_style_pattern` is accepted when it uses `\xHH` bytes with `\x2A` wildcards. Add `module` whenever possible; it keeps scans focused. `address_offset` is used when the pattern starts inside a function and should resolve back to the entry point.

Entries can also include a `resolver` object when the match should resolve to a referenced address or a field displacement instead of the match address:

```json
{
  "dwEntityList": {
    "pattern": "48 8B 0D ? ? ? ? 48 89 7C 24 ?",
    "module": "client",
    "result_type": "module_rva",
    "resolver": {
      "type": "rip_relative",
      "result_type": "module_rva",
      "instruction_offset": 0,
      "instruction_size": 7,
      "operand_offset": 3,
      "operand_size": 4,
      "add": 7
    }
  }
}
```

`string_ref` resolver entries use the `pattern` value as a literal string. The scanner finds the string in `.rdata`/`.data`, finds a RIP-relative `lea` reference in `.text`, and reports the enclosing function:

```json
{
  "CCSPlayerPawn_ctor": {
    "pattern": "CCSPlayerPawn",
    "module": "client",
    "result_type": "function_address",
    "resolver": {
      "type": "string_ref",
      "result_type": "function_address"
    }
  }
}
```

Supported resolver types are `rip_relative`, `instruction_displacement`, `direct_match`, and `string_ref`. Supported result types are `absolute_address`, `module_rva`, `field_offset`, and `function_address`.

`category`, `importance`, and `required` feed the update report. `game` and `module` signatures count as required unless the JSON says otherwise. `library`, `runtime`, `thunk`, and `auto` signatures count as optional.

CounterStrikeSharp gamedata files from `roflmuffin/CS2-Gamedata` are accepted as an input format too. Entries with `signatures.windows` are loaded as optional `function_address` signatures, using `signatures.library` as the target module. Offset-only records are skipped because they are metadata, not byte patterns. To vendor the current upstream server signatures into this repo, run:

```powershell
.\scripts\sync-counterstrikesharp-gamedata.ps1
```

## Output

Signature scan results are written to `cs2_signatures.json` in the current working directory. Each result includes `status`, `importance`, `required`, `ida_pattern`, `code_style_pattern`, `result_type`, and `resolver_status` so the dump can be reviewed or copied into C++ code more easily. Resolved functions also include a best-effort `pattern_synth` field with relocatable bytes wildcarded.

When read-only offset dumping runs after a signature scan, curated offsets stay in `dump\offsets.json` and resolved scan results are written separately to `dump\resolved_signatures.json`. RIP-relative results are stored as module RVAs, immediate displacement results are stored as field offsets, and curated offsets include validation status so bad module RVAs or unreasonable field offsets are visible in the dump.

Every run writes `dump\update_report.json` with signature health, dumper status, SDK status, build number when available, and loaded modules.

Read-only dumper output is written to `dump\` by default:

```text
dump\dump_info.json
dump\update_report.json
dump\interfaces.json
dump\interfaces.hpp
dump\offsets.json
dump\offsets.hpp
dump\resolved_signatures.json
dump\schemas\<module>.json
dump\schemas\<module>.hpp
dump\sdk\cpp\<module>.hpp
dump\sdk\csharp\<module>.cs
dump\sdk\rust\<module>.rs
dump\sdk\zig\<module>.zig
dump\sdk\ida.h
```

Those files are generated output and are ignored by git.

## Maintenance Notes

- Generated build artifacts such as `x64/`, `Win32/`, `compiled/`, `.exe`, `.pdb`, `.obj`, and `.tlog` files are ignored by git.
- The IDA plugin lives in `tools/ida/`.
- GitHub mode uses `signatures/index.json` and the matching `signatures/*_signatures.json` files.
- `tools/targets/cs2_targets.json` lists important signatures and curated known offsets that must not disappear silently.
- `tools/targets/known_offsets.json` is the source file for curated known offset scan patterns; it is embedded as a Windows resource at build time.
- `scripts\sync-counterstrikesharp-gamedata.ps1` converts `roflmuffin/CS2-Gamedata` `latest.json` into `signatures\server_signatures.json` and refreshes `signatures\index.json`.
- `scripts\import-cs2-universal-offsets.ps1` imports optional signatures from `scros22/cs2-universal-offsets` into `signatures\universal_signatures.json` and refreshes `signatures\index.json`.
- `scripts\import-dreamydumper.ps1` imports optional manual and field-offset signatures from `CBXPL/DreamyDumper` into `signatures\dreamy_signatures.json`, skips duplicate/ambiguous upstream patterns, and refreshes `signatures\index.json`.
- `scripts\compare-signatures.ps1` compares a candidate signature pack against the current published pack and fails on suspicious drops.
- `scripts\compare-scan-results.ps1` compares two `cs2_signatures.json` runtime outputs and reports added, removed, moved, status-changed, and pattern-changed entries.
- `scripts\verify-targets.ps1` validates the maintainer target registry against the published signature pack.
- `tools\sigindex-checker` is an optional Rust helper for local signature index/hash checks.
- License and third-party notices are tracked in [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Limitations

- Legacy built-in signatures are stale-prone after CS2 updates. They are disabled by default.
- The minimal JSON parser is designed for this project's generated format, not arbitrary JSON.
- The scanner reports addresses; it does not validate semantic correctness of each match.
- Use `--fail-on-degraded` in automation when missing required signatures should fail the process.
- C#, Rust, and Zig SDK files expose schema offsets as constants. The C++ SDK keeps the packed struct layout.

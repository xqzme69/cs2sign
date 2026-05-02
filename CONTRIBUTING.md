# Contributing

Thanks for contributing to `cs2sign`.

`cs2sign` is a Windows C++20 read-only Counter-Strike 2 signature scanner,
dumper, and SDK generator. Runtime access to `cs2.exe` must stay query/read-only.

## Scope

Accepted contributions usually fit one of these areas:

- Signature JSON updates and import tooling.
- Scanner correctness, resolver logic, and module filtering.
- Read-only schema, interface, known-offset, and SDK dump improvements.
- Build, CI, validation, and documentation fixes.

Changes that add injection, hooks, process memory writes, patching, anti-cheat
bypass behavior, or gameplay automation are out of scope for this repository.

## Setup

Requirements:

- Windows
- Visual Studio 2025 or MSVC build tools with Windows SDK
- PowerShell
- Rust, for the signature index checker
- Zig, only when validating Zig SDK output

Build the scanner:

```powershell
.\scripts\build.ps1 -Configuration Release -Platform x64 -Target scanner
```

Build with the VS 2022 toolset:

```powershell
.\scripts\build.ps1 -Configuration Release -Platform x64 -PlatformToolset v143 -Target scanner
```

## Validation

Run the checks that match the files you changed.

```powershell
.\scripts\verify-signatures.ps1
cargo run --locked --manifest-path .\tools\sigindex-checker\Cargo.toml -- .\signatures
.\scripts\verify-targets.ps1
.\scripts\verify-sdk.ps1
git diff --check
```

For scanner/runtime changes, also run a local scan against a running CS2 process
when possible:

```powershell
.\cs2sign\x64\Release\cs2sign.exe .\signatures --dump-all --emit-sdk --fail-on-degraded --no-pause
```

## Pull Requests

- Keep diffs focused.
- Preserve existing style and naming.
- Do not commit generated dumps, build outputs, or local research files.
- Include source/provenance links when importing community signatures.
- Update documentation when behavior, flags, outputs, or validation steps change.

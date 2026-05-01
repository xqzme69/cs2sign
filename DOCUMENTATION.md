# CS2 Signature Scanner - Documentation

## Overview

Counter-Strike 2 signature and dump tooling:

1. **IDA Plugin** (`cs2_sig_dumper.py`) — generates byte-pattern signatures from CS2 DLLs using IDA Pro
2. **C++ Runtime Scanner** (`cs2sign.exe`) — scans live CS2 process memory to find those signatures
3. **Read-Only Dumpers** (`cs2sign.exe --dump-*`) — dumps Source 2 schemas, interface registries, curated offsets, and run metadata through `ReadProcessMemory`
4. **SDK Generator** (`cs2sign.exe --emit-sdk`) — generates C++, C#, Rust, Zig, and IDA output from `dump/schemas/*.json`

```
IDA Pro + DLL files
       |
       v
  cs2_sig_dumper.py
       |
       v
  *_signatures.json
       |
       v
  signatures/index.json (GitHub) or local *_signatures.json
       |
       |
       v
  RemoteSignatureProvider / local files
       |
       v
   cs2sign.exe  <---->  cs2.exe (live process)
       |
       +--> cs2_signatures.json (signature scan results)
       |
       +--> dump/schemas/*.json + *.hpp
       +--> dump/interfaces.json + interfaces.hpp
       +--> dump/offsets.json + offsets.hpp
       +--> dump/resolved_signatures.json
       +--> dump/dump_info.json
       +--> dump/update_report.json
       |
       +--> dump/sdk/cpp/*.hpp
       +--> dump/sdk/csharp/*.cs
       +--> dump/sdk/rust/*.rs
       +--> dump/sdk/zig/*.zig
       +--> dump/sdk/ida.h

```

---

## Architecture

### Component 1: IDA Plugin (`cs2_sig_dumper.py`)

**Repository location:** `tools\ida\cs2_sig_dumper.py`

**Purpose:** Extract unique byte-pattern signatures from functions in a DLL loaded in IDA Pro.

**How it works:**

1. Iterates over all functions in the IDA database (`idautils.Functions()`)
2. For each function, reads instruction bytes from the function body
3. Marks relocatable bytes (operands that change between builds) as wildcards (`?`)
4. Finds the minimum unique pattern length. It starts with the function prefix, then tries instruction-aligned interior windows when the prefix is not unique.
5. Extends very short unique patterns with bounded stable context.
6. Adds metadata: demangled display name, category, fixed-byte count, wildcard ratio, and quality score.
7. Outputs signatures in four normal formats:
   - `{module}_signatures.json` — for the C++ scanner
   - `{module}_signatures.hpp` — C++ header with raw byte arrays
   - `{module}_signature_report.json` — review report with category/quality/failure summaries
   - `{module}_signature_manifest.json` — richer per-function metadata for post-update migration
8. Optional migration mode reads old signature/manifest files, tries exact and fuzzy matching against the newly opened DLL, and writes:
   - `{module}_migrated_signatures.json`
   - `{module}_migration_report.json`

**Module detection:**
```python
module_name = os.path.splitext(os.path.basename(idc.get_input_file_path()))[0]
```
Automatically uses the input filename (e.g., `client.dll` -> `client`, `engine2.dll` -> `engine2`).

**Output JSON format:**
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

`rva` is the function entry RVA. `pattern_rva` is where the byte pattern starts. `address_offset` is applied by the C++ scanner to resolve an interior match back to the function entry. The scanner accepts `pattern`, `ida_pattern`, or `code_style_pattern` as the source pattern.

For signatures generated from offset references, add a `resolver` object:

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

`rip_relative` resolves `match + add + displacement`. `instruction_displacement` reads the operand displacement and reports that value, which is useful for field offsets. `direct_match` keeps the old match-address behavior. `result_type` can be `absolute_address`, `module_rva`, `field_offset`, or `function_address`.

When read-only offset dumping runs after a signature scan, curated offsets stay in `dump\offsets.json` and resolved results from `cs2_signatures.json` are written to `dump\resolved_signatures.json`. Module addresses are converted to RVAs when the module is loaded; field displacements are emitted as field offsets. Curated offsets include validation status and a validation error when a result looks unsafe.

`category`, `importance`, and `required` feed scanner health. `game` and `module` are required unless the JSON says otherwise. `library`, `runtime`, `thunk`, and `auto` are optional.

**Hotkey:** Ctrl-Shift-S (when loaded as IDA plugin)

**Can also run as script:** File -> Script File in IDA

---

### Component 2: C++ Scanner (`cs2sign.exe`)

**Location:** `cs2sign\`

**Source files:**

| File | Role |
|------|------|
| `main.cpp` | Entry point, CLI/menu handling, workflow selection, update report orchestration |
| `ProcessMemoryReader.h / ProcessMemoryReader.cpp` | Process attachment, memory reading, region enumeration |
| `SignatureScanner.h / SignatureScanner.cpp` | Core scanning engine, pattern matching, multi-threading |
| `JSONParser.h / JSONParser.cpp` | Minimal JSON parser for IDA plugin output |
| `SignatureLoader.h` | Bridge: reads JSON -> adds signatures to scanner |
| `RemoteSignatureProvider.h / RemoteSignatureProvider.cpp` | Downloads and validates the GitHub signature pack, with timeouts, retries, and a local cache |
| `Console.h / Console.cpp` | Colored console output, menu prompts, animated banner |
| `BadApplePlayer.h / BadApplePlayer.cpp` | Embedded ASCII animation shown when console logs are disabled |
| `DumpUtils.h / DumpUtils.cpp` | Shared JSON/path/string/pattern/PE helpers for dumpers |
| `ExternalDumpers.h / ExternalDumpers.cpp` | Read-only schema, interface, known offset, and info dumpers |
| `SdkGenerator.h / SdkGenerator.cpp` | Generates C++, C#, Rust, Zig, and IDA SDK output from schema JSON |
| `BadAppleResources.rc` / `bad_apple_frames.bap` | Windows resource entry and compressed Bad Apple frame pack |
| `signatures/` | Published GitHub signature pack and `index.json` manifest |
| `tools/ida/cs2_sig_dumper.py` | IDA plugin that generates fresh signatures |

---

### Component 3: Read-Only Dumpers (`cs2sign.exe --dump-*`)

**Repository location:** `cs2sign\ExternalDumpers.cpp`

**Purpose:** Generate dumps without writing to or injecting into the target process.

**Available dumpers:**

| Option | Output | Purpose |
|--------|--------|---------|
| `--dump-schemas` | `dump\schemas\<module>.json/.hpp` | Source 2 schema classes, fields, enums, inheritance, and metadata |
| `--dump-interfaces` | `dump\interfaces.json/.hpp` | Interface registry entries discovered through `CreateInterface` exports |
| `--dump-offsets` | `dump\offsets.json/.hpp`, `dump\resolved_signatures.json` | Curated offsets plus resolved signature results when `cs2_signatures.json` is present |
| `--dump-info` | `dump\dump_info.json` | Timestamp, process ID, loaded modules, build number when available, and dumper status |
| `--dump-all` | all of the above | Convenience mode |

**How schema dumping works:**

1. Reads `schemasystem.dll` from the target process
2. Finds `SchemaSystem` with the read-only pattern `4C 8D 35 ? ? ? ? 0F 28 45`
3. Reads the schema type scope vector
4. Walks class and enum binding hash tables externally
5. Dumps fields, offsets, type names, base class names, enums, and metadata

Schema dumping has hard limits for total classes, fields, enums, and enum values so bad schema pointers fail early instead of producing unbounded output.

Schema metadata includes known entries such as:

- `MNetworkVarNames`
- `MNetworkChangeCallback`

**How interface dumping works:**

1. Enumerates loaded modules
2. Parses each module's PE export table
3. Finds `CreateInterface`
4. Resolves the interface registry list through RIP-relative addressing
5. Writes interface names and instance RVAs

**How known offsets work:**

1. Reads selected modules into local buffers
2. Scans curated IDA-style patterns
3. Resolves RIP-relative captures or immediate offset operands
4. Writes JSON/HPP and uses `dwBuildNumber` for `dump_info.json` when found

Each dumper is isolated: if one category fails after a CS2 update, the others still run and the failure is recorded in `dump_info.json`.

Example:

```powershell
.\cs2sign\x64\Release\cs2sign.exe --no-signatures --dump-all --output .\dump --no-pause
```

---

## Detailed File Descriptions

### main.cpp

**Initialization flow:**

1. `Console::Init()` — enable ANSI colors in Windows console
2. `Console::PrintBanner()` — animated ASCII art banner
3. Parse CLI/menu options
4. `ProcessMemoryReader::Attach("cs2.exe")` — find and attach to CS2 process
5. Resolve signatures from GitHub, or from local files when Local mode/path input is selected
6. `scanner.ScanAll()` — scan all signatures in memory
7. Print results summary
8. Output saved to `cs2_signatures.json` and `dump/update_report.json`

**Signature source logic:**

```
If argument is a directory:
    Find all *_signatures.json inside it
Else if argument is a regular file:
    Load that single file
Else if Local mode is selected:
    Find all *_signatures.json in the exe's directory
Else:
    Download signatures/index.json, validate sha256, and load cached files
```

Files must end with `_signatures.json` (e.g., `client_signatures.json`, `engine2_signatures.json`).

---

### ProcessMemoryReader.h / ProcessMemoryReader.cpp

**Key class: `ProcessMemoryReader`**

| Method | Description |
|--------|-------------|
| `Attach(processName)` | Finds process via `CreateToolhelp32Snapshot` + `Process32Next`, opens with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` |
| `ReadMemory(address, buffer, size)` | Wrapper around `ReadProcessMemory` |
| `GetMemoryRegions()` | Enumerates all committed memory regions via `VirtualQueryEx` |
| `GetProcessId()` | Returns attached process ID |
| `Detach()` | Closes process handle |

**Memory regions:**

Each region (`MemoryRegion` struct) contains:
- `baseAddress` — start address
- `size` — region size in bytes
- `protection` — Windows memory protection flags
- `module` — resolved module name via `GetModuleFileNameExW`

Only committed regions (`MEM_COMMIT`) with readable protection are enumerated.

---

### SignatureScanner.h / SignatureScanner.cpp

**Key class: `SignatureScanner`**

**Signature struct:**
```cpp
struct Signature {
    std::string name;       // Human-readable name
    std::string pattern;    // Raw byte pattern
    std::string mask;       // 'x' = match, '?' = wildcard
    std::string module;     // Target module (e.g., "client")
    std::string rva;        // Expected RVA from IDA
    int offset;             // Offset to add to found address
    bool found;             // Was it found?
    uintptr_t address;      // Found address (if any)
    std::string error;      // Error message (if any)
    int regionsScanned;     // Number of regions checked
    size_t bytesScanned;    // Total bytes read
};
```

**Adding signatures — three methods:**

1. `AddSignature(name, pattern, mask, offset)` — string-based pattern
2. `AddSignature(name, rawBytes, length, mask, offset)` — raw bytes with explicit length (for patterns containing `\x00`)
3. `AddSignatureFromIDA(name, idaPattern, module, rva, addressOffset)` — IDA-style pattern string (e.g., `"48 89 5C 24 ? 57"`)

**Pattern matching:**

`ComparePattern(memoryBytes, pattern, mask, length)`:
- For each byte position: if `mask[i] == 'x'`, the byte must match exactly
- If `mask[i] == '?'`, any byte is accepted (wildcard)

**Optimized scanning:**

`ScanPatternOptimized(region, signature)`:
1. Reads memory in 4MB chunks (with 1KB overlap between chunks)
2. Fast-path: checks first byte and second byte before full pattern comparison
3. Uses `std::atomic<bool>` for early termination when found

**Multi-threaded scanning:**

`ScanAll()`:
1. For each signature, iterates over all memory regions
2. **Module filtering**: if a signature specifies a module (e.g., `"client"`), only regions belonging to that module's DLL are scanned
3. After each signature, updates `cs2_signatures.json` with current results

**Module filtering code:**
```cpp
if (!sig.module.empty() && !region.module.empty()) {
    std::string target = sig.module + ".dll";
    // Case-insensitive comparison
    if (modLower.find(tgtLower) == std::string::npos) continue;
}
```

This is critical for performance — engine2 signatures only scan engine2.dll regions, not the entire address space.

---

### JSONParser.h / JSONParser.cpp

**Purpose:** Parse the IDA plugin's JSON output format.

**Input format:**
```json
{
  "FunctionName": {
    "pattern": "48 89 5C 24 ? 57",
    "module": "client",
    "rva": "0x1832550",
    "pattern_rva": "0x1832550",
    "pattern_offset": 0,
    "address_offset": 0,
    "length": 10
  },
  ...
}
```

**Output:** Vector of `SignatureEntry`:
```cpp
struct SignatureEntry {
    std::string name;      // Function name
    std::string pattern;   // IDA-style pattern string
    std::string module;    // Module name
    std::string rva;       // RVA string
    std::int64_t addressOffset; // Applied to the matched address
    int length;            // Pattern length
};
```

**Note:** This is a minimal hand-written JSON parser (no external dependencies like nlohmann/json). It handles the specific format produced by the IDA plugin.

---

### SignatureLoader.h

**Single function:** `LoadSignaturesFromJSON(scanner, filepath)`

1. Reads JSON file via `JSONParser::ParseFile()`
2. For each entry, calls `scanner.AddSignatureFromIDA(name, pattern, module, rva, addressOffset)`
3. Returns count of loaded signatures (or -1 on error)

---

### Console.h / Console.cpp

**Purpose:** Colorful console output with Windows console API.

**Features:**
- ANSI color support via `SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING)`
- Color enum: RED, GREEN, YELLOW, CYAN, MAGENTA, WHITE, DARK_GRAY
- `PrintBanner()` — animated "XQZME" ASCII art with magenta gradient
- `PrintHeader(title)` / `PrintFooter()` — section delimiters
- `PrintSuccess/Warning/Error/Info` — color-coded status messages
- `AnimateLine()` — per-character typing animation effect

---

## Data Flow

### Step 1: Generate Signatures (IDA Plugin)

```
IDA Pro loads client.dll
       |
       v
cs2_sig_dumper.py runs
       |
       v
For each function:
  1. Read prologue bytes
  2. Mark relocatable operands as '?'
  3. Find minimum unique prefix
  4. Store as IDA-style pattern
       |
       v
Output: client_signatures.json
        client_signatures.hpp
```

### Step 2: Scan Live Process (C++ Scanner)

```
cs2sign.exe starts
       |
       v
Attach to cs2.exe (ReadProcessMemory access)
       |
       v
Load signatures:
  1. GitHub signature pack from signatures/index.json
  2. Local *_signatures.json files — selected through Local mode/path input
       |
       v
For each signature:
  1. Filter memory regions by module (if specified)
  2. Read 4MB chunks from each region
  3. Compare pattern byte-by-byte using mask
  4. Stop on first match
       |
       v
Output: cs2_signatures.json (all results)
```

### Step 3: Results

Output JSON format:
```json
{
  "metadata": {
    "game": "Counter-Strike 2",
    "process_id": 2208,
    "total_signatures": 392,
    "scan_time": "Apr 13 2026 21:40:56"
  },
  "signatures": [
    {
      "name": "EntityList",
      "pattern": "48 8b 0d 00 00 00 00 48 85 c9 74 07",
      "ida_pattern": "48 8B 0D ? ? ? ? 48 85 C9 74 07",
      "code_style_pattern": "\\x48\\x8B\\x0D\\x2A\\x2A\\x2A\\x2A\\x48\\x85\\xC9\\x74\\x07",
      "mask": "xxx????xxxxx",
      "category": "game",
      "quality": "good",
      "importance": "required",
      "required": true,
      "status": "found",
      "confidence": 100,
      "source": "ida_plugin",
      "found": true,
      "address": "0x7FFB1F189109",
      "error": null,
      "regions_scanned": 121,
      "bytes_scanned": 2895872
    }
  ],
  "summary": {
    "found": 269,
    "missing": 123,
    "total": 392,
    "required_found": 240,
    "required_missing": 0,
    "required_total": 240,
    "optional_found": 29,
    "optional_missing": 123,
    "optional_total": 152
  }
}
```

Required signatures drive health. `optional_missing` is reported but does not fail the scan.

---

## Pattern Matching

### IDA-Style Patterns

Format: `"48 89 5C 24 ? 57 48 83 EC 20"`

- Each token is a hex byte or `?` (wildcard)
- Wildcards match any byte value
- Used for bytes that change between builds (e.g., relative offsets, stack sizes)

### Raw Byte Patterns + Mask

Format: `"\x48\x89\x5C\x24\x00\x57"` with mask `"xxxx?x"`

- `x` in mask = byte must match exactly
- `?` in mask = any byte accepted
- Required for patterns containing null bytes (`\x00`) since C strings terminate at null

### ParseIDAPattern Conversion

The `ParseIDAPattern()` function converts IDA-style to raw format:

```
Input:  "48 89 5C 24 ? 57"
Output: pattern = {0x48, 0x89, 0x5C, 0x24, 0x00, 0x57}
        mask    = "xxxx?x"
```

---

## Module-Based Filtering

When a signature specifies a module (e.g., `"client"`), the scanner only checks memory regions belonging to that module's DLL.

**Without filtering:** Each signature scans ~3300 regions / ~7.8 GB
**With filtering:** Each signature scans ~100-200 regions / ~30-200 MB

This is a ~40x performance improvement for module-specific signatures.

**How modules are resolved:**

1. `VirtualQueryEx()` returns memory region base addresses
2. `GetModuleFileNameExW()` maps base addresses to DLL file paths
3. Module name extracted from path (e.g., `C:\...\client.dll` -> `client.dll`)
4. Case-insensitive substring match against signature's module field

---

## Build System

**IDE:** Visual Studio 2025 (v18) Professional
**Toolset:** v145 (MSVC)
**Standard:** C++20
**Platform:** x64

**Build command:**
```bash
.\scripts\build.ps1 -Configuration Release -Platform x64
```

**Output paths:**
- Build output: `cs2sign\x64\Release\cs2sign.exe`
- Distribution folder, if you create one manually: `compiled\`

**Dependencies:** None (Windows SDK only, no external libraries)

---

## Maintainer Workflow After CS2 Update

When Counter-Strike 2 receives an update, function addresses and byte patterns change. End users do not need this workflow: the executable normally downloads the published GitHub signature pack. This section is for maintainers or contributors regenerating `signatures/`.

### Quick Update (Recommended)

1. Open each DLL in IDA Pro:
   - `client.dll`
   - `engine2.dll`
   - `schemasystem.dll`
   - `inputsystem.dll`
   - `soundsystem.dll`

   Function count depends on the IDA database and plugin filter preset. `balanced` skips CRT/STL/runtime symbols and thunks, but keeps module exports and non-runtime library symbols.

2. Run the plugin (Ctrl-Shift-S) on each DLL
   - Produces: `client_signatures.json`, `engine2_signatures.json`, etc.
   - Headless runs can set `CS2SIG_OUTPUT_DIR` to choose the output folder.
   - `CS2SIG_HEADLESS=1` exits IDA with a process exit code after script completion.
   - `CS2SIG_NO_CPP=1`, `CS2SIG_NO_REPORT=1`, and `CS2SIG_NO_MANIFEST=1` keep automated runs JSON-only.

3. Run `.\scripts\update-signatures.ps1` from the repository root to copy generated files into `signatures\` and refresh `signatures\index.json`

4. Maintainers can commit and publish the refreshed `signatures\` directory

5. Run `cs2sign.exe` and choose GitHub signatures, or choose Local mode for files placed next to the executable

### What Breaks on Update

| Component | Survives Update? | Why |
|-----------|-----------------|-----|
| IDA Plugin | Yes | Generates new signatures from new binaries |
| JSON Signatures | No | Addresses and byte patterns change |
| Hardcoded Signatures | No | Same reason — static byte patterns |
| Scanner Logic | Yes | Pattern matching algorithm doesn't depend on specific patterns |
| Module Filtering | Yes | Module names (client.dll, etc.) stay the same |

### Update Cycle

```
CS2 Update
    |
    v
JSON sigs break (*_signatures.json)
Legacy hardcoded sigs break if enabled
    |
    v
Re-run IDA plugin on updated DLLs, or use migration mode with the previous manifest
    |
    v
New *_signatures.json files generated
    |
    v
Refresh signatures/index.json and publish signatures/
    |
    v
Scanner downloads the new pack; update_report.json shows remaining failures
```

---

## Project Structure

```
cs2sign/
  cs2sign/
    main.cpp              # Entry point
    ProcessMemoryReader.h # Process memory access (header)
    ProcessMemoryReader.cpp # Process memory access (implementation)
    SignatureScanner.h     # Scanner engine (header)
    SignatureScanner.cpp   # Scanner engine (implementation)
    DumpUtils.h            # Shared read-only dumper utilities
    DumpUtils.cpp
    ExternalDumpers.h      # Read-only schema/interface/offset dumpers
    ExternalDumpers.cpp
    RemoteSignatureProvider.h/.cpp # GitHub signature pack download/cache
    BadApplePlayer.h/.cpp  # Console animation when logs are disabled
    BadAppleResources.rc   # Resource entry for the embedded frame pack
    bad_apple_frames.bap   # Compressed Bad Apple frame pack
    JSONParser.h           # JSON parser (header)
    JSONParser.cpp         # JSON parser (implementation)
    SignatureLoader.h      # JSON -> Scanner bridge
    Console.h              # Console output (header)
    Console.cpp            # Console output (implementation)
    cs2sign.vcxproj        # Visual Studio project file
  scripts/
    build.ps1              # Build helper
    clean.ps1              # Local artifact cleanup helper
    update-signatures.ps1  # Rebuild signatures/index.json for GitHub mode
    verify-signatures.ps1  # Validate published signature hashes and line endings
    verify-sdk.ps1         # Generate and syntax-check SDK output from fixtures
  signatures/
    index.json             # Remote signature manifest
    *_signatures.json      # Published signature files used by GitHub mode
  tests/
    sdk/schemas/           # Minimal schema fixture for SDK generator checks
  DOCUMENTATION.md
  README.md
  LICENSE
  THIRD_PARTY_NOTICES.md
  .editorconfig
  .clang-format
  .gitignore
  .gitattributes
  .github/workflows/build.yml

tools/
  ida/
    cs2_sig_dumper.py      # Recommended location for the IDA Pro plugin
```

---

## Security Notes

- The external scanner is **read-only** — it only reads process memory via `ReadProcessMemory`
- The external schema, interface, known offset, and info dumpers run in the same read-only executable
- The external scanner does not inject, hook, or modify CS2
- No `WriteProcessMemory`, `VirtualAllocEx`, `CreateRemoteThread`, or hook-installation calls are used
- The external scanner's `OpenProcess` call requests query/read rights only: `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`

---

## Known Limitations

1. **Single-threaded per signature** — while signatures are scanned sequentially, each signature scan is efficient (4MB chunks, fast-path byte checks). Multi-signature parallelism is not implemented.

2. **Console encoding** — wide string conversion `std::wstring wjf(jf.begin(), jf.end())` is lossy for non-ASCII paths. File paths with Cyrillic characters may display incorrectly in console output.

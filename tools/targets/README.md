# Target registry

`cs2_targets.json` is the maintainer-side list of important symbols that should stay covered by the published signature pack or by the curated read-only offset dumper.

`known_offsets.json` stores the curated runtime scan patterns used by the read-only offset dumper. The build embeds it into `cs2sign.exe` as a Windows resource, so end users do not need to keep the JSON file next to the executable.

The file is intentionally small and explicit. It does not replace generated `signatures/*_signatures.json`; it tells CI which entries must not silently disappear after a CS2 update.

Target fields:

- `name`: public target name.
- `module`: module key used by signature files, for example `client` or `engine2`.
- `binary`: optional DLL name for runtime-only known offsets.
- `kind`: `signature` or `known_offset`.
- `result_type`: expected output kind for offsets, such as `module_rva` or `field_offset`.
- `resolver`: expected resolver family, such as `rip_relative` or `instruction_displacement`.
- `required`: whether CI should fail when the target is missing.
- `stability`: maintainer hint, currently `stable`, `good`, `volatile`, or `experimental`.
- `source`: where the target is normally produced from.

Run validation locally:

```powershell
.\scripts\verify-targets.ps1
```

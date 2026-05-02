## Summary

- Describe the change.

## Validation

- [ ] `.\scripts\build.ps1 -Configuration Release -Platform x64 -Target scanner`
- [ ] `.\scripts\verify-signatures.ps1`
- [ ] `cargo run --locked --manifest-path .\tools\sigindex-checker\Cargo.toml -- .\signatures`
- [ ] `.\scripts\verify-targets.ps1`
- [ ] `.\scripts\verify-sdk.ps1`
- [ ] `git diff --check`

## Scope

- [ ] This keeps runtime access to `cs2.exe` read-only.
- [ ] This does not add injection, hooks, memory writes, anti-cheat bypass behavior, or gameplay automation.
- [ ] I did not commit generated dumps, build outputs, or local research files.

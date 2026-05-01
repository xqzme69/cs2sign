# Resolver assembly notes

These snippets document the two resolver forms used by the scanner. They are not build inputs.

## RIP-relative target

`rip_relative.asm` shows a common x64 form:

```asm
lea rcx, [rip + disp32]
```

The resolver reads the signed 32-bit displacement and computes:

```text
target = instruction_address + instruction_size + disp32
```

When the target belongs to a loaded module, cs2sign stores it as a module RVA.

## Field displacement

`field_offset.asm` shows an immediate displacement inside a memory operand:

```asm
inc dword ptr [rcx + 2090h]
```

The resolver reads the operand displacement and stores it as a field offset.

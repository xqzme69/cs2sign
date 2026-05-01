; Example pattern:
; 48 8D 0D ? ? ? ? 48 C1 E0 06
;
; Resolver:
; type = rip_relative
; operand_offset = 3
; instruction_size = 7

_TEXT SEGMENT
    lea rcx, [rip + 01234567h]
    shl rax, 6
_TEXT ENDS

END

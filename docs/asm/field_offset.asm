; Example pattern:
; FF 81 ? ? ? ? 48 85 D2
;
; Resolver:
; type = instruction_displacement
; operand_offset = 2
; operand_size = 4

_TEXT SEGMENT
    inc dword ptr [rcx + 2090h]
    test rdx, rdx
_TEXT ENDS

END

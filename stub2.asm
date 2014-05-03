global _start
section .text

BITS 32
org 0x0

incptr:					; command '>'
	inc edi
	nop
decptr:					; command '<'
	dec edi
	nop
incptrind:				; command '+'
	inc byte [edi]
	nop
decptrind:				; command '-'
	dec byte [edi]
	nop
incptr_mul:				; command '>>'
	add edi, 127
	nop
decptr_mul:				; command '<<'
	sub edi, 127
	nop
incptrind_mul:			; command '++'
	add byte [edi], 127
	nop
decptrind_mul:			; command '--'
	sub byte [edi], 127
	nop
_putchar:				; command '.'
	call dummy2
	nop
_getchar:				; command ','
	call dummy2
	nop
jumpzero:				; command '['
	cmp byte [edi],0
	jz near dummy2
jump:
	jmp near dummy2

dummy2:


global _start
section .text

BITS 32
org 0x401000

_start:
	; GetStdHandle(STD_INPUT_HANDLE)
	push -0x0a
	call dword [dummy]	; relocate, kernel32.dll:GetStdHandle
	mov [stdin], eax

	; GetStdHandle(STD_OUTPUT_HANDLE)
	push -0x0b
	call dword [dummy]	; relocate, kernel32.dll:GetStdHandle
	mov [stdout], eax
	mov edi, 0x403000
	; brainf*ck code start
	call main
	jmp exit

getchar:				; command ','
	; ReadFile(hStdIn, buf, 1, 0, 0)
	push edi
	push 0
	push dword len
	push 1
	push edi
	push dword [stdin]
	call dword [dummy]	; relocate, kernel32.dll:ReadFile
	pop edi
	ret

putchar:				; command '.'
	; WriteFile(hStdOut, buf, 1, 0, 0)
	push edi
	push 0
	push dword len
	push 1
	push edi
	push dword [stdout]
	call dword [dummy]	; relocate, kernel32.dll:WriteFile
	pop edi
	ret

exit:
	; ExitProcess(0)
	push 0
	call dword [dummy]	; relocate, kernel32.dll:ExitProcess
	ret

stdin:
	dd	0
stdout:
	dd	0
len:
	dd	0

main:
	ret
dummy:
	dd 0x90909090

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
_putchar:				; command '.'
	call putchar
	nop
_getchar:				; command ','
	call getchar
	nop
jumpzero:				; command '['
	cmp byte [edi],0
	jz near dummy2
jump:
	jmp near dummy2


dummy2:

global _start
section .text

BITS 32
org 0x401000

_start:
	lea ebx, [data]		; relocate, .data
	; GetStdHandle(STD_INPUT_HANDLE)
	push -0x0a
	call dword [dummy]	; relocate, kernel32.dll:GetStdHandle
	mov [ebx], eax

	; GetStdHandle(STD_OUTPUT_HANDLE)
	push -0x0b
	call dword [dummy]	; relocate, kernel32.dll:GetStdHandle
	mov [ebx+4], eax

	; VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
	push 0x04				; flProtect
	push 0x1000 | 0x100000	; flAllocationType
	push 0x10000			; dwSize
	push 0					; lpAddress
	call dword [dummy]	; relocate, kernel32.dll:VirtualAlloc
	mov edi, eax

	; brainf*ck code start
	call main
	jmp exit

getchar:				; command ','
	; ReadFile(hStdIn, buf, 1, 0, 0)
retry:
	push 0				; lpOverlapped
	lea ebx, [data]		; relocate, .data
	lea ecx, [ebx+8]
	push ecx			; lpNumberOfBytesRead
	push 1				; nNumberOfBytesToRead
	push edi			; lpBuffer
	push dword [ebx]	; hFile
	call dword [dummy]	; relocate, kernel32.dll:ReadFile

	cmp byte [edi],0x0d
	jz near retry

	ret

putchar:				; command '.'
	; WriteFile(hStdOut, buf, 1, 0, 0)

	push 0				; lpOverlapped
	lea ebx, [data]		; relocate, .data
	lea ecx, [ebx+8]
	push ecx			; lpNumberOfBytesWritten
	push 1				; nNumberOfBytesToWrite
	push edi			; lpBuffer
	push dword [ebx+4]	; hFile
	call dword [dummy]	; relocate, kernel32.dll:WriteFile

	ret

exit:
	; ExitProcess(0)
	push 0
	call dword [dummy]	; relocate, kernel32.dll:ExitProcess
	ret

main:
	ret

data:	; data section
dummy:
	dd 0x90909090
;	dd	0	; stdin handle
;	dd	0	; stdout handle
;	dd	0	; r/w length


dd getchar - 0x401000
dd putchar - 0x401000

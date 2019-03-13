[BITS 32]

global _start
section .text

start:
	; Clear regs
	xor edx,edx

	jmp short RunCommand
ReturnCommand:
	; UINT WinExec(
	;   LPCSTR lpCmdLine,
	;   UINT   uCmdShow
	; );
	pop ebx				; Put commandstring in EAX
	mov [ebx + 8], dl
	push byte +0x1			; uCmdShow = 1; SW_SHOWNORMAL in ShowWindow() API
	push ebx			; PTR to lpCmdLine
	mov ebx,0x77e6e5fd		; WinExec() Win7
	call ebx			; Call function

	xor edx,edx
	push edx

Exit:
	; ExitProcess(0)
	; void ExitProcess(
	;  UINT uExitCode
	; );
	mov eax,0x77e3214f		; ExitProcess() in kernel32.dll
	call eax			; Call function

RunCommand:
	call ReturnCommand
	db "calc.exeN"


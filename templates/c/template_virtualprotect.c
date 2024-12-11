# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <windows.h>

int main(void)
{
unsigned char shellcode[] = \

;

  DWORD run;
  BOOL ret = VirtualProtect (shellcode, strlen(shellcode),
    PAGE_EXECUTE_READWRITE, &run);

  if (!ret) {
    printf ("VirtualProtect\n");
    return EXIT_FAILURE;
  }

  printf("strlen(shellcode)=%d\n", strlen(shellcode));

  system("pause");

  ((void (*)(void))shellcode)();

  return EXIT_SUCCESS;
}

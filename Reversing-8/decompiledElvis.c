#include <stddef.h>
int main(int param_1,long param_2)

{
  long lVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  int local_4c;
  char local_48 [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28); // 0x28 is the offset of fs base pointer 
  local_48[0] = -0x4b; // represents ascii value of 'K'
  local_48[1] = -0x69; // i
  local_48[2] = -0x6e; // n
  local_48[3] = -0x67; // g
  local_48[4] = -0x43; // C
  local_48[5] = -0x72; // r
  local_48[6] = -0x65; // e
  local_48[7] = -0x6f; // o
  local_48[8] = -0x6c; // l 
  local_48[9] = -0x65; // e
  local_48[10] = '\0';
  local_48[0xb] = '\0';
  local_48[0xc] = '\0';
  local_48[0xd] = '\0';
  local_48[0xe] = '\0';
  local_48[0xf] = '\0';
  local_48[0x10] = '\0';
  local_48[0x11] = '\0';
  local_48[0x12] = '\0';
  local_48[0x13] = '\0';
  local_48[0x14] = '\0';
  local_48[0x15] = '\0';
  local_48[0x16] = '\0';
  local_48[0x17] = '\0';
  local_48[0x18] = '\0';
  local_48[0x19] = '\0';
  local_48[0x1a] = '\0';
  local_48[0x1b] = '\0';
  local_48[0x1c] = '\0';
  local_48[0x1d] = '\0';
  local_48[0x1e] = '\0';
  local_48[0x1f] = '\0';
  local_48[0x20] = '\0';
  local_48[0x21] = '\0';
  local_48[0x22] = '\0';
  local_48[0x23] = '\0';
  local_48[0x24] = '\0';
  local_48[0x25] = '\0';
  local_48[0x26] = '\0';
  local_48[0x27] = '\0';
  
  local_4c = 0;
  while( 1 ) {
    sVar2 = strlen(*(char **)(param_2 + 8));
    if (sVar2 <= (unsigned long)(long)local_4c) break;
    if ((int)local_48[local_4c] != -(int)*(char *)((long)local_4c + *(long *)(param_2 + 8))) {
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    local_4c = local_4c + 1;
  }
  puts("Well done");
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}


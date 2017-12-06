
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>


//char *input ="\x0\x0\x00\x17THIS IS A TEST STRING!\x001234567812345678\x01"
char *input ="\x00\x00\x00\x80THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!\x00""1234567812345678\x01";

char output[1000];

static void hexdump(unsigned char *buf, unsigned int len)
{
  while (len--)
    printf("%02x", *buf++);

  printf("\n");
}


int main(int argc, char **argv) {


  int fc;

  fc = open("/dev/file_crypto", O_RDWR);

  write(fc, input, 148);
  read(fc, output, 128);

  printf("\n\nOutput:\n");
  hexdump(output, 128);

  return 0;
}

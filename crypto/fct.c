#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>


//char *input ="\x0\x0\x00\x17THIS IS A TEST STRING!\x001234567812345678\x01"
char in1[200]="\x00\x00\x00\x80THIS NOTX TEST!!THIS NOTX TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!\x00""1234567812345678\x01";
char in2[200]="\x00\x00\x00\x90TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTHHHHHHHHHHHHHHHH\x00""1234567812345678\x00";


char out1[1000];
char out2[1000];

static void hexdump(unsigned char *buf, unsigned int len)
{
  while (len--)
    printf("%02x", *buf++);

  printf("\n");
}


int main(int argc, char **argv) {


  int fc;

  fc = open("/dev/file_crypto", O_RDWR);

  printf("Writing IN1\n");
  write(fc, in1, 149);
  printf("READING IN1\n");
  read(fc, out1, 128 + 16);

  //printf("\nCopy out1\n");
  memcpy(&in2[4], out1, 128+16);

  printf("Writing IN2\n");
  write(fc, in2, 149+16);
  printf("READING IN2\n");
  read(fc, out2, 128);

  printf("\n\nINPUT:\n");
  hexdump(&in1[4], 128);
  printf("OUTPUT:\n");
  hexdump(out2, 128);
  printf("\n%s\n",out2);

  return 0;
}

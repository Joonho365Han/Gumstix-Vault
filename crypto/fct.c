#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>


//char *input ="\x0\x0\x00\x17THIS IS A TEST STRING!\x001234567812345678\x01"
char in1[200]="\x00\x00\x00\x80THIS NOTX TEST!!THIS NOTX TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!\x00""1234567812345678\x01";
char in2[200]="\x00\x00\x00\x90TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTHHHHHHHHHHHHHHHH\x00""1234567812345678\x00";


char *data = "THIS IS A TEST!!";
int data_len = 16;

char *key = "1234567812345678";
int key_len = 16;

char out1[1000];
char out2[1000];


int content_size = 1024*100;
char *large_plain, *large_cipher, *large_dplain;


static void hexdump(unsigned char *buf, unsigned int len)
{
  while (len--)
    printf("%02x", *buf++);

  printf("\n");
}


int main(int argc, char **argv) {
  int fc;
  int i;

  fc = open("/dev/file_crypto", O_RDWR);

  printf("Writing IN1\n");
  write(fc, in1, 149);
  printf("READING IN1\n");
  read(fc, out1, 128 + 16);

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


  // Allocate Memory
  large_plain = (char*) malloc(4+content_size+16+1);
  large_cipher = (char*) malloc(4+content_size+16+1+16);
  large_dplain = (char*) malloc(content_size);

  // Build large input message (1MB)
  large_plain[0] = (content_size & 0xff000000) >> 24;
  large_plain[1] = (content_size & 0x00ff0000) >> 16;
  large_plain[2] = (content_size & 0x0000ff00) >> 8;
  large_plain[3] = (content_size & 0x000000ff);

  for( i = 0; i < content_size; i=i+data_len)
  {
    memcpy(&large_plain[4+i], data, data_len);
  }

  memcpy(&large_plain[4+content_size], key, key_len);

  large_plain[ 4 + content_size + key_len ] = 0x01;

  // Write plain text and read it back as cipher text

  printf("Writing Large Input\n");
  write(fc, large_plain, 4+content_size+16+1);

  // add IV length to content size
  content_size += 16;
  printf("Reading Encrypted Message\n");
  read(fc, &large_cipher[4], content_size); 

  large_cipher[0] = (content_size & 0xff000000) >> 24;
  large_cipher[1] = (content_size & 0x00ff0000) >> 16;
  large_cipher[2] = (content_size & 0x0000ff00) >> 8;
  large_cipher[3] = (content_size & 0x000000ff);

  memcpy(&large_cipher[4+content_size], key, key_len);

  large_cipher[ 4 + content_size + key_len ] = 0x00;

  printf("Writing Encrypted Message\n");
  write(fc, large_cipher, 4+content_size+key_len+1);
  
  // Subtract IV len from content_size
  content_size -= 16;
  printf("Reading Decrypted Message\n");
  read(fc, large_dplain, content_size);

  printf("Testing Files, Content Size = %d\n", content_size);
  for( i=0; i < content_size; i++)
  {
    if(large_plain[4+i] != large_dplain[i])
    {
      printf("Error: Large files are not equal at byte %d\n", i);
      return 0;
    }
  }

  printf("Files Match!\n");
 
  return 0;
}

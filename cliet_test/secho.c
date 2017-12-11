/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERV_ADDR "10.0.0.100"
#define PORTNO 81
#define MAX_FILE_SIZE = 100*1024

char in1[200]="\x00\x00\x00\x80THIS NOTX TEST!!THIS NOTX TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!\x00""1234567812345678\x01";
char raw1[200]="THIS NOTX TEST!!THIS NOTX TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!!THIS IS A TEST!\x00";
char in2[200]="\x00\x00\x00\x90TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTHHHHHHHHHHHHHHHH\x00""1234567812345678\x00";

void error(char *msg)
{
    perror(msg);
    exit(1);
}

void print_usage() {
  printf("Usage: gumstix_vault r|w file_name key\n");
}

int main(int argc, char *argv[])
{
  int sockfd, newsockfd, portno, clilen;
  char *buffer;
  int n;

  char *file_buffer;
  int file_size;
  int key_len;

  if(argc != 4)
  {
    print_usage();
    return 0;
  }

  if( *argv[1] != 'r' & *argv[1] != 'w' )
  {
    printf("arg1");
    print_usage();
    return 0;
  }

  buffer = (char*) malloc(4*1024*1024); // max file size
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  // Connect to the remote server
  struct sockaddr_in remoteaddr;
  remoteaddr.sin_family = AF_INET;
  remoteaddr.sin_addr.s_addr = inet_addr("10.0.0.100");
  remoteaddr.sin_port = htons(81);
  connect(sockfd, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr));

  if (sockfd < 0)
    error("ERROR opening socket");



  if( *argv[1] == 'w') {
    FILE *f = fopen(argv[2], "rb");
    fseek(f, 0, SEEK_END);
    int fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    int msg_size = 4 + fsize + 16 + 1;

    buffer = malloc(1 + 4 + 255);
    buffer[0] = 'C';
    buffer[1] = (msg_size & 0xff000000) >> 24;
    buffer[2] = (msg_size & 0x00ff0000) >> 16;
    buffer[3] = (msg_size & 0x0000ff00) >> 8;
    buffer[4] = (msg_size & 0x000000ff);

    strcpy(&buffer[5], argv[2]);


    n = write(sockfd, buffer, 1 + 4 + 255 );
    if (n != 1 + 4 + 255) printf("Error: Problem sending file size\n");
    free(buffer);

    // Read ready string
    buffer = malloc(100);
    n = read(sockfd, buffer, 6);
    if( n != 6) printf("Problem getting ready signal\n");
    free(buffer);

    //            [size][content][key][r|w]
    //buffer = malloc(4 + fsize + 1 + 16 + 1); // why +1 betweek content and key
    buffer = malloc(4 + fsize + 16 + 1);
    memset(buffer, 0, 4+fsize+16+1);
    fread(&buffer[4], fsize, 1, f);
    fclose(f);

    // set size
    buffer[0] = ( fsize & 0xff000000 ) >> 24;
    buffer[1] = ( fsize & 0x00ff0000 ) >> 16;
    buffer[2] = ( fsize & 0x0000ff00 ) >> 8;
    buffer[3] = fsize & 0x000000ff;

    // set key
    key_len = strlen(argv[3]);
    if (key_len > 16) key_len = 16;
    memcpy(&buffer[4+ fsize], argv[3], key_len);

    // set write
    buffer[ 4 + fsize + 16] = 1;

    n = write(sockfd, buffer, 4 + fsize + 16 + 1);
    if (n == 4 + fsize + 16 + 1 ) printf("Data Written\n");
    else printf("There was a problem writing the data");

  }
  else { // read file


    buffer = malloc( strlen(argv[2]) + 1);
    buffer[0] = 'R';
    memcpy(&buffer[1], argv[2], strlen(argv[2]));

    n = write(sockfd,buffer,strlen(argv[2]) + 1);
    if(n != strlen(argv[2]) + 1) printf("Error read: There was a problem writing the data");

    // read file size
    free(buffer);
    buffer = malloc(4);
    n = read(sockfd, buffer, 4);

    int file_size = 0;

    file_size |= buffer[0] << 24;
    file_size |= buffer[1] << 16;
    file_size |= buffer[2] << 8;
    file_size |= buffer[3];

    free(buffer);
    buffer = malloc(file_size);
    n = read(sockfd, buffer, file_size);

    FILE *f = fopen(argv[2], "wb");
    fwrite(buffer, 1, file_size, f);
    fclose(f);

  }

  return 0;
}

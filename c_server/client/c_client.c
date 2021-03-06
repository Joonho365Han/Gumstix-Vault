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
#define MAX_TRIES 100000


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
  int tries;
  int pad_len;

  char *file_buffer;
  int file_size;
  int key_len;

  if(argc != 4)
  {
    print_usage();
    return 0;
  }

  // Check for valic read/write command
  if( *argv[1] != 'r' & *argv[1] != 'w' )
  {
    printf("Error: Bad Read/Write command. Expecting 'r' or 'w'");
    print_usage();
    return 0;
  }

  // Check that file path is not to long
  if( strlen(argv[2]) > 250)
  {
    printf("Error: File name is too long! Max length is 250 charachters");
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

    // The encryption module needs file sizes in multiples of 16, so we
    // pad the input here and store how many bytes we added at the start of the
    // file. We will remove it during a read
    int original_size = fsize;
    fsize += 1; // byte to store pad len
    pad_len = 16 - ( fsize % 16);
    fsize += pad_len;

    printf("File Size: %d\n", fsize);
    int msg_size = 4 + fsize + 16 + 1;

    buffer = malloc(1 + 4 + 255);
    buffer[0] = 'C';
    buffer[1] = (msg_size & 0xff000000) >> 24;
    buffer[2] = (msg_size & 0x00ff0000) >> 16;
    buffer[3] = (msg_size & 0x0000ff00) >> 8;
    buffer[4] = (msg_size & 0x000000ff);

    strcpy(&buffer[5], argv[2]);

    printf("MSG size: %d\n%02x%02x%02x%02x\n",msg_size,buffer[1],buffer[2],buffer[3],buffer[4]);


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
    //fread(&buffer[4], fsize, 1, f);
    buffer[4] = pad_len;
    fread(&buffer[5], original_size, 1, f);
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

    n = 0;
    tries = 0;
    while( n < 4 + fsize + 16 + 1)
    {
      n += write(sockfd, &buffer[n], 4 + fsize + 16 + 1 - n );
      tries++;
      if( tries > MAX_TRIES)
      {
        printf("Error: There was a problem writing the data\n");
        printf("Exiting immediatly\n");
        return 0;
      }
    }

    printf("Data Written\n");

  }
  else { // read file

    buffer = malloc( 1 + 16 + 255 + 1 ); // + 1 for null char
    memset(buffer, 0, 1 + 16 + 255);
    buffer[0] = 'R';

    // set key
    key_len = strlen(argv[3]);
    if (key_len > 16) key_len = 16;
    memcpy(&buffer[1], argv[3], key_len);

    // set file name
    printf("file name: %s\nfile name len: %lu\n", argv[2], strlen(argv[2]));
    memcpy(&buffer[1+16], argv[2], strlen(argv[2])+1 ); // +1 for null char

    n = write(sockfd, buffer, 1 + 16 + strlen(argv[2]) + 1 );
    if(n != 1+16+strlen(argv[2]) + 1) printf("Error Read: There was a problem writing the data");
    free(buffer);

    // read file size
    buffer = malloc(4);
    n = read(sockfd, buffer, 4);
    if(n != 4) printf("Error Read: There was a problem reading the file size\n");

    int file_size = 0;

    // Get the padded file size
    file_size |= buffer[0] << 24;
    file_size |= buffer[1] << 16;
    file_size |= buffer[2] << 8;
    file_size |= buffer[3];
    free(buffer);

    printf("Incoming File Size: %d\n", file_size);

    // Get file
    buffer = malloc(file_size);
    n = 0;
    tries = 0;
    while( n < file_size )
    {
      n += read(sockfd, &buffer[n], file_size-n);
      tries++;
      if( tries > MAX_TRIES ) {
        printf("Error Read: There was a problem reading the file data\n");
        printf("Read data size: %d\n", n);
        printf("Exiting Immediatly\n");
        return 0;
      }
    }

    FILE *f = fopen(argv[2], "wb");
    // skip the pad byte and padding at the end
    printf("Pad len: %d\n", (int)buffer[0]);
    n = fwrite(&buffer[1], file_size-(int)buffer[0]-1, 1, f);
    fclose(f);

    if(n != 1) printf("Error Read: There was a problem writing the data to the local disk\n");
  }

  return 0;
}

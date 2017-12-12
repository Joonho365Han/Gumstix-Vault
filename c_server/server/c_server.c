/* A simple server in the internet domain using TCP
   The port number is passed as an argument 

   Modified to work with the Vaultstix server.

   Original Source: http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/server.c
*/
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#define MAX_TRIES 100000

void error(char *msg)
{
    perror(msg);
    exit(-1);
}

void sighandler(int i){}

void hexdump(unsigned char *buf, unsigned int len)
{
    while (len--) printf("%02x", *buf++);
    printf("\n");
}

//struct sigaction action, oa;
//int oflags;

int main(int argc, char *argv[])
{
    int n;
    int tries;

    if (argc < 2) {
        fprintf(stderr,"ERROR, no port provided\n");
        exit(-1);
    }

    //  Socket instantiation
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");

    //  Socket configuration
    int portno = atoi(argv[1]);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, &serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR on binding");

    //  Socket listening
    listen(sockfd, 1); // Socket should stay busy doing only one of C,R, or D

    //  Run socket server
    struct sockaddr_in cli_addr;
    int clilen = sizeof(cli_addr);
    while (1)
    {
        int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0)
            error("ERROR on accept");

        char *request = malloc(1 + 4 + 256);
        if (request == NULL)
            error("ERROR not enough memory");

        if (read(newsockfd, request, 1 + 4 + 256) < 0) 
            error("ERROR reading from socket");

        if (*request == 'C')
        {
            //  Find out file_size and byte_padd
            // int file_size = atoi(request+1);
            int msg_size= 0;
            msg_size |= ( (int)request[1]) << 24;
            msg_size |= ( (int)request[2]) << 16;
            msg_size |= ( (int)request[3]) << 8;
            msg_size |= ( (int)request[4]);

            char *file_name = malloc(256);
            strcpy(file_name, &request[5]);

            printf("Char: %c, MSG Size: %d\nFile Name: %s\n", request[0],msg_size,file_name);

            //  Allocate enough memory for encryption driver buffer
            free(request);
            request = malloc(msg_size);

            if (request == NULL){
                if (write(newsockfd,"ENOMEM",7) < 0)
                    error("ERROR writing to socket");

                close(newsockfd);
                continue;
            }

            //  Notify client it's ready to receive file
            if (write(newsockfd,"Ready",6) != 6)
                error("ERROR writing to socket");

            ///// Second socket receive

            //  Receive file
            n = 0;
            tries = 0;
            while( n < msg_size )
            {
              n += read(newsockfd, &request[n], msg_size-n);
              tries++;
              if ( tries > MAX_TRIES)
              {
                printf("Problem reading file\n");
                printf("Read %d, not %d\n", n, msg_size);
                error("ERROR reading from socket");
              }
            }

            //hexdump(request, msg_size);

            //  Open encryption drive
            int eFile = open("/dev/file_crypto", O_RDWR);
            if (eFile < 0)
                error("ERROR encrypt module isn't loaded");

            //  Pass file to encryptor
            if (write(eFile, request, msg_size) < 0)
                error("ERROR could not write to encryptor");
            printf("Write Done\n");

            // Close and Re open device file
            close(eFile);
            eFile = open("/dev/file_crypto", O_RDWR);
            if (eFile < 0)
                error("ERROR encrypt module isn't loaded");

            // Subtract non contentn fields, add space for IV
            printf("Reading from crypto\n");
            if (read(eFile, request, msg_size - 4 - 16 - 1 + 16) < 0)
                error("ERROR Could not read from encryptor");
            close(eFile);

            //  Open file with filename
            FILE *file = fopen(file_name, "w");
            if (file < 0)
                error("ERROR could not open file to write");

            // Store to file
            // printf("Writing %s at %d Bytes\n", filename, msg_size-4-16-1+16)
            if (fwrite(request, msg_size-4-16-1+16, 1, file) < 1 )
                error("ERROR could not store encrypted file");
            fclose(file);
        }
        else if (*request == 'R')
        {
            //  Read key and filename
            char key[16], filename[256];
            memcpy(key, request+1, 16);
            memcpy(filename, request+1+16, 256);

            printf("Request: %s\n", request);
            //hexdump(request, 1 + 16 + 256 );

            //  Open file
            FILE *file = fopen(filename, "rb");
            if (file < 0)
                error("ERROR could not open file to write");

            //  Find out file size
            struct stat filestat;
            if (stat(filename, &filestat))
                error("ERROR could not find out size of file");
            int file_size = filestat.st_size;

            printf("File Size: %d\n", file_size);

            //  Allocate enough memory for decryption driver buffer
            free(request);
            request = calloc(4+file_size+16+1, 1);
            if (request == NULL){
                if (write(newsockfd,"ENOMEM",7) < 0)
                    error("ERROR writing to socket");

                close(newsockfd);
                continue;
            }

            //  Format decryption buffer
            // Set file size
            request[0] = ( file_size & 0xff000000) >> 24;
            request[1] = ( file_size & 0x00ff0000) >> 16;
            request[2] = ( file_size & 0x0000ff00) >> 8;
            request[3] = ( file_size & 0x000000ff);

            // Fill file content
            if (fread(&request[4], file_size, 1, file) < 1)
                error("ERROR could not read encrypted file");
            fclose(file);

            // set key
            memcpy(&request[4+file_size], key, 16);

            // set decrypt flag
            request[4+file_size+16] = 0x00;

            //  Open decryption drive
            int eFile = open("/dev/file_crypto", O_RDWR);
            if (eFile < 0)
                error("ERROR encrypt module isn't loaded");

            //  Pass file to decryptor
            n = write(eFile, request, 4+file_size+16+1);
            if ( n != 4+file_size+16+1 )
              error("ERROR could not write to decryptor");
            free(request);

            // Subtract IV len from file size
            file_size -= 16;
            // Send file size
            request = malloc(4);
            request[0] = ( file_size & 0xff000000) >> 24;
            request[1] = ( file_size & 0x00ff0000) >> 16;
            request[2] = ( file_size & 0x0f00ff00) >> 8;
            request[3] = ( file_size & 0x000000ff);
            n = write(newsockfd, request, 4);
            if( n != 4)
              error("ERROR writing to socket");

            // Close and re open the device file
            close(eFile);
            eFile = open("/dev/file_crypto", O_RDWR);
            if (eFile < 0)
                error("ERROR encrypt module isn't loaded");

            //  Read decrypted data
            free(request);
            request = malloc(file_size);
            n = read(eFile, request, file_size);
            if ( n != file_size)
            {
              printf("Read error: not right amout of data returned\n");
              printf("Read %d, not %d\n", n, file_size);
              error("ERROR Could not read from decryptor");
            }
            printf("Done Reading decrypted data\n");
            close(eFile);

            printf("Decrypted Data:\n");
            hexdump(request, 16);

            //  Send file content
            printf("Sending %d Bytes of data\n",file_size);
            n = 0;
            tries = 0;
            while(n < file_size)
            {
              n += write(newsockfd, &request[n], file_size-n);
              tries++;
              if( tries > MAX_TRIES )
              {
                printf("Did not write the correct ammount of data\n");
                printf("wrote %d, not %d\n", n, file_size);
                error("ERROR writing to socket");
              }
            }
            printf("Read Complete\n");
        }

        else if (*request == 'D')
        {
            //  Read filename
            char filename[256];
            memcpy(filename, request+1, 256);

            //  Delete file
            if (remove(filename) < 0)
            {
                if (write(newsockfd, "Could not delete file ", 23) < 0)
                    error("ERROR writing to socket");

                close(newsockfd);
                continue;
            }
        }

        free(request);
        close(newsockfd);
    }

    return 0;
}

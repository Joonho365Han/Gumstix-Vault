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

void error(char *msg)
{
    perror(msg);
    exit(-1);
}

void sighandler(int i){}

int main(int argc, char *argv[])
{
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

        char *request = malloc(273);
        if (request == NULL)
            error("ERROR not enough memory");

        if (read(newsockfd, request, 273) < 0) 
            error("ERROR reading from socket");

        if (*request == 'C')
        {
            //  Find out file_size and byte_padd
            int file_size = atoi(request+1);
            int byte_padd = 16 - (file_size & 0xf);

            //  Allocate enough memory for encryption driver buffer
            free(request);
            request = malloc(sizeof(int)+file_size+byte_padd+16+1+256);
            if (request == NULL){
                if (write(newsockfd,"ENOMEM",7) < 0)
                    error("ERROR writing to socket");

                close(newsockfd);
                continue;
            }

            //  Notify client it's ready to receive file
            if (write(newsockfd,"Ready",6) < 0)
                error("ERROR writing to socket");

            ///// Second socket receive

            //  Receive file
            if (read(newsockfd,request+sizeof(int),file_size+byte_padd+16+1+255) < 0)
                error("ERROR reading from socket");

            //  Open encryption drive
            int eFile = open("/dev/encrypt", O_RDWR);
            if (eFile < 0)
                error("ERROR encrypt module isn't loaded");
            fcntl(eFile, F_SETOWN, getpid());
            fcntl(eFile, F_SETFL, fcntl(eFile, F_GETFL) | O_ASYNC);

            //  Pass file to encryptor
            *((int*) request) = file_size+byte_padd;
            if (write(eFile, request, sizeof(int)+file_size+byte_padd+16+1) < 0)
                error("ERROR could not write to encryptor");

            //  Go to sleep and wait to be awoken
            struct sigaction handler;
            sigemptyset(&handler.sa_mask);
            handler.sa_handler = sighandler;
            handler.sa_flags = SA_SIGINFO;
            sigaction(SIGIO, &handler, NULL);
            pause();

            /////  Awoke

            //  Read encrypted data + added IV
            *((int*) request) = byte_padd;
            if (read(eFile, request+sizeof(int), file_size+byte_padd+16) < 0)
                error("ERROR Could not read from encryptor");

            //  Open file with filename
            request[sizeof(int)+file_size+byte_padd+16+1+255] = '\0';
            FILE *file = fopen(request+sizeof(int)+file_size+byte_padd+16+1, "w");
            if (file < 0)
                error("ERROR could not open file to write");

            //  Store to file
            if (fwrite(request, sizeof(int)+file_size+byte_padd+16, 1, file) < sizeof(int)+file_size+byte_padd+16 )
                error("ERROR could not store encrypted file");
        }
        else if (*request == 'R')
        {
            //  Read key and filename
            char key[16], filename[256];
            memcpy(key, request+1, 16);
            memcpy(filename, request+1+16, 256);

            //  Open file
            FILE *file = fopen(filename, "r");
            if (file < 0)
                error("ERROR could not open file to write");

            //  Find out file size
            struct stat filestat;
            if (stat(filename, &filestat))
                error("ERROR could not find out size of file");
            int file_size = filestat.st_size;

            //  Allocate enough memory for decryption driver buffer
            free(request);
            request = calloc(file_size+16+1, 1);
            if (request == NULL){
                if (write(newsockfd,"ENOMEM",7) < 0)
                    error("ERROR writing to socket");

                close(newsockfd);
                continue;
            }

            //  Format decryption buffer
            if (fread(request, file_size, 1, file) < file_size)
                error("ERROR could not read encrypted file");
            int byte_padd = *((int*) request);
            *((int*) request) = file_size - sizeof(int);
            memcpy(request+file_size, key, 16);

            //  Open decryption drive
            int eFile = open("/dev/encrypt", O_RDWR);
            if (eFile < 0)
                error("ERROR encrypt module isn't loaded");
            fcntl(eFile, F_SETOWN, getpid());
            fcntl(eFile, F_SETFL, fcntl(eFile, F_GETFL) | O_ASYNC);

            //  Pass file to decryptor
            if (write(eFile, request, file_size+16+1) < 0)
                error("ERROR could not write to decryptor");

            //  Go to sleep and wait to be awoken
            struct sigaction handler;
            sigemptyset(&handler.sa_mask);
            handler.sa_handler = sighandler;
            handler.sa_flags = SA_SIGINFO;
            sigaction(SIGIO, &handler, NULL);
            pause();

            /////  Awoke

            //  Read decrypted data = filesize - sizeof(int) - padding - added IV size
            if (read(eFile, request+7, file_size - sizeof(int) - 16 - byte_padd) < 0)
                error("ERROR Could not read from decryptor");

            //  Send file content
            strncpy(request, "Success", 7);
            if (write(newsockfd, request, 7+file_size-sizeof(int)-16-byte_padd) < 0)
                error("ERROR writing to socket");
        }
        else if (*request == 'U')
        {
            //  PRepare file list buffer
            int   len   = 1;
            char *files = malloc(len);
            files[0] = '[';

            //  Open directory
            DIR *dp = opendir ("./");
            if (dp == NULL)
                error("Couldn't open the directory");
            
            //  Get file names
            struct dirent *ep;
            while (ep = readdir(dp))
            {
                int name_len = strlen(ep->d_name);
                len  += name_len + 1;
                files = realloc(files, len);
                strncpy(files+len-name_len-1, ep->d_name, name_len);
                files[len-1] = ',';
            }
            closedir (dp);

            //  Close file list
            if (files[len-1] != ',')
                files = realloc(files, ++len);
            files[len-1] = ']';

            //  Send file list
            if (write(newsockfd,files,len) < 0)
                error("ERROR writing to socket");
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

        close(newsockfd);
    }

    return 0; 
}
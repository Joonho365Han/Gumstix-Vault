/******************************************************************************
  Copyright (c) 2013 Morten Houmøller Nygaard - www.mortz.dk - admin@mortz.dk
 
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#include "Handshake.h"
#include "Communicate.h"
#include "Errors.h"

#define PORT 81

void error(char *msg)
{
    perror(msg);
	pthread_exit((void *) EXIT_FAILURE);
}

void sighandler(int i){}

ws_list *l;
int port;

/**
 * Handler to call when CTRL+C is typed. This function shuts down the server
 * in a safe way.
 */
void sigint_handler(int sig) {
	if (sig == SIGINT || sig == SIGSEGV) {
		if (l != NULL) {
			list_free(l);
			l = NULL;
		}
		(void) signal(sig, SIG_DFL);
		exit(0);
	} else if (sig == SIGPIPE) {
		(void) signal(sig, SIG_IGN);
	}
}

/**
 * Shuts down a client in a safe way. This is only used for Hybi-00.
 */
void cleanup_client(void *args) {
	ws_client *n = args;
	if (n != NULL) {
		printf("Shutting client down..\n\n> ");
		fflush(stdout);
		list_remove(l, n);
	}
}

/**
 * This function listens for input from STDIN and tries to match it to a 
 * pattern that will trigger different actions.
 */
void *cmdline(void *arg) {
	pthread_detach(pthread_self());
	(void) arg; char buffer[1024];
	
	while (1) {
		memset(buffer, '\0', 1024);
		printf("> ");
		fflush(stdout);
		fgets(buffer, 1024, stdin);
		
		if (strncasecmp(buffer, "users", 5) == 0 || 
				strncasecmp(buffer, "online", 6) == 0 ||
				strncasecmp(buffer, "clients", 7) == 0) {
			list_print(l);
			continue;
		} else if (strncasecmp(buffer, "exit", 4) == 0 || 
				strncasecmp(buffer, "quit", 4) == 0) {
			raise(SIGINT);
			break;
		} else if ( strncasecmp(buffer, "help", 4) == 0 ) {
			printf("------------------------ HELP ------------------------\n");
			printf("|   To display information about the online users,   |\n");
			printf("|   type: 'users', 'online', or 'clients'.           |\n");
			printf("|                                                    |\n");
			printf("|   To send a message to a specific user from the    |\n");
			printf("|   server type: 'send <IP> <SOCKET> <MESSAGE>' or   |\n");
			printf("|   'write <IP> <SOCKET> <MESSAGE>'.                 |\n");
			printf("|                                                    |\n");
			printf("|   To send a message to all users from the server   |\n");
			printf("|   type: 'sendall <MESSAGE>' or 'writeall           |\n");
			printf("|   <MESSAGE>'.                                      |\n");
			printf("|                                                    |\n");
 			printf("|   To kick a user from the server and close the     |\n");
			printf("|   socket connection type: 'kick <IP> <SOCKET>'     |\n");
			printf("|   or 'close <IP> <SOCKET>'.                        |\n");
			printf("|                                                    |\n"); 
 			printf("|   To kick all users from the server and close      |\n");
			printf("|   all socket connections type: 'kickall' or        |\n");
			printf("|   'closeall'.                                      |\n");
			printf("|                                                    |\n");
			printf("|   To quit the server type: 'quit' or 'exit'.       |\n");
			printf("------------------------------------------------------\n");
			fflush(stdout);
			continue;
		} else if ( strncasecmp(buffer, "kickall", 7) == 0 ||
				strncasecmp(buffer, "closeall", 8) == 0) {
			list_remove_all(l);	
		} else if ( strncasecmp(buffer, "kick", 4) == 0 ||
				strncasecmp(buffer, "close", 5) == 0) {
			char *token = strtok(buffer, " "), *addr, *sock;

			if (token != NULL) {
				token = strtok(NULL, " ");

				if (token == NULL) {
					printf("The command was executed without parameters. Type "
						   "'help' to see how to execute the command properly."
						   "\n");
					fflush(stdout);
					continue;
				} else {
					addr = token;	
				}

				token = strtok(NULL, "");

				if (token == NULL) {
					printf("The command was executed with too few parameters. Type "
						   "'help' to see how to execute the command properly."
						   "\n");
					fflush(stdout);
					continue;
				} else {
					sock = token;	
				}

				ws_client *n = list_get(l, addr, 
						strtol(sock, (char **) NULL, 10));

				if (n == NULL) {
					printf("The client that was supposed to receive the "
						   "message, was not found in the userlist.\n");
					fflush(stdout);
					continue;
				}

				ws_closeframe(n, CLOSE_SHUTDOWN);
			}
		} else if ( strncasecmp(buffer, "sendall", 7) == 0 ||
			   strncasecmp(buffer, "writeall", 8) == 0) {
			char *token = strtok(buffer, " ");
			ws_connection_close status;

			if (token != NULL) {
				token = strtok(NULL, "");

				if (token == NULL) {
					printf("The command was executed without parameters. Type "
						   "'help' to see how to execute the command properly."
						   "\n");
					fflush(stdout);
					continue;
				} else {
					ws_message *m = message_new();
					m->len = strlen(token);
					
					char *temp = malloc( sizeof(char)*(m->len+1) );
					if (temp == NULL) {
						raise(SIGINT);		
						break;
					}
					memset(temp, '\0', (m->len+1));
					memcpy(temp, token, m->len);
					m->msg = temp;
					temp = NULL;

					if ( (status = encodeMessage(m)) != CONTINUE) {
						message_free(m);
						free(m);
						raise(SIGINT);
						break;;
					}

					list_multicast_all(l, m);
					message_free(m);
					free(m);
				}
			}
		} else if ( strncasecmp(buffer, "send", 4) == 0 ||
				strncasecmp(buffer, "write", 5) == 0) {
			char *token = strtok(buffer, " "), *addr, *sock, *msg;
			ws_connection_close status;

			if (token != NULL) {
				token = strtok(NULL, " ");

				if (token == NULL) {
					printf("The command was executed without parameters. Type "
						   "'help' to see how to execute the command properly."
						   "\n");
					fflush(stdout);
					continue;
				} else {
					addr = token;	
				}

				token = strtok(NULL, " ");

				if (token == NULL) {
					printf("The command was executed with too few parameters. Type "
						   "'help' to see how to execute the command properly."
						   "\n");
					fflush(stdout);
					continue;
				} else {
					sock = token;	
				}

				token = strtok(NULL, "");
				
				if (token == NULL) {
					printf("The command was executed with too few parameters. Type "
						   "'help' to see how to execute the command properly."
						   "\n");
					fflush(stdout);
					continue;
				} else {
					msg = token;	
				}

				ws_client *n = list_get(l, addr, 
						strtol(sock, (char **) NULL, 10));

				if (n == NULL) {
					printf("The client that was supposed to receive the "
						   "message, was not found in the userlist.\n");
					fflush(stdout);
					continue;
				}

				ws_message *m = message_new();
				m->len = strlen(msg);
				
				char *temp = malloc( sizeof(char)*(m->len+1) );
				if (temp == NULL) {
					raise(SIGINT);		
					break;
				}
				memset(temp, '\0', (m->len+1));
				memcpy(temp, msg, m->len);
				m->msg = temp;
				temp = NULL;

				if ( (status = encodeMessage(m)) != CONTINUE) {
					message_free(m);
					free(m);
					raise(SIGINT);
					break;;
				}

				list_multicast_one(l, n, m);
				message_free(m);
				free(m);
			}
		} else {
			printf("To see functions available type: 'help'.\n");
			fflush(stdout);
			continue;
		}
	}

	pthread_exit((void *) EXIT_SUCCESS);
}

void *handleClient(void *args) {
	pthread_detach(pthread_self());
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	pthread_cleanup_push(&cleanup_client, args);

	int buffer_length = 0, string_length = 1, reads = 1;

	ws_client *n = args;
	n->thread_id = pthread_self();

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	char buffer[BUFFERSIZE];
	n->string = (char *) malloc(sizeof(char));

	if (n->string == NULL) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		handshake_error("Couldn't allocate memory.", ERROR_INTERNAL, n);
		pthread_exit((void *) EXIT_FAILURE);
	}

	printf("Client connected with the following information:\n"
		   "\tSocket: %d\n"
		   "\tAddress: %s\n\n", n->socket_id, (char *) n->client_ip);
	printf("Checking whether client is valid ...\n\n");
	fflush(stdout);

	/**
	 * Getting headers and doing reallocation if headers is bigger than our
	 * allocated memory.
	 */
	do {
		memset(buffer, '\0', BUFFERSIZE);
		if ((buffer_length = recv(n->socket_id, buffer, BUFFERSIZE, 0)) <= 0){
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			handshake_error("Didn't receive any headers from the client.", 
					ERROR_BAD, n);
			pthread_exit((void *) EXIT_FAILURE);
		}

		if (reads == 1 && strlen(buffer) < 14) {
			handshake_error("SSL request is not supported yet.", 
					ERROR_NOT_IMPL, n);
			pthread_exit((void *) EXIT_FAILURE);
		}

		string_length += buffer_length;

		char *tmp = realloc(n->string, string_length);
		if (tmp == NULL) {
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			handshake_error("Couldn't reallocate memory.", ERROR_INTERNAL, n);
			pthread_exit((void *) EXIT_FAILURE);
		}
		n->string = tmp;
		tmp = NULL;

		memset(n->string + (string_length-buffer_length-1), '\0', 
				buffer_length+1);
		memcpy(n->string + (string_length-buffer_length-1), buffer, 
				buffer_length);
		reads++;
	} while( strncmp("\r\n\r\n", n->string + (string_length-5), 4) != 0 
			&& strncmp("\n\n", n->string + (string_length-3), 2) != 0
			&& strncmp("\r\n\r\n", n->string + (string_length-8-5), 4) != 0
			&& strncmp("\n\n", n->string + (string_length-8-3), 2) != 0 );
	
	printf("User connected with the following headers:\n%s\n\n", n->string);
	fflush(stdout);

	ws_header *h = header_new();

	if (h == NULL) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		handshake_error("Couldn't allocate memory.", ERROR_INTERNAL, n);
		pthread_exit((void *) EXIT_FAILURE);
	}

	n->headers = h;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	if ( parseHeaders(n->string, n, port) < 0 ) {
		pthread_exit((void *) EXIT_FAILURE);
	}

	if ( sendHandshake(n) < 0 && n->headers->type != UNKNOWN ) {
		pthread_exit((void *) EXIT_FAILURE);	
	}	

	list_add(l, n);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	printf("Client has been validated and is now connected\n\n");
	printf("> ");
	fflush(stdout);

	uint64_t next_len = 0;
	char next[BUFFERSIZE];
	memset(next, '\0', BUFFERSIZE);

	while (1) {
		if ( communicate(n, next, next_len) != CONTINUE) {
			break;
		}

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			printf("Received message: %s\n", n->message->msg);

			/* SEND REPLY RIGHT HERE /////////////////////////////////////////////////////////////////////////////////// */
			char *request = n->message->enc + 11;

		        if (*request == 'C')
		        {
		        	printf("Received request: %c\n", *request);
		            // //  Find out file_size and byte_padd
		            // int file_size = atoi(request+1);
		            // int byte_padd = 16 - (file_size & 0xf);

		            // //  Allocate enough memory for encryption driver buffer
		            // free(request);
		            // request = malloc(sizeof(int)+file_size+byte_padd+16+1+256);
		            // if (request == NULL){
		            //     if (write(newsockfd,"ENOMEM",7) < 0)
		            //         error("ERROR writing to socket");

		            //     close(newsockfd);
		            //     continue;
		            // }

		            // //  Notify client it's ready to receive file
		            // if (write(newsockfd,"Ready",6) < 0)
		            //     error("ERROR writing to socket");

		            // ///// Second socket receive

		            // //  Receive file
		            // if (read(newsockfd,request+sizeof(int),file_size+byte_padd+16+1+255) < 0)
		            //     error("ERROR reading from socket");

		            // //  Open encryption drive
		            // int eFile = open("/dev/encrypt", O_RDWR);
		            // if (eFile < 0)
		            //     error("ERROR encrypt module isn't loaded");
		            // fcntl(eFile, F_SETOWN, getpid());
		            // fcntl(eFile, F_SETFL, fcntl(eFile, F_GETFL) | O_ASYNC);

		            // //  Pass file to encryptor
		            // *((int*) request) = file_size+byte_padd;
		            // if (write(eFile, request, sizeof(int)+file_size+byte_padd+16+1) < 0)
		            //     error("ERROR could not write to encryptor");

		            // //  Go to sleep and wait to be awoken
		            // struct sigaction handler;
		            // sigemptyset(&handler.sa_mask);
		            // handler.sa_handler = sighandler;
		            // handler.sa_flags = SA_SIGINFO;
		            // sigaction(SIGIO, &handler, NULL);
		            // pause();

		            // /////  Awoke

		            // //  Read encrypted data + added IV
		            // *((int*) request) = byte_padd;
		            // if (read(eFile, request+sizeof(int), file_size+byte_padd+16) < 0)
		            //     error("ERROR Could not read from encryptor");

		            // //  Open file with filename
		            // request[sizeof(int)+file_size+byte_padd+16+1+255] = '\0';
		            // FILE *file = fopen(request+sizeof(int)+file_size+byte_padd+16+1, "w");
		            // if (file < 0)
		            //     error("ERROR could not open file to write");

		            // //  Store to file
		            // if (fwrite(request, sizeof(int)+file_size+byte_padd+16, 1, file) < sizeof(int)+file_size+byte_padd+16 )
		            //     error("ERROR could not store encrypted file");
		        }
		        else if (*request == 'R')
		        {
		        	printf("Received request: %c\n", *request);
		            // //  Read key and filename
		            // char key[16], filename[256];
		            // memcpy(key, request+1, 16);
		            // memcpy(filename, request+1+16, 256);

		            // //  Open file
		            // FILE *file = fopen(filename, "r");
		            // if (file < 0)
		            //     error("ERROR could not open file to write");

		            // //  Find out file size
		            // struct stat filestat;
		            // if (stat(filename, &filestat))
		            //     error("ERROR could not find out size of file");
		            // int file_size = filestat.st_size;

		            // //  Allocate enough memory for decryption driver buffer
		            // free(request);
		            // request = calloc(file_size+16+1, 1);
		            // if (request == NULL){
		            //     if (write(newsockfd,"ENOMEM",7) < 0)
		            //         error("ERROR writing to socket");

		            //     close(newsockfd);
		            //     continue;
		            // }

		            // //  Format decryption buffer
		            // if (fread(request, file_size, 1, file) < file_size)
		            //     error("ERROR could not read encrypted file");
		            // int byte_padd = *((int*) request);
		            // *((int*) request) = file_size - sizeof(int);
		            // memcpy(request+file_size, key, 16);

		            // //  Open decryption drive
		            // int eFile = open("/dev/encrypt", O_RDWR);
		            // if (eFile < 0)
		            //     error("ERROR encrypt module isn't loaded");
		            // fcntl(eFile, F_SETOWN, getpid());
		            // fcntl(eFile, F_SETFL, fcntl(eFile, F_GETFL) | O_ASYNC);

		            // //  Pass file to decryptor
		            // if (write(eFile, request, file_size+16+1) < 0)
		            //     error("ERROR could not write to decryptor");

		            // //  Go to sleep and wait to be awoken
		            // struct sigaction handler;
		            // sigemptyset(&handler.sa_mask);
		            // handler.sa_handler = sighandler;
		            // handler.sa_flags = SA_SIGINFO;
		            // sigaction(SIGIO, &handler, NULL);
		            // pause();

		            // /////  Awoke

		            // //  Read decrypted data = filesize - sizeof(int) - padding - added IV size
		            // if (read(eFile, request+7, file_size - sizeof(int) - 16 - byte_padd) < 0)
		            //     error("ERROR Could not read from decryptor");
		        }
		        else if (*request == 'U')
		        {
		        	printf("Received request: %c\n", *request);
		            //  Prepare file list buffer
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
		                len  += 1 + name_len + 1 + 1;
		                files = realloc(files, len);
		                files[len-name_len-1-1-1] = '"';
		                strncpy(files+len-name_len-1-1, ep->d_name, name_len);
		                files[len-1-1] = '"';
		                files[len-1] = ',';
		            }
		            closedir (dp);

		            //  Close file list
		            if (files[len-1] != ',')
		                files = realloc(files, ++len);
		            files[len-1] = ']';

		            printf("File list generated: %s%c\n", files, '\0');

		            //  Replace the return message with file list.
		            n->message->enc = realloc(n->message->enc, len+12);
		            memcpy(n->message->enc + 10, files, len);
		            n->message->enc[10+len] = '}';
		            n->message->enc[10+len+1] = '\0';
		            n->message->enc_len = len + 11;

		            printf("Final message: %s\n", n->message->enc);
		        }
		        else if (*request == 'D')
		        {
		        	printf("Received request: %c\n", *request);
		            // //  Read filename
		            // char filename[256];
		            // memcpy(filename, request+1, 256);

		            // //  Delete file
		            // if (remove(filename) < 0)
		            //     memset(request,"Could not delete file ", 23);
		        }
		        else
		        {
		        	printf("Received weird request: %c\n", *request);
		            //  Replace the return message request type
		        	*request = 'X';
		        }
			/* END REPLY RIGHT HERE /////////////////////////////////////////////////////////////////////////////////// */

			list_multicast_one(l, n, n->message);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

		if (n->message != NULL) {
			memset(next, '\0', BUFFERSIZE);
			memcpy(next, n->message->next, n->message->next_len);
			next_len = n->message->next_len;
			message_free(n->message);
			free(n->message);
			n->message = NULL;	
		}
	}
	
	printf("Shutting client down..\n\n");
	printf("> ");
	fflush(stdout);

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	list_remove(l, n);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	pthread_cleanup_pop(0);
	pthread_exit((void *) EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
	int server_socket, client_socket, on = 1;
	
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_length;
	pthread_t pthread_id;
	pthread_attr_t pthread_attr;

	/**
	 * Creating new lists, l is supposed to contain the connected users.
	 */
	l = list_new();

	/**
	 * Listens for CTRL-C and Segmentation faults.
	 */ 
	(void) signal(SIGINT, &sigint_handler);
	(void) signal(SIGSEGV, &sigint_handler);
	(void) signal(SIGPIPE, &sigint_handler);


	printf("Server: \t\tStarted\n");
	fflush(stdout);

	/**
	 * Assigning port value.
	 */
	if (argc == 2) {
		port = strtol(argv[1], (char **) NULL, 10);
		
		if (port <= 1024 || port >= 65565) {
			port = PORT;
		}

	} else {
		port = PORT;	
	}

	printf("Port: \t\t\t%d\n", port);
	fflush(stdout);

	/**
	 * Opening server socket.
	 */
	if ( (server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
		server_error(strerror(errno), server_socket, l);
	}

	printf("Socket: \t\tInitialized\n");
	fflush(stdout);

	/**
	 * Allow reuse of address, when the server shuts down.
	 */
	if ( (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &on, 
					sizeof(on))) < 0 ){
		server_error(strerror(errno), server_socket, l);
	}

	printf("Reuse Port %d: \tEnabled\n", port);
	fflush(stdout);

	memset((char *) &server_addr, '\0', sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port);

	printf("Ip Address: \t\t%s\n", inet_ntoa(server_addr.sin_addr));
	fflush(stdout);

	/**
	 * Bind address.
	 */
	if ( (bind(server_socket, (struct sockaddr *) &server_addr, 
			sizeof(server_addr))) < 0 ) {
		server_error(strerror(errno), server_socket, l);
	}

	printf("Binding: \t\tSuccess\n");
	fflush(stdout);

	/**
	 * Listen on the server socket for connections
	 */
	if ( (listen(server_socket, 10)) < 0) {
		server_error(strerror(errno), server_socket, l);
	}

	printf("Listen: \t\tSuccess\n\n");
	fflush(stdout);

	/**
	 * Attributes for the threads we will create when a new client connects.
	 */
	pthread_attr_init(&pthread_attr);
	pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&pthread_attr, 524288);

	printf("Server is now waiting for clients to connect ...\n\n");
	fflush(stdout);

	/**
	 * Create commandline, such that we can do simple commands on the server.
	 */
	if ( (pthread_create(&pthread_id, &pthread_attr, cmdline, NULL)) < 0 ){
		server_error(strerror(errno), server_socket, l);
	}

	/**
	 * Do not wait for the thread to terminate.
	 */
	pthread_detach(pthread_id);

	while (1) {
		client_length = sizeof(client_addr);
		
		/**
		 * If a client connects, we observe it here.
		 */
		if ( (client_socket = accept(server_socket, 
				(struct sockaddr *) &client_addr,
				&client_length)) < 0) {
			server_error(strerror(errno), server_socket, l);
		}

		/**
		 * Save some information about the client, which we will
		 * later use to identify him with.
		 */
		char *temp = (char *) inet_ntoa(client_addr.sin_addr);
		char *addr = (char *) malloc( sizeof(char)*(strlen(temp)+1) );
		if (addr == NULL) {
			server_error(strerror(errno), server_socket, l);
			break;
		}
		memset(addr, '\0', strlen(temp)+1);
	    memcpy(addr, temp, strlen(temp));	

		ws_client *n = client_new(client_socket, addr);

		/**
		 * Create client thread, which will take care of handshake and all
		 * communication with the client.
		 */
		if ( (pthread_create(&pthread_id, &pthread_attr, handleClient, 
						(void *) n)) < 0 ){
			server_error(strerror(errno), server_socket, l);
		}

		pthread_detach(pthread_id);
	}

	list_free(l);
	l = NULL;
	close(server_socket);
	pthread_attr_destroy(&pthread_attr);
	return EXIT_SUCCESS;
}

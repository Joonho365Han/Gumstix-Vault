#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
//#include <unistd.h>

#define BUF_SIZE 128

void sighandler(int);
inline void read_encrypt( char* buf, int buf_size);

struct sigaction action, oa;

int main(int argc, char **argv) {

  char *buf;
	int eFile, sdFile, oflags;
  FILE *proc_fp;

  buf = (char*) malloc( BUF_SIZE);

loop_start:

  eFile = open("/dev/encrypt", O_RDONLY);
  if (eFile < 0) {
		fprintf (stderr, "encrypt module isn't loaded\n");
		return;
	}

	// Setup signal handler
	memset(&action, 0, sizeof(action));
	action.sa_handler = sighandler;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	sigaction(SIGIO, &action, NULL);
	fcntl(eFile, F_SETOWN, getpid());
	oflags = fcntl(eFile, F_GETFL);
	fcntl(eFile, F_SETFL, oflags | FASYNC);

	// Closes.
 	close(eFile);


	// Waits.
  printf("Pausing\n");
	pause();
  printf("Resuming\n");


  // Re open the file and read the data
  read_encrypt( buf, BUF_SIZE );

  // Write the buffer to the SD card
  sdFile = open("/root/test.txt", O_RDWR);
  if (sdFile < 0) printf("SDFILE ERROR!");
  write(sdFile, buf, BUF_SIZE);
	close(sdFile);

  goto loop_start;

}

// SIGIO handler
void sighandler(int signo)
{
  printf("SIGHANDLER!\n");
  return;
}


inline void read_encrypt( char* buf, int buf_size) {
  int eFile;

  eFile = open("/dev/encrypt", O_RDWR);
  read(eFile, buf, buf_size);
	close(eFile);

}


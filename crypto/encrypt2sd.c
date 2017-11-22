#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
//#include <unistd.h>

#define MAX_PATH_LENGTH 4096

void sighandler(int);
inline void read_encrypt( char* buf, int buf_size);
inline void read_encrypt_proc( char* file_path, int *buf_size, int *new_iv);

struct sigaction action, oa;

int main(int argc, char **argv) {

  char *buf;
  int buf_size;
  char *file_path;
  int new_iv;
	int eFile, sdFile, oflags;
  FILE *proc_fp;

  file_path = (char*)malloc ( MAX_PATH_LENGTH );

loop_start:

  //eFile = open("/dev/encrypt", O_RDONLY);
  eFile = open("/dev/encrypt", O_RDWR);
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

	// Waits.
  printf("Pausing\n");
	pause();
  printf("Resuming\n");

	// Closes.
 	close(eFile);


  // Get destination file and file length
  read_encrypt_proc( file_path, &buf_size, &new_iv);
  printf("BUF_SIZE = %d\n", buf_size);

  // Allocate memory for the buffer
  buf = (char*)malloc( buf_size );
  memset(buf,'0',buf_size);

  // Re open the file and read the data
  read_encrypt( buf, buf_size);

  // Write the buffer to the SD card
  sdFile = open( file_path, O_RDWR );
  if (sdFile < 0) printf("SDFILE ERROR!");
  write(sdFile, buf, buf_size);
	close(sdFile);
  free(buf);

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

  eFile = open("/dev/encrypt", O_RDONLY);
  read(eFile, buf, buf_size);
	close(eFile);

}

inline void read_encrypt_proc( char* file_path, int *buf_size, int *new_iv) {
  FILE *eFile;

  eFile = fopen("/proc/encrypt", "r");
  fscanf(eFile, "%*s %s %*s %d %*s %d", file_path, buf_size, new_iv);
	fclose(eFile);

}


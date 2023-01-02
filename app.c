#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include "nexus.h"

#define IOCTL_DRIVER_NAME "/dev/nexus"

int fd_ioctl;
int numwrite = 0;

int open_driver(const char* driver_name);
void close_driver(const char* driver_name, int fd_driver);

int open_driver(const char* driver_name) {

    printf("open\n");

    int fd_driver = open(driver_name, O_RDWR);
    if (fd_driver == -1) {
        printf("ERROR: could not open \"%s\".\n", driver_name);
        printf("    errno = %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

	return fd_driver;
}

void close_driver(const char* driver_name, int fd_driver) {

    printf("* Close Driver\n");

    int result = close(fd_driver);
    if (result == -1) {
        printf("ERROR: could not close \"%s\".\n", driver_name);
        printf("    errno = %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void *writer_func(void *data)
{

  const char* name = "writer thread";
  if (ioctl(fd_ioctl, NEXUS_THREAD_SPAWN, name) < 0) {
			perror("Error ioctl");
			exit(EXIT_FAILURE);
  }

  const char* text = "Test Text from thread";

  struct nexus_thread_exchange exchange;
  exchange.op = NEXUS_THREAD_WRITE;
  exchange.buffer = malloc(strlen(text));
  exchange.size = strlen(text);
  exchange.sender = getpid();
  memcpy(exchange.buffer, text, strlen(text));

  printf("write %d\n", gettid());
  
  if (ioctl(fd_ioctl, NEXUS_THREAD_OP, &exchange) < 0) {
			perror("Error write ioctl");
			printf("%d\n", gettid());
			//exit(EXIT_FAILURE);
  }


  if (ioctl(fd_ioctl, NEXUS_THREAD_EXIT, NULL) < 0) {
			perror("Error exit ioctl");
			printf("%d\n", gettid());
			//exit(EXIT_FAILURE);
  }
}

void *read_func(void *data)
{
  const char* name = "reader thread";
  if (ioctl(fd_ioctl, NEXUS_THREAD_SPAWN, name) < 0) {
			perror("Error ioctl");
			exit(EXIT_FAILURE);
  }

  const char* text = "Test Text from thread read";

  struct nexus_thread_exchange exchange_r;

  exchange_r.op = NEXUS_THREAD_READ;
  exchange_r.buffer = malloc(strlen(text));
  exchange_r.size = strlen(text);

  if (ioctl(fd_ioctl, NEXUS_THREAD_OP, &exchange_r) < 0) {
			perror("Error ioctl");
			close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
			exit(EXIT_FAILURE);
	}	

		printf("read thread %s\n", (const char*)exchange_r.buffer);

  if (ioctl(fd_ioctl, NEXUS_THREAD_EXIT, NULL) < 0) {
			perror("Error exit ioctl");
			printf("%d\n", gettid());
			//exit(EXIT_FAILURE);
  }	
}

int main(void) {

  fd_ioctl = open_driver(IOCTL_DRIVER_NAME);

  const char* text = "Test Text";


  struct nexus_thread_exchange exchange;
  struct nexus_thread_exchange exchange_r;


  exchange.op = NEXUS_THREAD_WRITE;
  exchange.buffer = malloc(strlen(text));
  exchange.size = strlen(text);
  exchange.return_code = 0xdeadbeef;
  exchange.receiver = getpid();
  memcpy(exchange.buffer, text, strlen(text));

  printf("write\n");
  
  if (ioctl(fd_ioctl, NEXUS_THREAD_OP, &exchange) < 0) {
			perror("Error ioctl");
			close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
			exit(EXIT_FAILURE);
  }


  exchange_r.op = NEXUS_THREAD_READ;
  exchange_r.buffer = malloc(strlen(text));

  if (ioctl(fd_ioctl, NEXUS_THREAD_OP, &exchange_r) < 0) {
			perror("Error ioctl");
			close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
			exit(EXIT_FAILURE);
	}	

	printf("read %s\n", (const char*)exchange_r.buffer);

	for (int i = 0; i < 25; i++) {
		pthread_t thread;
		thread = pthread_create(&thread, NULL, writer_func, (void*)getpid());
		if (thread < 0)
		{
			perror("thread create error : ");
			exit(0);
		}
	}

	for (int i = 0; i < 25; i++) {
		exchange_r.op = NEXUS_THREAD_READ;
		memset(exchange_r.buffer, 0, strlen("Test Text from thread"));

		if (ioctl(fd_ioctl, NEXUS_THREAD_OP, &exchange_r) < 0) {
			exit(EXIT_FAILURE);
		}	
		printf("thread %d from %d read %s\n", gettid(), exchange_r.return_code, (const char*)exchange_r.buffer);
	}

	//sleep(2);
	//close_driver(IOCTL_DRIVER_NAME, fd_ioctl);

	return EXIT_SUCCESS;
}




#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


/*
This program runs the specified command at the specified time

usage: exec_at <time> <command...> 
*/
int main(int argc, char *argv[])
{

	if(argc < 3) {
		printf("usage: %s <time> <command..>\n", argv[0]);
	}

        char *ptr;
        int base = 10;
        // convert input time to int
        int timeIn = strtol(argv[1], &ptr, base);

	struct timespec startTime;
        startTime.tv_sec = timeIn;
        startTime.tv_nsec = 0;

        int ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &startTime, NULL);
	if (ret != 0) {
	    fprintf(stderr, "ERROR: clock_nanosleep returned %d", ret);
	    exit(ret);
	}

	ret = execv(argv[2], argv + 2);
	if (ret != 0) {
	    int errsv = errno;
	    fprintf(stderr, "ERROR: execv failed with errno %d\n", errsv);
	    exit(ret);
	}
}

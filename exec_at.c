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

usage: exec_at <time_sec> <time_nsec> <command...> 
*/
int main(int argc, char *argv[])
{

	if(argc < 3) {
		printf("usage: %s <time_sec> <time_nsec> <command..>\n", argv[0]);
	}

        char *ptr1;
        char *ptr2;
        int base = 10;
        // convert input time to int
        int timeIn_sec = strtol(argv[1], &ptr1, base);
        int timeIn_nsec = strtol(argv[2], &ptr2, base);
        

	struct timespec startTime;
        startTime.tv_sec = timeIn_sec;
        startTime.tv_nsec = timeIn_nsec;

        int ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &startTime, NULL);
	if (ret != 0) {
	    fprintf(stderr, "ERROR: clock_nanosleep returned %d", ret);
	    exit(ret);
	}

	ret = execv(argv[3], argv + 3);
	if (ret != 0) {
	    int errsv = errno;
	    fprintf(stderr, "ERROR: execv failed with errno %d\n", errsv);
	    exit(ret);
	}
}

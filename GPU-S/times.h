#include <sys/time.h>
#include <time.h>

double get_time(void);

double get_time(void)
{
    struct timeval tv;
    double t;
    gettimeofday(&tv, (struct timezone *)0);
    t = tv.tv_sec*1000000 + tv.tv_usec; //  tv_sec 秒 long tv_usec 微秒 
    return t;
}
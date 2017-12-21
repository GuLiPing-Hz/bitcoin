#ifndef TIMEC_H___
#define TIMEC_H___

#ifdef WIN32   // Windows system specific
#include <windows.h>

static LARGE_INTEGER frequency;
#else          // Unix based system specific
#include <sys/time.h>
#endif

static double gettimedouble(void) {
#ifdef WIN32
	static int isFirst = 1;
	if (isFirst){
		QueryPerformanceFrequency(&frequency);
		isFirst = 0;
	}

	LARGE_INTEGER tv;
	QueryPerformanceCounter(&tv);

	return tv.QuadPart * (1000000.0 / frequency.QuadPart) * 0.000001;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_usec * 0.000001 + tv.tv_sec;
#endif
}
#endif//TIMEC_H___


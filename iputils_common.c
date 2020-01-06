#include <errno.h>
#include <stdarg.h>
#include <stdio_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if HAVE_GETRANDOM
# include <sys/random.h>
#endif

#ifdef HAVE_ERROR_H
# include <error.h>
#else
void error(int status, int errnum, const char *format, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", program_invocation_short_name);
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (errnum)
		fprintf(stderr, ": %s\n", strerror(errnum));
	else
		fprintf(stderr, "\n");
	if (status)
		exit(status);
}
#endif

int close_stream(FILE *stream)
{
	const int flush_status = fflush(stream);
#ifdef HAVE___FPENDING
	const int some_pending = (__fpending(stream) != 0);
#endif
	const int prev_fail = (ferror(stream) != 0);
	const int fclose_fail = (fclose(stream) != 0);

	if (flush_status ||
	    prev_fail || (fclose_fail && (
#ifdef HAVE___FPENDING
					  some_pending ||
#endif
					  errno != EBADF))) {
		if (!fclose_fail && !(errno == EPIPE))
			errno = 0;
		return EOF;
	}
	return 0;
}

void close_stdout(void)
{
	if (close_stream(stdout) != 0 && !(errno == EPIPE)) {
		if (errno)
			error(0, errno, "write error");
		else
			error(0, 0, "write error");
		_exit(EXIT_FAILURE);
	}
	if (close_stream(stderr) != 0)
		_exit(EXIT_FAILURE);
}

long strtol_or_err(char const *const str, char const *const errmesg,
		   const long min, const long max)
{
	long num;
	char *end = NULL;

	errno = 0;
	if (str == NULL || *str == '\0')
		goto err;
	num = strtol(str, &end, 10);
	if (errno || str == end || (end && *end))
		goto err;
	if (num < min || max < num)
		error(EXIT_FAILURE, 0, "%s: '%s': out of range: %lu <= value <= %lu",
		      errmesg, str,  min, max);
	return num;
 err:
	error(EXIT_FAILURE, errno, "%s: '%s'", errmesg, str);
	abort();
}

static unsigned int iputil_srand_fallback(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ((getpid() << 16) ^ getuid() ^ ts.tv_sec ^ ts.tv_nsec);
}

void iputils_srand(void)
{
	unsigned int i;
#if HAVE_GETRANDOM
	ssize_t ret;

	while ((ret = getrandom(&i, sizeof(i), GRND_NONBLOCK)) != sizeof(i)) {
		switch(errno) {
		case EINTR:
			continue;
		default:
			i = iputil_srand_fallback();
			break;
		}
	}
#else
	i = iputil_srand_fallback();
#endif
	srand(i);
	/* Consume up to 31 random numbers */
	i = rand() & 0x1F;
	while (0 < i) {
		rand();
		i--;
	}
}

void timespecsub(struct timespec *a, struct timespec *b, struct timespec *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_nsec = a->tv_nsec - b->tv_nsec;

	if (res->tv_nsec < 0) {
		res->tv_sec--;
		res->tv_nsec += 1000000000L;
	}
}

#include <errno.h>
#include <stdarg.h>
#include <stdio_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
#ifdef HAVE___FPENDING
	const int some_pending = (__fpending(stream) != 0);
#endif
	const int prev_fail = (ferror(stream) != 0);
	const int fclose_fail = (fclose(stream) != 0);

	if (prev_fail || (fclose_fail && (
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

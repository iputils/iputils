#ifndef HAVE_ERROR_H
# include <errno.h>
# include <stdarg.h>
# include <stdio.h>

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
#else
/*
 * FIXME: this can be removed when this file has some (any) content that is
 * not within preprocessor condition(s).
 */
typedef int make_iso_compilers_happy;
#endif

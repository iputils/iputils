#ifndef IPUTILS_COMMON_H
#define IPUTILS_COMMON_H

#include <stdio.h>

#define ARRAY_SIZE(arr) \
  (sizeof(arr) / sizeof((arr)[0]) + \
   sizeof(__typeof__(int[1 - 2 * \
	  !!__builtin_types_compatible_p(__typeof__(arr), \
					 __typeof__(&arr[0]))])) * 0)

#if defined(USE_IDN) || defined(ENABLE_NLS)
# include <locale.h>
#endif

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(Text) gettext (Text)
#else
# undef bindtextdomain
# define bindtextdomain(Domain, Directory) /* empty */
# undef textdomain
# define textdomain(Domain) /* empty */
# define _(Text) Text
#endif

#ifdef HAVE_ERROR_H
# include <error.h>
#else
extern void error(int status, int errnum, const char *format, ...);
#endif

extern int close_stream(FILE *stream);
extern void close_stdout(void);
extern long strtol_or_err(char const *const str, char const *const errmesg,
			  const long min, const long max);

#endif /* IPUTILS_COMMON_H */

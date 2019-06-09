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

#ifdef USE_IDN
# include <idn2.h>

# include <netdb.h>
# ifndef AI_IDN
#  define AI_IDN		0x0040
# endif
# ifndef AI_CANONIDN
#  define AI_CANONIDN		0x0080
# endif
# ifndef NI_IDN
#  define NI_IDN 32
# endif
#endif /* #ifdef USE_IDN */

#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef IP_PMTUDISC_DO
# define IP_PMTUDISC_DO		2
#endif
#ifndef IPV6_PMTUDISC_DO
# define IPV6_PMTUDISC_DO	2
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

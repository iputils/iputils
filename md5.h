#ifndef IPUTILS_MD5_H
# define IPUTILS_MD5_H

# include <stdint.h>

# define IPUTILS_MD5LENGTH 16

struct IPUTILS_MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
};

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct IPUTILS_MD5Context IPUTILS_MD5_CTX;

void iputils_MD5Init(struct IPUTILS_MD5Context *ctx);
void iputils_MD5Update(struct IPUTILS_MD5Context *ctx,
		       const char *buf, unsigned len);
void iputils_MD5Final(unsigned char digest[IPUTILS_MD5LENGTH],
		      struct IPUTILS_MD5Context *ctx);
void iputils_MD5Transform(uint32_t buf[4], uint32_t const in[16]);

#endif

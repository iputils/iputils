#ifndef IPUTILS_MD5DIG_H
#define IPUTILS_MD5DIG_H

#if defined(USE_GCRYPT)
# include <stdlib.h>
# include <gcrypt.h>
# define IPUTILS_MD5DIG_LEN	16
#elif defined(USE_NETTLE)
# include <nettle/md5.h>
#else
# include <openssl/md5.h>
#endif

#if defined(USE_GCRYPT)
typedef struct {
	gcry_md_hd_t dig;
} iputils_md5dig_ctx;

static void iputils_md5dig_init(iputils_md5dig_ctx *ctx)
{
	if (gcry_md_open(&ctx->dig, GCRY_MD_MD5, 0) != GPG_ERR_NO_ERROR)
		abort();
	return;
}

static void iputils_md5dig_update(iputils_md5dig_ctx *ctx,
			   void *buf, int len)
{
	gcry_md_write(ctx->dig, buf, len);
	return;
}

static void iputils_md5dig_final(unsigned char *digest,
				 iputils_md5dig_ctx *ctx)
{
	const void *p;
	size_t dlen;

	p = gcry_md_read(ctx->dig, GCRY_MD_MD5);
	dlen = gcry_md_get_algo_dlen(GCRY_MD_MD5);

	if (dlen != IPUTILS_MD5DIG_LEN)
		abort();

	memcpy(digest, p, dlen);

	gcry_md_close(ctx->dig);
}

# define MD5_DIGEST_LENGTH	IPUTILS_MD5DIG_LEN
# define MD5_CTX		iputils_md5dig_ctx
# define MD5_Init		iputils_md5dig_init
# define MD5_Update		iputils_md5dig_update
# define MD5_Final		iputils_md5dig_final

#elif defined(USE_NETTLE)
typedef struct md5_ctx iputils_md5dig_ctx;

static void iputils_md5dig_init(iputils_md5dig_ctx *ctx)
{
	md5_init(ctx);
	return;
}

static void iputils_md5dig_update(iputils_md5dig_ctx *ctx,
			   void *buf, int len)
{
	md5_update(ctx, len, buf);
	return;
}

static void iputils_md5dig_final(unsigned char *digest,
				 iputils_md5dig_ctx *ctx)
{
	md5_digest(ctx, MD5_DIGEST_SIZE, digest);
}

# define MD5_DIGEST_LENGTH	MD5_DIGEST_SIZE
# define MD5_CTX		iputils_md5dig_ctx
# define MD5_Init		iputils_md5dig_init
# define MD5_Update		iputils_md5dig_update
# define MD5_Final		iputils_md5dig_final
#endif

#endif

#ifndef IPUTILS_MD5DIG_H
#define IPUTILS_MD5DIG_H

#ifdef USE_GNUTLS
# include <stdlib.h>
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
# define IPUTILS_MD5DIG_LEN	16
#else
# include <openssl/md5.h>
#endif

#ifdef USE_GNUTLS
typedef struct {
	gnutls_hash_hd_t dig;
} iputils_md5dig_ctx;

static void iputils_md5dig_init(iputils_md5dig_ctx *ctx)
{
	if (gnutls_hash_init(&ctx->dig, GNUTLS_MAC_MD5))
		abort();
	return;
}

static void iputils_md5dig_update(iputils_md5dig_ctx *ctx,
			   void *buf, int len)
{
	if (gnutls_hash(ctx->dig, buf, len) < 0)
		abort();
	return;
}

static void iputils_md5dig_final(unsigned char *digest,
				 iputils_md5dig_ctx *ctx)
{
	if (gnutls_hash_get_len(GNUTLS_MAC_MD5) > IPUTILS_MD5DIG_LEN)
		abort();
	gnutls_hash_deinit(ctx->dig, digest);
}

# define MD5_DIGEST_LENGTH	IPUTILS_MD5DIG_LEN
# define MD5_CTX		iputils_md5dig_ctx
# define MD5_Init		iputils_md5dig_init
# define MD5_Update		iputils_md5dig_update
# define MD5_Final		iputils_md5dig_final
#endif
#endif

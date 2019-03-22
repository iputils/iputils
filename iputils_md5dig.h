#ifndef IPUTILS_MD5DIG_H
#define IPUTILS_MD5DIG_H

#if defined(USE_GCRYPT)
# include <stdlib.h>
# include <gcrypt.h>
# define IPUTILS_MD5DIG_LEN	16
#elif defined(USE_NETTLE)
# include <nettle/md5.h>
#elif defined(USE_OPENSSL)
# include <openssl/md5.h>
#elif defined(USE_KERNEL_CRYPTO_API)
# define IPUTILS_MD5DIG_LEN	16
# include <errno.h>
# include <linux/if_alg.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <unistd.h>
# include "iputils_common.h"
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
			   const void *buf, int len)
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
			   const void *buf, int len)
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
#elif defined(USE_KERNEL_CRYPTO_API)
typedef struct {
	int bind_sock;
	int comm_sock;
} iputils_md5dig_ctx;

static void iputils_md5dig_init(iputils_md5dig_ctx *const ctx)
{
	const struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "md5"
	};

	ctx->comm_sock = -1;
	if ((ctx->bind_sock = socket(AF_ALG, SOCK_SEQPACKET, 0)) < 0)
		return;
	if (bind(ctx->bind_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return;
	ctx->comm_sock = accept(ctx->bind_sock, NULL, 0);
	return;
}

static void iputils_md5dig_update(iputils_md5dig_ctx *ctx,
				  void const *const buf, const int len)
{
	if (ctx->comm_sock < 0)
		return;
	if (write(ctx->comm_sock, buf, len) != len)
		error(0, errno, "write to AF_ALG socket failed");
	return;
}

static void iputils_md5dig_final(unsigned char *digest,
				 iputils_md5dig_ctx const *const ctx)
{
	if (ctx->comm_sock < 0)
		return;
	if (read(ctx->comm_sock, digest, IPUTILS_MD5DIG_LEN) != IPUTILS_MD5DIG_LEN)
		error(0, errno, "read from AF_ALG socket failed");
	close(ctx->comm_sock);
	close(ctx->bind_sock);
}

# define MD5_DIGEST_LENGTH	IPUTILS_MD5DIG_LEN
# define MD5_CTX		iputils_md5dig_ctx
# define MD5_Init		iputils_md5dig_init
# define MD5_Update		iputils_md5dig_update
# define MD5_Final		iputils_md5dig_final
#endif

#endif

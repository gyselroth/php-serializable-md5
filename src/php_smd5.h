/**
 * Serializable MD5 smd5ing context
 *
 * Author: Raffael Sahli <sahli@gyselroth.com>
 *
 *
 * Initial copyright of ext/smd5:
 *
 * Copyright (c) The PHP Group
 * Author: Sara Golemon <pollita@php.net>
 */

#include "php.h"
#include "ext/standard/md5.h"

#define PHP_SMD5_EXTNAME	"smd5"
#define PHP_SMD5_VERSION	"1.0.0"

#define L64 INT64_C

typedef struct _php_smd5_ops {
	size_t digest_size;
	size_t block_size;
	size_t context_size;
	unsigned is_crypto: 1;
} php_smd5_ops;

typedef struct _php_smd5context_object {
	const php_smd5_ops *ops;
	PHP_MD5_CTX *context;

	zend_long options;
	unsigned char *key;

	zend_object std;
} php_smd5context_object;

static inline php_smd5context_object *php_smd5context_from_object(zend_object *obj) {
	return ((php_smd5context_object*)(obj + 1)) - 1;
}

extern const php_smd5_ops php_smd5_md5_ops;
extern zend_module_entry smd5_module_entry;
#define phpext_smd5_ptr &smd5_module_entry

#ifdef PHP_WIN32
#	define PHP_SMD5_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SMD5_API __attribute__ ((visibility("default")))
#else
#	define PHP_SMD5_API
#endif

PHP_FUNCTION(md5_init);
PHP_FUNCTION(md5_update);
PHP_FUNCTION(md5_update_stream);
PHP_FUNCTION(md5_final);


extern PHP_SMD5_API zend_class_entry *php_smd5context_ce;
PHP_SMD5_API const php_smd5_ops *php_smd5_fetch_ops(const char *algo, size_t algo_len);
PHP_SMD5_API void php_smd5_register_algo(const char *algo, const php_smd5_ops *ops);
PHP_SMD5_API int php_md5_copy(const void *ops, void *orig_context, void *dest_context);

static inline void php_smd5_bin2hex(char *out, const unsigned char *in, size_t in_len)
{
	static const char hexits[17] = "0123456789abcdef";
	size_t i;

	for(i = 0; i < in_len; i++) {
		out[i * 2]       = hexits[in[i] >> 4];
		out[(i * 2) + 1] = hexits[in[i] &  0x0F];
	}
}

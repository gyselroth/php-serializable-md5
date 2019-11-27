/**
 * Serializable MD5 hashing context
 *
 * Author: Raffael Sahli <sahli@gyselroth.com>
 *
 *
 * Initial copyright of ext/hash:
 *
 * Copyright (c) The PHP Group
 * Author: Sara Golemon <pollita@php.net>
 */

#include "php.h"
#include "ext/standard/md5.h"

#define PHP_SMD5_EXTNAME	"smd5"
#define PHP_SMD5_VERSION	PHP_VERSION

#define L64 INT64_C

typedef struct _php_hash_ops {
	size_t digest_size;
	size_t block_size;
	size_t context_size;
	unsigned is_crypto: 1;
} php_hash_ops;

typedef struct _php_hashcontext_object {
	const php_hash_ops *ops;
	PHP_MD5_CTX *context;

	zend_long options;
	unsigned char *key;

	zend_object std;
} php_hashcontext_object;

static inline php_hashcontext_object *php_hashcontext_from_object(zend_object *obj) {
	return ((php_hashcontext_object*)(obj + 1)) - 1;
}

extern const php_hash_ops php_hash_md5_ops;
extern zend_module_entry hash_module_entry;
#define phpext_hash_ptr &hash_module_entry

#ifdef PHP_WIN32
#	define PHP_HASH_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_HASH_API __attribute__ ((visibility("default")))
#else
#	define PHP_HASH_API
#endif

PHP_FUNCTION(md5_init);
PHP_FUNCTION(md5_update);
PHP_FUNCTION(md5_update_stream);
PHP_FUNCTION(md5_final);


extern PHP_HASH_API zend_class_entry *php_hashcontext_ce;
PHP_HASH_API const php_hash_ops *php_hash_fetch_ops(const char *algo, size_t algo_len);
PHP_HASH_API void php_hash_register_algo(const char *algo, const php_hash_ops *ops);
PHP_HASH_API int php_md5_copy(const void *ops, void *orig_context, void *dest_context);

static inline void php_hash_bin2hex(char *out, const unsigned char *in, size_t in_len)
{
	static const char hexits[17] = "0123456789abcdef";
	size_t i;

	for(i = 0; i < in_len; i++) {
		out[i * 2]       = hexits[in[i] >> 4];
		out[(i * 2) + 1] = hexits[in[i] &  0x0F];
	}
}

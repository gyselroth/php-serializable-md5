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
 *         Scott MacVicar <scottmac@php.net>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include "php_hash.h"
#include "ext/standard/info.h"
#include "ext/standard/file.h"

#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "ext/spl/spl_exceptions.h"

#include "hash_arginfo.h"

HashTable php_hash_hashtable;
zend_class_entry *php_hashcontext_ce;
static zend_object_handlers php_hashcontext_handlers;

/* Hash Registry Access */

PHP_HASH_API const php_hash_ops *php_hash_fetch_ops(const char *algo, size_t algo_len) /* {{{ */
{
	char *lower = zend_str_tolower_dup(algo, algo_len);
	php_hash_ops *ops = zend_hash_str_find_ptr(&php_hash_hashtable, lower, algo_len);
	efree(lower);

	return ops;
}
/* }}} */

PHP_HASH_API void php_hash_register_algo(const char *algo, const php_hash_ops *ops) /* {{{ */
{
	size_t algo_len = strlen(algo);
	char *lower = zend_str_tolower_dup(algo, algo_len);
	zend_hash_add_ptr(&php_hash_hashtable, zend_string_init_interned(lower, algo_len, 1), (void *) ops);
	efree(lower);
}
/* }}} */

PHP_HASH_API int php_md5_copy(const void *ops, void *orig_context, void *dest_context) /* {{{ */
{
	php_hash_ops *hash_ops = (php_hash_ops *)ops;

	memcpy(dest_context, orig_context, hash_ops->context_size);
	return SUCCESS;
}
/* }}} */

static inline void php_hash_string_xor_char(unsigned char *out, const unsigned char *in, const unsigned char xor_with, const size_t length) {
	size_t i;
	for (i=0; i < length; i++) {
		out[i] = in[i] ^ xor_with;
	}
}

static inline void php_hash_string_xor(unsigned char *out, const unsigned char *in, const unsigned char *xor_with, const size_t length) {
	size_t i;
	for (i=0; i < length; i++) {
		out[i] = in[i] ^ xor_with[i];
	}
}

/* {{{ proto MD5Context md5_init(string algo[, int options, string key])
Initialize a hashing context */
PHP_FUNCTION(md5_init)
{
	zend_string *algo, *key = NULL;
	zend_long options = 0;
	int argc = ZEND_NUM_ARGS();
	void *context;
	const php_hash_ops *ops;
	php_hashcontext_object *hash;

	ops = php_hash_fetch_ops("md5", 3);
	object_init_ex(return_value, php_hashcontext_ce);
	hash = php_hashcontext_from_object(Z_OBJ_P(return_value));

	context = emalloc(ops->context_size);
	PHP_MD5Init(context);

	hash->ops = ops;
	hash->context = context;
	hash->options = options;
	hash->key = NULL;
}
/* }}} */

#define PHP_HASHCONTEXT_VERIFY(func, hash) { \
	if (!hash->context) { \
		zend_throw_error(NULL, "%s(): supplied resource is not a valid Hash Context resource", func); \
		return; \
	} \
}

/* {{{ proto bool md5_update(MD5Context context, string data)
Pump data into the hashing algorithm */
PHP_FUNCTION(md5_update)
{
	zval *zhash;
	php_hashcontext_object *hash;
	zend_string *data;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "OS", &zhash, php_hashcontext_ce, &data) == FAILURE) {
		return;
	}

	hash = php_hashcontext_from_object(Z_OBJ_P(zhash));
	PHP_HASHCONTEXT_VERIFY("md5_update", hash);
	PHP_MD5Update(hash->context, (unsigned char *) ZSTR_VAL(data), ZSTR_LEN(data));

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto int md5_update_stream(MD5Context context, resource handle[, int length])
Pump data into the hashing algorithm from an open stream */
PHP_FUNCTION(md5_update_stream)
{
	zval *zhash, *zstream;
	php_hashcontext_object *hash;
	php_stream *stream = NULL;
	zend_long length = -1, didread = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "Or|l", &zhash, php_hashcontext_ce, &zstream, &length) == FAILURE) {
		return;
	}

	hash = php_hashcontext_from_object(Z_OBJ_P(zhash));
	PHP_HASHCONTEXT_VERIFY("md5_update_stream", hash);
	php_stream_from_zval(stream, zstream);

	while (length) {
		char buf[1024];
		zend_long toread = 1024;
		ssize_t n;

		if (length > 0 && toread > length) {
			toread = length;
		}

		if ((n = php_stream_read(stream, buf, toread)) <= 0) {
			RETURN_LONG(didread);
		}

		PHP_MD5Update(hash->context, (unsigned char *) buf, n);
		length -= n;
		didread += n;
	}

	RETURN_LONG(didread);
}
/* }}} */

/* {{{ proto string md5_final(MD5Context context[, bool raw_output=false])
Output resulting digest */
PHP_FUNCTION(md5_final)
{
	zval *zhash;
	php_hashcontext_object *hash;
	zend_bool raw_output = 0;
	zend_string *digest;
	size_t digest_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "O|b", &zhash, php_hashcontext_ce, &raw_output) == FAILURE) {
		return;
	}

	hash = php_hashcontext_from_object(Z_OBJ_P(zhash));
	PHP_HASHCONTEXT_VERIFY("md5_final", hash);

	digest_len = hash->ops->digest_size;
	digest = zend_string_alloc(digest_len, 0);
	PHP_MD5Final((unsigned char *) ZSTR_VAL(digest), hash->context);

	ZSTR_VAL(digest)[digest_len] = 0;

	/* Invalidate the object from further use */
	efree(hash->context);
	hash->context = NULL;

	if (raw_output) {
		RETURN_NEW_STR(digest);
	} else {
		zend_string *hex_digest = zend_string_safe_alloc(digest_len, 2, 0, 0);

		php_hash_bin2hex(ZSTR_VAL(hex_digest), (unsigned char *) ZSTR_VAL(digest), digest_len);
		ZSTR_VAL(hex_digest)[2 * digest_len] = 0;
		zend_string_release_ex(digest, 0);
		RETURN_NEW_STR(hex_digest);
	}
}
/* }}} */

/* {{{ proto MD5Context md5_copy(MD5Context context)
Copy hash object */
PHP_FUNCTION(md5_copy)
{
	zval *zhash;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "O", &zhash, php_hashcontext_ce) == FAILURE) {
		return;
	}

	RETVAL_OBJ(Z_OBJ_HANDLER_P(zhash, clone_obj)(Z_OBJ_P(zhash)));

	if (php_hashcontext_from_object(Z_OBJ_P(return_value))->context == NULL) {
		zval_ptr_dtor(return_value);

		zend_throw_error(NULL, "Cannot copy hash");
		return;
	}
}
/* }}} */

/* }}} */

/* }}} */

/* {{{ proto MD5Context::__construct() */
static PHP_METHOD(MD5Context, __construct) {
	/* Normally unreachable as private/final */
	zend_throw_exception(zend_ce_error, "Illegal call to private/final constructor", 0);
}
/* }}} */

/* {{{ proto MD5Context::__sleep() */
static PHP_METHOD(MD5Context, __sleep) {
	zval *zhash;
	php_hashcontext_object *hash;
	zhash = getThis();
	hash = php_hashcontext_from_object(Z_OBJ_P(zhash));

	if(strlen(hash->context->buffer) != 0) {
		zend_throw_exception(spl_ce_RuntimeException, "Can not serialize buffer. Pump data with a multiple of 64bytes", 0);
	}

	zend_update_property_long(php_hashcontext_ce, zhash, "a", 1, hash->context->a TSRMLS_CC);
	zend_update_property_long(php_hashcontext_ce, zhash, "b", 1, hash->context->b TSRMLS_CC);
	zend_update_property_long(php_hashcontext_ce, zhash, "c", 1, hash->context->c TSRMLS_CC);
	zend_update_property_long(php_hashcontext_ce, zhash, "d", 1, hash->context->d TSRMLS_CC);
	zend_update_property_long(php_hashcontext_ce, zhash, "lo", 2, hash->context->lo TSRMLS_CC);
	zend_update_property_long(php_hashcontext_ce, zhash, "hi", 2, hash->context->hi TSRMLS_CC);

	array_init(return_value);
	add_index_string(return_value, 0, "a");
	add_index_string(return_value, 1, "b");
	add_index_string(return_value, 2, "c");
	add_index_string(return_value, 3, "d");
	add_index_string(return_value, 4, "lo");
	add_index_string(return_value, 5, "hi");
}
/* }}} */

/* {{{ proto MD5Context::__wakeup() */
static PHP_METHOD(MD5Context, __wakeup) {
	zval *zhash;
	php_hashcontext_object *hash;

	zend_long options = 0;
	void *context;
	const php_hash_ops *ops;

	zhash = getThis();
	hash = php_hashcontext_from_object(Z_OBJ_P(zhash));

	ops = php_hash_fetch_ops("md5", 3);

	context = emalloc(ops->context_size);
	PHP_MD5Init(context);

	hash->ops = ops;
	hash->context = context;
	hash->options = options;
	hash->key = NULL;

	zval *value;
	value = zend_read_property(php_hashcontext_ce, zhash, ZEND_STRL("a"), 1, 1 TSRMLS_CC);
	hash->context->a = Z_LVAL_P(value);
	value = zend_read_property(php_hashcontext_ce, zhash, ZEND_STRL("b"), 1, 1 TSRMLS_CC);
	hash->context->b = Z_LVAL_P(value);
	value = zend_read_property(php_hashcontext_ce, zhash, ZEND_STRL("c"), 1, 1 TSRMLS_CC);
	hash->context->c = Z_LVAL_P(value);
	value = zend_read_property(php_hashcontext_ce, zhash, ZEND_STRL("d"), 1, 1 TSRMLS_CC);
	hash->context->d = Z_LVAL_P(value);
	value = zend_read_property(php_hashcontext_ce, zhash, ZEND_STRL("lo"), 2, 1 TSRMLS_CC);
	hash->context->lo = Z_LVAL_P(value);
	value = zend_read_property(php_hashcontext_ce, zhash, ZEND_STRL("hi"), 2, 1 TSRMLS_CC);
	hash->context->hi = Z_LVAL_P(value);
}
/* }}} */

static const zend_function_entry php_hashcontext_methods[] = {
	PHP_ME(MD5Context, __construct, NULL, ZEND_ACC_PRIVATE)
	PHP_ME(MD5Context, __sleep, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(MD5Context, __wakeup, NULL, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

/* {{{ php_hashcontext_create */
static zend_object* php_hashcontext_create(zend_class_entry *ce) {
	php_hashcontext_object *objval = zend_object_alloc(sizeof(php_hashcontext_object), ce);
	zend_object *zobj = &objval->std;

	zend_object_std_init(zobj, ce);
	object_properties_init(zobj, ce);
	zobj->handlers = &php_hashcontext_handlers;

	return zobj;
}
/* }}} */

/* {{{ php_hashcontext_dtor */
static void php_hashcontext_dtor(zend_object *obj) {
	php_hashcontext_object *hash = php_hashcontext_from_object(obj);

	/* Just in case the algo has internally allocated resources */
	if (hash->context) {
		unsigned char *dummy = emalloc(hash->ops->digest_size);
		PHP_MD5Final(dummy, hash->context);

		efree(dummy);
		efree(hash->context);
		hash->context = NULL;
	}

	if (hash->key) {
		ZEND_SECURE_ZERO(hash->key, hash->ops->block_size);
		efree(hash->key);
		hash->key = NULL;
	}
}
/* }}} */

/* {{{ php_hashcontext_clone */
static zend_object *php_hashcontext_clone(zend_object *zobj) {
	php_hashcontext_object *oldobj = php_hashcontext_from_object(zobj);
	zend_object *znew = php_hashcontext_create(zobj->ce);
	php_hashcontext_object *newobj = php_hashcontext_from_object(znew);

	zend_objects_clone_members(znew, zobj);

	newobj->ops = oldobj->ops;
	newobj->options = oldobj->options;
	newobj->context = emalloc(newobj->ops->context_size);
	PHP_MD5Init(newobj->context);

	if (SUCCESS != php_md5_copy(newobj->ops, oldobj->context, newobj->context)) {
		efree(newobj->context);
		newobj->context = NULL;
		return znew;
	}

	newobj->key = ecalloc(1, newobj->ops->block_size);
	if (oldobj->key) {
		memcpy(newobj->key, oldobj->key, newobj->ops->block_size);
	}

	return znew;
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(hash)
{
	zend_class_entry ce;
	zend_hash_init(&php_hash_hashtable, 35, NULL, NULL, 1);
	php_hash_register_algo("md5",			&php_hash_md5_ops);
	INIT_CLASS_ENTRY(ce, "MD5Context", php_hashcontext_methods);

	php_hashcontext_ce = zend_register_internal_class(&ce);

	zend_declare_property_long(php_hashcontext_ce, "a", 1, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_hashcontext_ce, "b", 1, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_hashcontext_ce, "c", 1, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_hashcontext_ce, "d", 1, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_hashcontext_ce, "lo", 2, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_hashcontext_ce, "hi", 2, 0,ZEND_ACC_PRIVATE);

	php_hashcontext_ce->ce_flags |= ZEND_ACC_FINAL;
	php_hashcontext_ce->create_object = php_hashcontext_create;

	memcpy(&php_hashcontext_handlers, &std_object_handlers,
	       sizeof(zend_object_handlers));
	php_hashcontext_handlers.offset = XtOffsetOf(php_hashcontext_object, std);
	php_hashcontext_handlers.dtor_obj = php_hashcontext_dtor;
	php_hashcontext_handlers.clone_obj = php_hashcontext_clone;

	return SUCCESS;
}
/* }}} */


/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(hash)
{
	zend_hash_destroy(&php_hash_hashtable);

	return SUCCESS;
}
/* }}} */

/* {{{ hash_functions[]
 */
static const zend_function_entry md5_functions[] = {
	PHP_FE(md5_init,								arginfo_md5_init)
	PHP_FE(md5_update,								arginfo_md5_update)
	PHP_FE(md5_update_stream,						arginfo_md5_update_stream)
	PHP_FE(md5_final,								arginfo_md5_final)
	PHP_FE(md5_copy,								arginfo_md5_copy)

	PHP_FE_END
};
/* }}} */

/* {{{ hash_module_entry
 */
zend_module_entry smd5_module_entry = {
	STANDARD_MODULE_HEADER,
	PHP_SMD5_EXTNAME,
	md5_functions,
	PHP_MINIT(hash),
	PHP_MSHUTDOWN(hash),
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	NULL, /* MINFO */
	PHP_SMD5_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

ZEND_GET_MODULE(smd5)

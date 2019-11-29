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
 *         Scott MacVicar <scottmac@php.net>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include "php_smd5.h"
#include "ext/standard/info.h"
#include "ext/standard/file.h"

#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "ext/spl/spl_exceptions.h"

#include "smd5_arginfo.h"

const php_smd5_ops php_smd5_md5_ops = {
	16,
	64,
	sizeof(PHP_MD5_CTX),
	1
};

HashTable php_smd5_smd5table;
zend_class_entry *php_smd5context_ce;
static zend_object_handlers php_smd5context_handlers;

/* Hash Registry Access */

PHP_SMD5_API const php_smd5_ops *php_smd5_fetch_ops(const char *algo, size_t algo_len) /* {{{ */
{
	char *lower = zend_str_tolower_dup(algo, algo_len);
	php_smd5_ops *ops = zend_hash_str_find_ptr(&php_smd5_smd5table, lower, algo_len);
	efree(lower);

	return ops;
}
/* }}} */

PHP_SMD5_API void php_smd5_register_algo(const char *algo, const php_smd5_ops *ops) /* {{{ */
{
	size_t algo_len = strlen(algo);
	char *lower = zend_str_tolower_dup(algo, algo_len);
	zend_hash_add_ptr(&php_smd5_smd5table, zend_string_init_interned(lower, algo_len, 1), (void *) ops);
	efree(lower);
}
/* }}} */

PHP_SMD5_API int php_md5_copy(const void *ops, void *orig_context, void *dest_context) /* {{{ */
{
	php_smd5_ops *smd5_ops = (php_smd5_ops *)ops;

	memcpy(dest_context, orig_context, smd5_ops->context_size);
	return SUCCESS;
}
/* }}} */

static inline void php_smd5_string_xor_char(unsigned char *out, const unsigned char *in, const unsigned char xor_with, const size_t length) {
	size_t i;
	for (i=0; i < length; i++) {
		out[i] = in[i] ^ xor_with;
	}
}

static inline void php_smd5_string_xor(unsigned char *out, const unsigned char *in, const unsigned char *xor_with, const size_t length) {
	size_t i;
	for (i=0; i < length; i++) {
		out[i] = in[i] ^ xor_with[i];
	}
}

/* {{{ proto MD5Context md5_init()
Initialize a smd5ing context */
PHP_FUNCTION(md5_init)
{
	PHP_MD5_CTX *context;
	const php_smd5_ops *ops;
	php_smd5context_object *smd5;

	ops = php_smd5_fetch_ops("md5", 3);
	object_init_ex(return_value, php_smd5context_ce);
	smd5 = php_smd5context_from_object(Z_OBJ_P(return_value));

	context = emalloc(ops->context_size);

    //clear memory block since we may have buffered date in context->buffer
    memset(context, 0, ops->context_size);

	PHP_MD5Init(context);

	smd5->ops = ops;
	smd5->context = context;
}
/* }}} */

#define PHP_SMD5CONTEXT_VERIFY(func, smd5) { \
	if (!smd5->context) { \
		zend_throw_error(NULL, "%s(): supplied resource is not a valid Hash Context resource", func); \
		return; \
	} \
}

/* {{{ proto bool md5_update(MD5Context context, string data)
Pump data into the smd5ing algorithm */
PHP_FUNCTION(md5_update)
{
	zval *zsmd5;
	php_smd5context_object *smd5;
	zend_string *data;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "OS", &zsmd5, php_smd5context_ce, &data) == FAILURE) {
		return;
	}

	smd5 = php_smd5context_from_object(Z_OBJ_P(zsmd5));
	PHP_SMD5CONTEXT_VERIFY("md5_update", smd5);
	PHP_MD5Update(smd5->context, (unsigned char *) ZSTR_VAL(data), ZSTR_LEN(data));

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto int md5_update_stream(MD5Context context, resource handle[, int length])
Pump data into the smd5ing algorithm from an open stream */
PHP_FUNCTION(md5_update_stream)
{
	zval *zsmd5, *zstream;
	php_smd5context_object *smd5;
	php_stream *stream = NULL;
	zend_long length = -1, didread = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "Or|l", &zsmd5, php_smd5context_ce, &zstream, &length) == FAILURE) {
		return;
	}

	smd5 = php_smd5context_from_object(Z_OBJ_P(zsmd5));
	PHP_SMD5CONTEXT_VERIFY("md5_update_stream", smd5);
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

		PHP_MD5Update(smd5->context, (unsigned char *) buf, n);
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
	zval *zsmd5;
	php_smd5context_object *smd5;
	zend_bool raw_output = 0;
	zend_string *digest;
	size_t digest_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "O|b", &zsmd5, php_smd5context_ce, &raw_output) == FAILURE) {
		return;
	}

	smd5 = php_smd5context_from_object(Z_OBJ_P(zsmd5));
	PHP_SMD5CONTEXT_VERIFY("md5_final", smd5);

	digest_len = smd5->ops->digest_size;
	digest = zend_string_alloc(digest_len, 0);
	PHP_MD5Final((unsigned char *) ZSTR_VAL(digest), smd5->context);

	ZSTR_VAL(digest)[digest_len] = 0;

	/* Invalidate the object from further use */
	efree(smd5->context);
	smd5->context = NULL;

	if (raw_output) {
		RETURN_NEW_STR(digest);
	} else {
		zend_string *hex_digest = zend_string_safe_alloc(digest_len, 2, 0, 0);

		php_smd5_bin2hex(ZSTR_VAL(hex_digest), (unsigned char *) ZSTR_VAL(digest), digest_len);
		ZSTR_VAL(hex_digest)[2 * digest_len] = 0;
		zend_string_release_ex(digest, 0);
		RETURN_NEW_STR(hex_digest);
	}
}
/* }}} */

/* {{{ proto MD5Context md5_copy(MD5Context context)
Copy smd5 object */
PHP_FUNCTION(md5_copy)
{
	zval *zsmd5;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "O", &zsmd5, php_smd5context_ce) == FAILURE) {
		return;
	}

	RETVAL_OBJ(Z_OBJ_HANDLER_P(zsmd5, clone_obj)(Z_OBJ_P(zsmd5)));

	if (php_smd5context_from_object(Z_OBJ_P(return_value))->context == NULL) {
		zval_ptr_dtor(return_value);

		zend_throw_error(NULL, "Cannot copy smd5");
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
	zval *zsmd5;
	php_smd5context_object *smd5;
	zsmd5 = getThis();
	smd5 = php_smd5context_from_object(Z_OBJ_P(zsmd5));

    PHP_SMD5CONTEXT_VERIFY("__sleep", smd5);

	if(strlen(smd5->context->buffer) != 0) {
		zend_throw_exception(spl_ce_RuntimeException, "Can not serialize buffer. Pump data with a multiple of 64bytes", 0);
	}

	zend_update_property_long(php_smd5context_ce, zsmd5, "a", 1, smd5->context->a TSRMLS_CC);
	zend_update_property_long(php_smd5context_ce, zsmd5, "b", 1, smd5->context->b TSRMLS_CC);
	zend_update_property_long(php_smd5context_ce, zsmd5, "c", 1, smd5->context->c TSRMLS_CC);
	zend_update_property_long(php_smd5context_ce, zsmd5, "d", 1, smd5->context->d TSRMLS_CC);
	zend_update_property_long(php_smd5context_ce, zsmd5, "lo", 2, smd5->context->lo TSRMLS_CC);
	zend_update_property_long(php_smd5context_ce, zsmd5, "hi", 2, smd5->context->hi TSRMLS_CC);

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
	zval *zsmd5;
	php_smd5context_object *smd5;

	void *context;
	const php_smd5_ops *ops;

	zsmd5 = getThis();
	smd5 = php_smd5context_from_object(Z_OBJ_P(zsmd5));

	ops = php_smd5_fetch_ops("md5", 3);

	context = emalloc(ops->context_size);
	PHP_MD5Init(context);

	smd5->ops = ops;
	smd5->context = context;

	zval *value;
	value = zend_read_property(php_smd5context_ce, zsmd5, ZEND_STRL("a"), 1, 1 TSRMLS_CC);
	smd5->context->a = Z_LVAL_P(value);
	value = zend_read_property(php_smd5context_ce, zsmd5, ZEND_STRL("b"), 1, 1 TSRMLS_CC);
	smd5->context->b = Z_LVAL_P(value);
	value = zend_read_property(php_smd5context_ce, zsmd5, ZEND_STRL("c"), 1, 1 TSRMLS_CC);
	smd5->context->c = Z_LVAL_P(value);
	value = zend_read_property(php_smd5context_ce, zsmd5, ZEND_STRL("d"), 1, 1 TSRMLS_CC);
	smd5->context->d = Z_LVAL_P(value);
	value = zend_read_property(php_smd5context_ce, zsmd5, ZEND_STRL("lo"), 2, 1 TSRMLS_CC);
	smd5->context->lo = Z_LVAL_P(value);
	value = zend_read_property(php_smd5context_ce, zsmd5, ZEND_STRL("hi"), 2, 1 TSRMLS_CC);
	smd5->context->hi = Z_LVAL_P(value);
}
/* }}} */

static const zend_function_entry php_smd5context_methods[] = {
	PHP_ME(MD5Context, __construct, NULL, ZEND_ACC_PRIVATE)
	PHP_ME(MD5Context, __sleep, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(MD5Context, __wakeup, NULL, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

/* {{{ php_smd5context_create */
static zend_object* php_smd5context_create(zend_class_entry *ce) {
	php_smd5context_object *objval = zend_object_alloc(sizeof(php_smd5context_object), ce);
	zend_object *zobj = &objval->std;

	zend_object_std_init(zobj, ce);
	object_properties_init(zobj, ce);
	zobj->handlers = &php_smd5context_handlers;

	return zobj;
}
/* }}} */

/* {{{ php_smd5context_dtor */
static void php_smd5context_dtor(zend_object *obj) {
	php_smd5context_object *smd5 = php_smd5context_from_object(obj);

	/* Just in case the algo has internally allocated resources */
	if (smd5->context) {
		unsigned char *dummy = emalloc(smd5->ops->digest_size);
		PHP_MD5Final(dummy, smd5->context);

		efree(dummy);
		efree(smd5->context);
		smd5->context = NULL;
	}

	if (smd5->key) {
		ZEND_SECURE_ZERO(smd5->key, smd5->ops->block_size);
		efree(smd5->key);
		smd5->key = NULL;
	}
}
/* }}} */

/* {{{ php_smd5context_clone */
static zend_object *php_smd5context_clone(zend_object *zobj) {
	php_smd5context_object *oldobj = php_smd5context_from_object(zobj);
	zend_object *znew = php_smd5context_create(zobj->ce);
	php_smd5context_object *newobj = php_smd5context_from_object(znew);

	zend_objects_clone_members(znew, zobj);

	newobj->ops = oldobj->ops;
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
PHP_MINIT_FUNCTION(smd5)
{
	zend_class_entry ce;
	zend_hash_init(&php_smd5_smd5table, 35, NULL, NULL, 1);
	php_smd5_register_algo("md5",			&php_smd5_md5_ops);
	INIT_CLASS_ENTRY(ce, "MD5Context", php_smd5context_methods);

	php_smd5context_ce = zend_register_internal_class(&ce);

	zend_declare_property_long(php_smd5context_ce, "a", 1, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_smd5context_ce, "b", 1, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_smd5context_ce, "c", 1, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_smd5context_ce, "d", 1, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_smd5context_ce, "lo", 2, 0, ZEND_ACC_PRIVATE);
	zend_declare_property_long(php_smd5context_ce, "hi", 2, 0,ZEND_ACC_PRIVATE);

	php_smd5context_ce->ce_flags |= ZEND_ACC_FINAL;
	php_smd5context_ce->create_object = php_smd5context_create;

	memcpy(&php_smd5context_handlers, &std_object_handlers,
	       sizeof(zend_object_handlers));
	php_smd5context_handlers.offset = XtOffsetOf(php_smd5context_object, std);
	php_smd5context_handlers.dtor_obj = php_smd5context_dtor;
	php_smd5context_handlers.clone_obj = php_smd5context_clone;

	return SUCCESS;
}
/* }}} */


/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(smd5)
{
	zend_hash_destroy(&php_smd5_smd5table);

	return SUCCESS;
}
/* }}} */

/* {{{ smd5_functions[]
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

/* {{{ smd5_module_entry
 */
zend_module_entry smd5_module_entry = {
	STANDARD_MODULE_HEADER,
	PHP_SMD5_EXTNAME,
	md5_functions,
	PHP_MINIT(smd5),
	PHP_MSHUTDOWN(smd5),
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	NULL, /* MINFO */
	PHP_SMD5_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

ZEND_GET_MODULE(smd5)

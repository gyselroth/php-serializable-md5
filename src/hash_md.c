/**
 * Serializable MD5 hashing context
 *
 * Author: Raffael Sahli <sahli@gyselroth.com>
 *
 *
 * Initial copyright of ext/hash:
 *
 * Copyright (c) The PHP Group
 * Author: (Taken from: ext/standard/md5.c)
 */

#include "php_hash.h"
#include "php_hash_md.h"

const php_hash_ops php_hash_md5_ops = {
	16,
	64,
	sizeof(PHP_MD5_CTX),
	1
};

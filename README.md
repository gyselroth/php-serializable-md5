# Serializable MD5 HashContext
[![Build Status](https://travis-ci.org/gyselroth/php-serializable-md5.svg)](https://travis-ci.org/gyselroth/php-serializable-md5)
[![GitHub release](https://img.shields.io/github/release/gyselroth/php-serializable-md5.svg)](https://github.com/gyselroth/php-serializable-md5/releases)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/gyselroth/php-serializable-md5/master/LICENSE)

The smd5 extension brings serializable MD5 context to userland PHP.
It differs from the core extension ext/hash|standard/md5 in that way that it is completely serializable and unserializable.

## Requirements

Runtime requirements:
* PHP version >= 7.3

Tools required for installation:
* PHP Dev tools
* git

## Intallation

```sh
git clone https://github.com/gyselroth/php-serializable-md5
cd php-serializable-md5
phpize
./configure
make install

//enable module
echo "extension=smd5.so" >> `php --ini | grep "Loaded Configuration" | sed -e "s|.*:\s*||"`
```

## Why?
PHP ext/hash disallows serialization of HashContext. This is no problem for small chunks of data.
But if you need to calculcate hashes for bigger data and might to pause it or calculate it in chunks it wont be 
possible with ext/hash. With smd5 you are able to serialize the context, store it somewhere and continue to calculate the hash later.
For example over multiple http requests or pause/continue.


## Exposed methods

This extension exposes 4 new methods to PHP which work similar to the well known hash methods.

* Initialize MD5Context `md5_init(): MD5Context`
* Update MD5Context from string `md5_update(MD5Context $ctx, string $data): bool (Returns true)`
* Update MD5Context from stream `md5_update_stream(MD5Context $ctx, resource $stream, int $length=-1): int (Number of bytes read from stream)`
* Finalize MD5 Hash `md5_final(MD5Context $ctx): string (Returns the MD5 string)`

## Example

```php
$ctx = md5_init();
md5_update($ctx, "foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob");

$dump = serialize($ctx);
//$dump can now safely be stored somewhere and be reused at a later time

$new = unserialize($dump);
md5_update($ctx, " foobar");

$hash = md5_final($new);
var_dump($hash);
//Will print the correct MD5 hash:
//string(32) "49d68437b1ffb0db3fdf2d4a930be971"
```

## Serialization
You are only allowed to serialize the MD5Context if there is no data in the internal buffer.
This means you can only call `serialize()` if you add data to the context with a multiplication of 64bytes!
This is due security reason that no buffered data gets exposed.

You can still pump less data but then you may not use `serialize()` and end up with a `\RuntimeException`.
Usually your last update call may contain less data, this is fine because you should finalize the hash anyway and there is no 
reason to serialize the context.


## Why is this a c extension?

I have implemented this in userland PHP, see the gist [here](https://gist.github.com/raffis/3362374991ed1493abd5ebcc3d465cf0#file-php).
The problem is calculating an md5 hash with php takes ages, even with PHP7.4 and JIT it takes more than 20s for a 2MB string.

## Risks

The core extension [hash](https://www.php.net/manual/en/book.hash.php) disallows serialization for a good reason. 
Exposing the hashing context after serialization is a security risk if not handled well.
This is also the reason this extension only exposes this feature for MD5 and not for other algorithms as well since
MD5 should not be used for passwords or similar stuff anyway.

However if handled well and the serialized hash context is safely stored for whatever reason this library is very useful.

PHP_ARG_ENABLE(smd5, whether to enable SerializableMD5
World support,
[ --enable-smd5   Enable SerializableMD5 support])

SOURCE="src/hash.c"

if test "$PHP_SMD5" = "yes"; then
  AC_DEFINE(HAVE_SMD5, 1, [Whether you have SerializableMD5])
  PHP_NEW_EXTENSION(smd5, $SOURCE, $ext_shared)
fi


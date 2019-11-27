--TEST--
MD5 hash of a string which equals the md5 c buffer size
--FILE--
<?php
$ctx = md5_init();
md5_update($ctx, "foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob");
echo md5_final($ctx)."\n";
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
49d68437b1ffb0db3fdf2d4a930be971
===DONE===

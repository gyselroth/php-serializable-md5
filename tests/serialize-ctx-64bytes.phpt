--TEST--
Serialize MD5 context and unserialize
--FILE--
<?php
$ctx = md5_init();
md5_update($ctx, "foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob");
$d = serialize($ctx);
//var_dump($d);
$new = unserialize($d);
var_dump(md5_final($ctx));
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
string(32) "49d68437b1ffb0db3fdf2d4a930be971"
===DONE===

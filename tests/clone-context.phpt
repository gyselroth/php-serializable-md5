--TEST--
Clone MD5 Context
--FILE--
<?php
$ctx = md5_init();
md5_update($ctx, "foobar");
$new = clone $ctx;
var_dump(md5_final($new));
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
string(32) "49d68437b1ffb0db3fdf2d4a930be971"
===DONE===

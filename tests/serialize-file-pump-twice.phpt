--TEST--
Serialize MD5 Context and unserialize and pump from a stream
--FILE--
<?php
$stream = fopen('data://text/plain,foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob','r');
$ctx = md5_init();
md5_update_stream($ctx, $stream);
$d = serialize($ctx);
$new = unserialize($d);
var_dump(md5_final($new));
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
string(32) "49d68437b1ffb0db3fdf2d4a930be971"
===DONE===

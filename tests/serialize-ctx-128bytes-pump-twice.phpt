--TEST--
Serialize MD5 Context and unserialize and continue pump another 64bytes of data
--FILE--
<?php
$ctx = md5_init();
md5_update($ctx, "foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob");
$d = serialize($ctx);
$new = unserialize($d);
md5_update($new, "foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob");
var_dump(md5_final($new));
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
string(32) "8f983d681b58941c3ab4525135161f00"
===DONE===

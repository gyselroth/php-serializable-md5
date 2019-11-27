--TEST--
Throw RuntimeException if serialize gets called with an open buffer
--FILE--
<?php
try {
    $ctx = md5_init();
    md5_update($ctx, "foobar");
    $d = serialize($ctx);
} catch(\RuntimeException $e) {
    var_dump($e->getMessage());
}
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
string(62) "Can not serialize buffer. Pump data with a multiple of 64bytes"
===DONE===

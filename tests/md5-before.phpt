--TEST--
Check serialization if md5 used before (buffer not empty)
--FILE--
<?php
$t = "testtesttesttesttesttesttesttesttesttesttesttesttesttesttest";
md5($t.$t."test");

$ctx = md5_init();
md5_update($ctx, "foobarfoobar");
var_dump(md5_final($ctx));
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
string(32) "59faa421729e846dd800dce59943bfc0"
===DONE===

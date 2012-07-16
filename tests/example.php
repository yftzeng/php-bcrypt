<?php
require __DIR__ . '/../lib/Bcrypt.class.php';

$hash = Bcrypt::hash('demo');

echo 'Hash: ' . $hash . "\n";
echo 'Verify: ' . Bcrypt::verify('demo', $hash) . "\n";

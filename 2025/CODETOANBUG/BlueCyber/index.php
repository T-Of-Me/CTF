<?php

function fil($str)
{
    return str_replace("BlueCyber", "BC", $str);
}

class x
{
    public $username;
    public $password;
    public $isAdmin = false;

    public function __construct($username, $password)
    {
        $this->username = $username;
        $this->password = $password;
    }

    public function __wakeup()
    {
        if ($this->isAdmin) {
            // Ensure the file inclusion is controlled and safe
            if (file_exists("flag.php")) {
                include "flag.php";
                echo 'Awesome! Here is your flag: ' . htmlspecialchars($flag, ENT_QUOTES, 'UTF-8');
            } else {
                echo 'Flag file not found.';
            }
        } else {
            echo 'Incorrect credentials.<br>';
        }
    }
}

$username = isset($_GET['username']) ? $_GET['username'] : '';
$password = isset($_GET['password']) ? $_GET['password'] : '';

$ser = fil(serialize(new x($username, $password)));
$o = @unserialize($ser);

if (isset($_GET['debug'])) {
    highlight_file(__FILE__);
}
?>

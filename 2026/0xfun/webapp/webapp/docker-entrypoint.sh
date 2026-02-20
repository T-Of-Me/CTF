#!/bin/sh
set -eu

if [ "${MODE:-web}" = "internal" ]; then
  echo "[perimeter-drift] internal service listening on http://internal:9000"
  exec python3 /srv/internal_service/app.py
fi

if [ "${MODE:-web}" = "bot" ]; then
  echo "[perimeter-drift] admin bot listening on http://bot:7000"
  export DISPLAY=:99
  Xvfb :99 -screen 0 1366x768x24 >/tmp/xvfb.log 2>&1 &
  exec python3 /srv/internal_service/bot.py
fi

python3 /srv/scripts/init_db.py
echo "[perimeter-drift] web app listening on http://127.0.0.1:5000 (host mapped)"
exec python3 /srv/app/app.py

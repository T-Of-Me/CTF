#!/bin/bash

set -e 
unset FLAG

export ADMIN_KEY="$(tr -dc 'a-f0-9' </dev/urandom | head -c 32)"

python -u -m uvicorn app:app \
  --host 0.0.0.0 \
  --port 5000 \


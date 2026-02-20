#!/bin/sh
set -e

echo "[init_tun] Setting up tun0 interface..."

# Create tun0
ip tuntap add dev tun0 mode tun
ip addr add 10.0.0.1/24 dev tun0
ip link set dev tun0 up

echo "[init_tun] tun0 created successfully."

# Hand over to supervisord to start all services
exec supervisord -c /etc/supervisord.conf

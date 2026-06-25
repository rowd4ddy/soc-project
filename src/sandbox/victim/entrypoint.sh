#!/bin/bash
# entrypoint.sh — starts all victim services and keeps the container alive.

set -e

echo "[victim] starting rsyslog..."
# Ubuntu 24.04 containers don't have systemd — start rsyslog directly
rsyslogd || true

echo "[victim] starting nginx..."
nginx -g "daemon off;" &

echo "[victim] starting sshd..."
mkdir -p /var/run/sshd
/usr/sbin/sshd

echo "[victim] flushing any stale iptables rules..."
iptables -F 2>/dev/null || true

echo "[victim] ready — tailing logs"

# Ensure log files exist
mkdir -p /var/log/nginx
touch /var/log/auth.log /var/log/nginx/access.log /var/log/nginx/error.log

# Keep container alive by tailing logs
tail -F /var/log/auth.log /var/log/nginx/access.log /var/log/nginx/error.log 2>/dev/null
#!/bin/bash
set -Eeuo pipefail
umask 077
# Root-owned bootstrap never writes command output or JIT material to cloud-init logs.
exec >/dev/null 2>&1
phase() { printf 'CI7_BOOT_PHASE=%s\n' "$1" > /dev/ttyS0 2>/dev/null || true; }
phase BOOTSTRAP
trap 'phase FAILED; rm -f /run/ci7/jit; systemctl poweroff' ERR
test "$(id -u)" = 0
test -s /run/ci7/jit
test -s /run/ci7/run-id
test ! -e /var/lib/ci7/provisioned
mkdir -p /var/lib/ci7
touch /var/lib/ci7/provisioned

# No network administration service, default credentials, or inherited SSH trust.
systemctl disable --now ssh.service ssh.socket 2>/dev/null || true
systemctl mask ssh.service ssh.socket
phase NETWORK
rm -f /root/.ssh/authorized_keys /home/ubuntu/.ssh/authorized_keys
mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNS=1.1.1.1 9.9.9.9\nFallbackDNS=\nDomains=~.\n' > /etc/systemd/resolved.conf.d/ci7.conf
systemctl restart systemd-resolved
export DEBIAN_FRONTEND=noninteractive
phase DEPENDENCIES
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl git tar gzip nftables libicu74 libssl3t64 libkrb5-3 zlib1g

# Block the host, private networks, metadata endpoints, and inbound administration.
# DHCP is the sole private-network bootstrap exception; no management SSH exists.
phase FIREWALL
nft -f - <<'NFT'
table inet ci7 {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    udp sport 67 udp dport 68 accept
  }
  chain output {
    type filter hook output priority 0; policy accept;
    oifname "lo" accept
    udp sport 68 udp dport 67 accept
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } drop
    meta nfproto ipv6 drop
  }
}
NFT
# The NAT DHCP resolver is a required DNS dependency. Allow only DNS to the
# assigned IPv4 resolvers; private administration and all other private traffic
# remain blocked. Resolver values stay inside the disposable guest.
while read -r resolver; do
  if [[ "$resolver" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    nft insert rule inet ci7 output ip daddr "$resolver" udp dport 53 accept
    nft insert rule inet ci7 output ip daddr "$resolver" tcp dport 53 accept
  fi
done < <(awk '$1 == "nameserver" { print $2 }' /run/systemd/resolve/resolv.conf)
test ! -S /var/run/docker.sock
phase IDENTITY
test "$(id -u ldw-runner)" != 0
test "$(id -Gn ldw-runner)" = ldw-runner
install -d -o ldw-runner -g ldw-runner -m 0700 /opt/actions-runner
archive=/var/tmp/ci7-runner.tar.gz
phase DOWNLOAD
if curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --connect-timeout 30 --max-time 300 \
  --output "$archive" 'https://github.com/actions/runner/releases/download/v2.338.0/actions-runner-linux-x64-2.338.0.tar.gz'; then
  :
else
  status=$?
  case "$status" in
    6) phase DOWNLOAD_DNS_FAILED ;;
    7) phase DOWNLOAD_CONNECT_FAILED ;;
    22) phase DOWNLOAD_HTTP_FAILED ;;
    23) phase DOWNLOAD_WRITE_FAILED ;;
    35|60) phase DOWNLOAD_TLS_FAILED ;;
    *) phase DOWNLOAD_OTHER_FAILED ;;
  esac
  phase FAILED
  rm -f /run/ci7/jit
  systemctl poweroff
  exit 1
fi
printf '%s  %s\n' 'af4b794c1bc41d73d40535e3fe092a39f9679cd8d965954c2aca25a05ca41d32' "$archive" | sha256sum --check --strict
phase HASH
tar -xzf "$archive" -C /opt/actions-runner
rm -f "$archive"
chown -R ldw-runner:ldw-runner /opt/actions-runner
chown ldw-runner:ldw-runner /run/ci7/jit
chmod 0600 /run/ci7/jit
chmod 0755 /run/ci7
chmod 0444 /run/ci7/run-id
systemctl daemon-reload
phase SERVICE
systemctl start ci7-runner.service

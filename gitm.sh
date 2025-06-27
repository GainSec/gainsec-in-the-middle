#!/bin/bash

set -e

cat <<'EOF'
   ____ ___ _____ __  __
  / ___|_ _|_   _|  \/  |
 | |  _ | |  | | | |\/| |
 | |_| || |  | | | |  | |
  \____|___| |_| |_|  |_|

         GainSec In The Middle
EOF

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

BR_IFACE="br0"
WAN_IFACE="eth0"
PHY_IFACE="wlan0"
VIF_NAME="wlan0_ap"
SSID="GainSecInTheMiddle"
PASSWORD="12345678"
SUBNET_CIDR="192.168.100.1/24"
SUBNET_IP="192.168.100.1"
DNSMASQ_CONF="./mitm_dnsmasq.conf"
HOSTAPD_CONF="./mitm_hostapd.conf"
TCPDUMP_PID_FILE="./mitm_tcpdump.pids"
CAPTURE_FILE="./mitm-capture_${TIMESTAMP}.pcap"
LEASE_FILE="/tmp/mitm_dnsmasq.leases"
LEASE_WATCH_PID_FILE="./mitm_leasewatch.pid"

CERT_FILE="./mitm.crt"
KEY_FILE="./mitm.key"
SSL_PORT="10443"
SSLSPLIT_LOGDIR="./sslsplit-logs"
SSLSPLIT_LOGFILE="$SSLSPLIT_LOGDIR/sslsplit_${TIMESTAMP}.log"
SSLSPLIT_STATE="/tmp/sslsplit"
SSLSPLIT_BIN="sslsplit"
SSLSPLIT_PID_FILE="./mitm_sslsplit.pid"
SSL_CAPTURE_FILE="./sslsplit_capture_${TIMESTAMP}.pcap"

ACTION="$1"
shift || true
DUMP_FLAG=false
LIVE_FLAG=false
STRIP_FLAG=false
ANDROID_FLAG=false
BURP_FLAG=false
while [[ "$1" ]]; do
    case "$1" in
        --dump)    DUMP_FLAG=true ;;
        --live)    LIVE_FLAG=true ;;
        --strip)   STRIP_FLAG=true ;;
        --android) ANDROID_FLAG=true ;;
        --burp)    BURP_FLAG=true ;;
    esac
    shift || true
done

if [[ "$ACTION" != "up" && "$ACTION" != "down" ]]; then
    echo "Usage: $0 <up|down> [--dump] [--live] [--strip] [--android] [--burp]"
    exit 1
fi

stop_pidfile() {
    local file="$1"
    if [[ -f "$file" ]]; then
        while read -r PID; do
            kill "$PID" 2>/dev/null || true
        done < "$file"
        rm -f "$file"
    fi
}

if [[ "$ACTION" == "down" ]]; then
    echo "[*] Stopping services and tearing down interface state..."
    stop_pidfile "$TCPDUMP_PID_FILE"
    stop_pidfile "$SSLSPLIT_PID_FILE"
    stop_pidfile "$LEASE_WATCH_PID_FILE"
    killall dnsmasq 2>/dev/null || true
    killall hostapd 2>/dev/null || true
    ip link set $VIF_NAME down 2>/dev/null || true
    iw dev $VIF_NAME del 2>/dev/null || true
    ip link set $BR_IFACE down 2>/dev/null || true
    brctl delbr $BR_IFACE 2>/dev/null || true
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    echo "[+] Teardown complete."
    exit 0
fi

if $STRIP_FLAG || $ANDROID_FLAG || $BURP_FLAG; then
    if [[ ! -f "$KEY_FILE" || ! -f "$CERT_FILE" ]]; then
        echo "[*] Generating MITM-CA key and certificate..."
        openssl genrsa -out "$KEY_FILE" 2048
        openssl req -new -x509 -days 3650 -key "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=MITM-CA"
        echo "[+] Created $KEY_FILE and $CERT_FILE in $(pwd)"
    fi
fi

if $ANDROID_FLAG; then
    HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CERT_FILE" | head -1)
    echo "[*] intercept cert should be named ${HASH}.0"
    cp "$CERT_FILE" "${HASH}.0"
    echo "[+] mitm.crt has been copied to ${HASH}.0 and is ready for /system/etc/security/cacerts/"
fi

if $BURP_FLAG; then
    echo "[*] Preparing Burp import files (PKCS#12 & PEM)..."
    openssl pkcs12 -export -out mitm.p12 -inkey "$KEY_FILE" -in "$CERT_FILE" -name "MITM-CA" -passout pass:
    cat "$CERT_FILE" "$KEY_FILE" > mitm_combined.pem
    echo "[+] Generated mitm.p12 (no password) and mitm_combined.pem for Burp Suite import."
fi

if command -v rfkill >/dev/null 2>&1; then
    if rfkill list wifi | grep -q "Soft blocked: yes"; then
        echo "[*] Wireless interface soft blocked; unblocking..."
        rfkill unblock wifi
    else
        echo "[*] RFKill shows wireless interface is not soft blocked"
    fi
else
    echo "[*] RFKill shows wireless interface is not soft blocked"
fi

echo "[*] Creating virtual AP interface '$VIF_NAME' on physical '$PHY_IFACE'..."
iw dev $PHY_IFACE interface add $VIF_NAME type __ap

echo "[*] Writing hostapd config..."
cat <<EOF > $HOSTAPD_CONF
interface=$VIF_NAME
ssid=$SSID
country_code=US
hw_mode=g
channel=6
wpa=2
wpa_passphrase=$PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
EOF

#Change 8.8.8.8 to your internal DNS server ideally
echo "[*] Writing dnsmasq config..."
cat <<EOF > $DNSMASQ_CONF
interface=$BR_IFACE
dhcp-range=192.168.100.10,192.168.100.100,12h
dhcp-option=6,8.8.8.8
dhcp-leasefile=$LEASE_FILE
EOF

echo "[*] Bringing up virtual interface..."
ip link set $VIF_NAME up

echo "[*] Setting up bridge '$BR_IFACE'..."
brctl addbr $BR_IFACE
brctl addif $BR_IFACE $VIF_NAME
ip addr add $SUBNET_CIDR dev $BR_IFACE
ip link set $BR_IFACE up

echo "[*] Enabling IP forwarding and setting NAT rules..."
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o $WAN_IFACE -j MASQUERADE
iptables -A FORWARD -i $BR_IFACE -o $WAN_IFACE -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Change value of dport if the service runs on a port outside of 443
if $STRIP_FLAG; then
    echo "[*] Adding SSLsplit redirect rule on $BR_IFACE..."
    iptables -t nat -A PREROUTING -i $BR_IFACE -p tcp --dport 443 -j REDIRECT --to-port $SSL_PORT

    echo "[*] Starting sslstrip/split infrastructure..."
    mkdir -p "$SSLSPLIT_LOGDIR" "$SSLSPLIT_STATE"
    $SSLSPLIT_BIN -l "$SSLSPLIT_LOGFILE" -j "$SSLSPLIT_STATE" -S "$SSLSPLIT_LOGDIR" -k "$KEY_FILE" -c "$CERT_FILE" ssl 0.0.0.0 "$SSL_PORT" &
    echo $! > "$SSLSPLIT_PID_FILE"

    tcpdump -i $BR_IFACE -w "$SSL_CAPTURE_FILE" &
    echo $! >> "$TCPDUMP_PID_FILE"
fi

echo "[*] Starting dnsmasq..."
dnsmasq -C $DNSMASQ_CONF

echo "[*] Starting hostapd..."
echo "[+] SSID: $SSID"
echo "[+] Password: $PASSWORD"
hostapd $HOSTAPD_CONF &
HOSTAPD_PID=$!

if [[ ! -f "$LEASE_FILE" ]]; then
    touch "$LEASE_FILE"
fi

tail -n0 -F "$LEASE_FILE" | while read -r EXP MAC IP HOSTNAME CLIENTID; do
    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    printf '[+] %s New device MAC=%s IP=%s\n' "$DATE" "$MAC" "$IP"
done &
LEASE_WATCH_PID=$!
echo $LEASE_WATCH_PID > "$LEASE_WATCH_PID_FILE"

if $DUMP_FLAG || $LIVE_FLAG; then
    echo "[*] Starting tcpdump capture(s) on $BR_IFACE..."
fi
if $DUMP_FLAG; then
    tcpdump -i $BR_IFACE -nn -s 0 -v -w "$CAPTURE_FILE" &
    echo $! >> "$TCPDUMP_PID_FILE"
fi
if $LIVE_FLAG; then
    tcpdump -i $BR_IFACE -nn -A &
    echo $! >> "$TCPDUMP_PID_FILE"
fi

wait $HOSTAPD_PID

stop_pidfile "$TCPDUMP_PID_FILE"
stop_pidfile "$SSLSPLIT_PID_FILE"
stop_pidfile "$LEASE_WATCH_PID_FILE"

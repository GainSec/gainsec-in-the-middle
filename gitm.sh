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
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EMUDHRA_PROFILE_ROOT="$SCRIPT_DIR/profiles/emudhra"
DEFAULT_EMUDHRA_PROFILE="dv-g3b-aaa"

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
CHAIN_FILE=""
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
EMUDHRA_PROFILE=""
CUSTOM_CA=false
CA_CERT_SET=false
CA_KEY_SET=false
CA_CHAIN_SET=false
DRY_RUN=false
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --dump)    DUMP_FLAG=true ;;
        --live)    LIVE_FLAG=true ;;
        --strip)   STRIP_FLAG=true ;;
        --android) ANDROID_FLAG=true ;;
        --burp)    BURP_FLAG=true ;;
        --dry-run) DRY_RUN=true ;;
        --emudhra)
            EMUDHRA_PROFILE="$DEFAULT_EMUDHRA_PROFILE"
            if [[ -n "${2:-}" && "${2:-}" != --* ]]; then
                EMUDHRA_PROFILE="$2"
                shift
            fi
            STRIP_FLAG=true
            ;;
        --ca-cert)
            [[ -n "${2:-}" ]] || { echo "[!] --ca-cert requires a file" >&2; exit 1; }
            CERT_FILE="$2"; CUSTOM_CA=true; CA_CERT_SET=true; shift
            ;;
        --ca-key)
            [[ -n "${2:-}" ]] || { echo "[!] --ca-key requires a file" >&2; exit 1; }
            KEY_FILE="$2"; CUSTOM_CA=true; CA_KEY_SET=true; shift
            ;;
        --ca-chain)
            [[ -n "${2:-}" ]] || { echo "[!] --ca-chain requires a file" >&2; exit 1; }
            CHAIN_FILE="$2"; CUSTOM_CA=true; CA_CHAIN_SET=true; shift
            ;;
        *) echo "[!] Unknown option: $1" >&2; exit 1 ;;
    esac
    shift || true
done

usage() {
    cat <<EOF
Usage:
  $0 up [--dump] [--live] [--strip] [--android] [--burp] [--dry-run]
        [--emudhra [PROFILE]]
        [--ca-cert FILE --ca-key FILE [--ca-chain FILE]]
  $0 down
  $0 profiles
  $0 profile-info PROFILE
  $0 verify-profile PROFILE

Bundled eMudhra profiles are for authorized isolated lab testing only.
EOF
}

profile_path() {
    local name="$1"
    [[ "$name" =~ ^(dv|ov|ev)-g3(b|c)-(aaa|emsign)$ ]] || return 1
    local dir="$EMUDHRA_PROFILE_ROOT/$name"
    [[ -d "$dir" ]] || return 1
    printf '%s\n' "$dir"
}

list_profiles() {
    local dir
    for dir in "$EMUDHRA_PROFILE_ROOT"/*; do
        if [[ -d "$dir" ]]; then
            basename "$dir"
        fi
    done
    return 0
}

validate_pem_chain() {
    local chain="$1"
    awk '
        BEGIN { inside=0; count=0; bad=0 }
        /^[[:space:]]*$/ { next }
        /^-----BEGIN CERTIFICATE-----$/ { if (inside) bad=1; inside=1; count++; next }
        /^-----END CERTIFICATE-----$/ { if (!inside) bad=1; inside=0; next }
        { if (!inside || $0 !~ /^[A-Za-z0-9+\/=]+$/) bad=1 }
        END { if (inside || bad || count == 0) exit 1 }
    ' "$chain" || { echo "[!] CA chain contains malformed or non-certificate content: $chain" >&2; return 1; }
}

verify_ca_material() {
    local cert="$1" key="$2" chain="${3:-}" label="${4:-custom}" trust_anchor="${5:-}"
    [[ -s "$cert" ]] || { echo "[!] Missing CA certificate: $cert" >&2; return 1; }
    [[ -s "$key" ]] || { echo "[!] Missing CA private key: $key" >&2; return 1; }
    if [[ -n "$chain" && ! -s "$chain" ]]; then
        echo "[!] Missing CA chain: $chain" >&2
        return 1
    fi
    if [[ -n "$chain" ]]; then
        validate_pem_chain "$chain"
        openssl crl2pkcs7 -nocrl -certfile "$chain" | openssl pkcs7 -print_certs -noout >/dev/null
    fi

    openssl x509 -in "$cert" -noout >/dev/null
    openssl pkey -in "$key" -noout >/dev/null

    local cert_pub key_pub cert_text
    cert_pub=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)
    key_pub=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)
    [[ "$cert_pub" == "$key_pub" ]] || { echo "[!] CA certificate/private key mismatch" >&2; return 1; }

    cert_text=$(openssl x509 -in "$cert" -noout -text)
    [[ "$cert_text" == *"CA:TRUE"* ]] || { echo "[!] Certificate is not a CA (CA:TRUE missing)" >&2; return 1; }
    [[ "$cert_text" == *"Certificate Sign"* ]] || { echo "[!] Certificate cannot sign certificates" >&2; return 1; }

    if [[ -n "$trust_anchor" ]]; then
        [[ -s "$trust_anchor" ]] || { echo "[!] Missing trust anchor: $trust_anchor" >&2; return 1; }
        if [[ -n "$chain" ]]; then
            openssl verify -CAfile "$trust_anchor" -untrusted "$chain" "$cert" >/dev/null
        else
            openssl verify -CAfile "$trust_anchor" "$cert" >/dev/null
        fi
    elif [[ -n "$chain" ]]; then
        # Custom chains must include a complete path through a trust anchor.
        openssl verify -CAfile "$chain" "$cert" >/dev/null
    fi
    printf '[+] Profile verified: %s (CA:TRUE, keyCertSign, matching key)\n' "$label"
}

profile_info() {
    local name="$1" dir chain
    dir=$(profile_path "$name") || { echo "[!] Unknown eMudhra profile: $name" >&2; return 1; }
    echo "Profile: $name"
    echo "Certificate: $dir/ca.crt"
    echo "Private key: $dir/ca.key"
    [[ -s "$dir/chain.pem" ]] && echo "Chain: $dir/chain.pem"
    openssl x509 -in "$dir/ca.crt" -noout -subject -issuer -fingerprint -sha256
    if [[ -s "$dir/chain.pem" ]]; then
        echo "Additional chain certificate(s):"
        openssl crl2pkcs7 -nocrl -certfile "$dir/chain.pem" | openssl pkcs7 -print_certs -noout
    fi
}

case "$ACTION" in
    profiles)
        [[ $# -eq 0 ]] || { echo "[!] Unexpected positional argument: $1" >&2; usage; exit 1; }
        list_profiles
        exit 0
        ;;
    profile-info|verify-profile)
        PROFILE_NAME="${1:-}"
        [[ -n "$PROFILE_NAME" && $# -eq 1 ]] || { usage; exit 1; }
        PROFILE_DIR=$(profile_path "$PROFILE_NAME") || { echo "[!] Unknown eMudhra profile: $PROFILE_NAME" >&2; exit 1; }
        if [[ "$ACTION" == "profile-info" ]]; then
            profile_info "$PROFILE_NAME"
        else
            PROFILE_CHAIN=""
            [[ -s "$PROFILE_DIR/chain.pem" ]] && PROFILE_CHAIN="$PROFILE_DIR/chain.pem"
            verify_ca_material "$PROFILE_DIR/ca.crt" "$PROFILE_DIR/ca.key" "$PROFILE_CHAIN" "$PROFILE_NAME" "$PROFILE_DIR/trust-anchor.pem"
        fi
        exit 0
        ;;
    up|down)
        [[ $# -eq 0 ]] || { echo "[!] Unexpected positional argument: $1" >&2; usage; exit 1; }
        ;;
    *) usage; exit 1 ;;
esac

if [[ -n "$EMUDHRA_PROFILE" && "$CUSTOM_CA" == true ]]; then
    echo "[!] --emudhra cannot be combined with --ca-cert/--ca-key/--ca-chain" >&2
    exit 1
fi

if [[ -n "$EMUDHRA_PROFILE" ]]; then
    PROFILE_DIR=$(profile_path "$EMUDHRA_PROFILE") || { echo "[!] Unknown eMudhra profile: $EMUDHRA_PROFILE" >&2; exit 1; }
    CERT_FILE="$PROFILE_DIR/ca.crt"
    KEY_FILE="$PROFILE_DIR/ca.key"
    [[ -s "$PROFILE_DIR/chain.pem" ]] && CHAIN_FILE="$PROFILE_DIR/chain.pem"
fi

if [[ "$CUSTOM_CA" == true ]]; then
    if [[ "$CA_CERT_SET" != true || "$CA_KEY_SET" != true ]]; then
        echo "[!] Custom CA mode requires both --ca-cert and --ca-key" >&2
        exit 1
    fi
    STRIP_FLAG=true
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
    if $DRY_RUN; then
        echo "[*] Dry run; teardown commands were not executed."
        exit 0
    fi
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
    if [[ -n "$EMUDHRA_PROFILE" || "$CUSTOM_CA" == true ]]; then
        PROFILE_TRUST=""
        [[ -n "$EMUDHRA_PROFILE" ]] && PROFILE_TRUST="$PROFILE_DIR/trust-anchor.pem"
        verify_ca_material "$CERT_FILE" "$KEY_FILE" "$CHAIN_FILE" "${EMUDHRA_PROFILE:-custom}" "$PROFILE_TRUST"
    elif $DRY_RUN && [[ ! -f "$KEY_FILE" || ! -f "$CERT_FILE" ]]; then
        echo "[*] Dry run: default MITM-CA key and certificate would be generated at $KEY_FILE and $CERT_FILE."
    elif [[ ! -f "$KEY_FILE" || ! -f "$CERT_FILE" ]]; then
        echo "[*] Generating MITM-CA key and certificate..."
        openssl genrsa -out "$KEY_FILE" 2048
        openssl req -new -x509 -days 3650 -key "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=MITM-CA"
        echo "[+] Created $KEY_FILE and $CERT_FILE in $(pwd)"
    fi
fi

if $DRY_RUN; then
    echo "[*] Dry run; no interfaces, firewall rules, or services will be changed."
    if $STRIP_FLAG; then
        DRY_SSLSPLIT_ARGS=(-l "$SSLSPLIT_LOGFILE" -j "$SSLSPLIT_STATE" -S "$SSLSPLIT_LOGDIR" -k "$KEY_FILE" -c "$CERT_FILE")
        [[ -n "$CHAIN_FILE" ]] && DRY_SSLSPLIT_ARGS+=(-C "$CHAIN_FILE")
        printf '%q ' "$SSLSPLIT_BIN" "${DRY_SSLSPLIT_ARGS[@]}" ssl 0.0.0.0 "$SSL_PORT"
        printf '\n'
    fi
    exit 0
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
    SSLSPLIT_ARGS=(-l "$SSLSPLIT_LOGFILE" -j "$SSLSPLIT_STATE" -S "$SSLSPLIT_LOGDIR" -k "$KEY_FILE" -c "$CERT_FILE")
    [[ -n "$CHAIN_FILE" ]] && SSLSPLIT_ARGS+=(-C "$CHAIN_FILE")
    "$SSLSPLIT_BIN" "${SSLSPLIT_ARGS[@]}" ssl 0.0.0.0 "$SSL_PORT" &
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

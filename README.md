# GainSec in the Middle (G.I.T.M)
![Carrier](https://gainsec.com/wp-content/uploads/2026/10/gainsec-inthe-middle.jpg)

* Current Version: 1.2-lab
* Internal repository: <https://git.gainpalfam.com/admin/Gitm-ehudmra>

## Description
GITM is a Man-in-the-Middle (MITM) router and wireless access point for authorized embedded, IoT, and security research. It automatically configures the access point, DHCP, DNS, bridging, NAT, traffic redirection, packet capture, live inspection, and SSLsplit interception. Standard `--strip` mode preserves the original locally generated CA workflow, while `--strip --emudhra` enables opt-in stale-trust testing with 12 bundled, verified eMudhra profiles covering DV, OV, and EV intermediates across the AAA Certificate Services and emSign trust paths. GITM also supports validated user-supplied subordinate CAs, Android certificate preparation, and Burp Suite integration.

## Prerequisites

```bash
sudo apt update
sudo apt install hostapd dnsmasq sslsplit tcpdump iptables iw brctl openssl bridge-utils  rfkill psmisc gawk
```

## Out of the box:
* Checks if wireless is soft-blocked
* Access Point Creation (wlan0_ap) via hostapd
* DHCP + DNS via dnsmasq
* Bridges vAP (br0) enables IP forwarding & NAT via iptables
* Tears it all down smoothly; a must for troubleshooting
* Outputs and logs almost everything
* Aggregates all relevant logs into one directory
* Prints (and logs) when new devices connect to the AP including at what date, time, MAC address and IP they were assigned
* Optional: Generates CA * Key if missing, configures HTTPS redirection to local port, configures and starts sslsplit
* Optional: Dump traffic to pcap via tcpdump
* Optional: Live-view traffic via tcpdump
* Optional: Preps cert for Android system import
* Optional: Preps cert for Burp Suite import
* Optional: Uses a supplied subordinate CA certificate, key, and parent chain
* Optional: Includes twelve pinned eMudhra/emSign lab profiles covering the six affected TLS CA keys through both emSign and AAA/Sectigo trust paths
* And More


### Args:

* `up` - Generates, creates, and starts the MITM processes and services
* `down` - Smoothly tears down the MITM processes and services
* --android - Generates (If doesn't exist) and renames cert for Android system import
* --burp - Generates (If doesn't exist) .p12 and PEM bundle for Burp Suite
* --dump - Dumps traffic to pcap
* --live - Displays live traffic
* --strip - Enables SSL/TLS interception with GITM's locally generated CA
* --emudhra [PROFILE] - Makes `--strip` use a bundled revoked eMudhra TLS intermediate; defaults to `dv-g3b-aaa`
* --ca-cert FILE --ca-key FILE [--ca-chain FILE] - Uses arbitrary supplied CA material; a custom chain must contain a complete verifiable path through its trust anchor
* --dry-run - Validates CA material and prints the SSLsplit command without changing interfaces, firewall rules, or services

List and inspect the included profiles:

```bash
./gitm.sh profiles
./gitm.sh profile-info dv-g3b-aaa
./gitm.sh verify-profile dv-g3b-aaa
```

Plain `--strip` preserves the original GITM behavior and generates or reuses the local `mitm.crt` and `mitm.key`. Add `--emudhra` to select the broadly compatible direct-AAA profile automatically instead:

```bash
sudo ./gitm.sh up --strip --emudhra
```

Validate the complete SSLsplit invocation without changing the system:

```bash
./gitm.sh up --emudhra dv-g3b-aaa --dry-run
./gitm.sh up --emudhra dv-g3b-emsign --dry-run
```

Start the authorized test AP and transparent TLS interception:

```bash
sudo ./gitm.sh up --strip --emudhra dv-g3b-aaa --dump
```

Profile names use `{dv,ov,ev}-g3{b,c}-{aaa,emsign}`. The `aaa` profiles test clients that still trust the Sectigo `AAA Certificate Services` path. The `emsign` profiles test the direct emSign hierarchy and include the additional parent chain required by SSLsplit.

The files are under `profiles/emudhra/`. Every profile includes the exact CA certificate, matching reconstructed private key, offline trust anchor, and a source manifest with pinned upstream commits and fingerprints. Profiles that need an additional parent chain also include `chain.pem`.

### Verification

Run the deterministic profile and argument regression suite:

```bash
tests/test_emudhra_profiles.sh
bash -n gitm.sh tests/test_emudhra_profiles.sh
```

The release was tested on macOS and Kali Linux.

### Running with the Android and Dump args, showing how it prints (and logs) when devices connect to the AP
<img src="https://gainsec.com/wp-content/uploads/2025/06/android-dump.jpg" alt="android-dump-mac" width="600"/>

### Running with the Burp and Live args, showing how it prints live traffic and prepares the cert for import into Burp Suite.
<img src="https://gainsec.com/wp-content/uploads/2025/06/BurpLive.jpg" alt="live-burp" width="600"/>

### Running with the Strip arg, enabling TLS/SSL interception.
<img src="https://gainsec.com/wp-content/uploads/2025/06/strip.jpg" alt="strip" width="600"/>

### Smoothly tearing it all down.
<img src="https://gainsec.com/wp-content/uploads/2025/06/Teardown.jpg" alt="teardown" width="600"/>

## Authors

* **Jon Gaines** - [GainSec](https://gainsec.com)

## Acknowledgments

* Matt Brown - [nmatt0](https://github.com/nmatt0/mitmrouter)

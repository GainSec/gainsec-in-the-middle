# GainSec in the Middle (G.I.T.M)

* Current Version: 1.0

## Description
Implementation of Man-in-the-Middle (MiTM) Router / Access Point (AP). Great for embedded, IoT, or simlar penetration tests, hacks or research. Creates all interfaces and configurations on the fly, integrates other functionality to make tls stripping, android use or burp suite use more streamlined.

## Prerequisites 

sudo apt update
sudo apt install hostapd dnsmasq sslsplit tcpdump iptables iw brctl openssl

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
* And More


### Args:

* --up - Generates, Creates, Starts all the MITM processes and services
* --down - Securely and smoothly tears down all the MITM processes and services
* --android - Generates (If doesn't exist) and renames cert for Android system import
* --burp - Generates (If doesn't exist) .p12 and PEM bundle for Burp Suite
* --dump - Dumps traffic to pcap
* --live - Displays live traffic
* --strip - Enables SSL/TLS Interception

### Running with the Android and Dump args, showing how it prints (and logs) when devices connect to the AP
<img src="https://gainsec.com/wp-content/uploads/2025/06/android-dump.jpg" alt="android-dump-mac" width="600"/>

### Running with the Burp and Live args, showing how it prints live traffic and prepares the cert for import into Burp Suite.
<img src="https://gainsec.com/wp-content/uploads/2025/06/BurpLive.jpg" alt="live-burp" width="600"/>

### Running with the Strip arg, enabling TLS/SSL interception.
<img src="https://gainsec.com/wp-content/uploads/2025/06/strip.jpg" alt="strip" width="600"/>

### Smoothly tearing it all down.
<img src="https://gainsec.com/wp-content/uploads/2025/06/Teardown.jpg" alt="teardown" width="600"/>

## Authors

* **Jon Gaines** - [GainSec](https://github.com/GainSec)

## Acknowledgments

* Matt Brown - [nmatt0](https://github.com/nmatt0/mitmrouter)
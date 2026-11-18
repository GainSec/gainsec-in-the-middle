# Bundled eMudhra Lab Profiles

These profiles contain the publicly reconstructed private keys and revoked intermediate CA certificates from the October 2026 eMudhra/emSign incident. They are included only for authorized, isolated compatibility testing of devices you own or are permitted to assess.

Each profile contains `ca.crt`, `ca.key`, `trust-anchor.pem`, and `manifest.json`. Profiles chaining through `emSign Root TLS CA - G3` also contain `chain.pem`, because that issuer is itself subordinate to `emSign ECC Root CA - G3`. The `aaa` profiles chain directly to the device's pre-existing `AAA Certificate Services` trust anchor and therefore do not need an extra chain file. `trust-anchor.pem` is retained for deterministic offline testing and is not passed to SSLsplit.

Use `./gitm.sh profiles`, `./gitm.sh profile-info NAME`, and `./gitm.sh verify-profile NAME` before interception. Run with `./gitm.sh up --strip --emudhra NAME`.

Sources are pinned in each manifest. All bundled certificates are revoked. A modern or correctly patched client should reject them.

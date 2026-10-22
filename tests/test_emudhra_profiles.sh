#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GITM="$ROOT/gitm.sh"
run_gitm() { bash "$GITM" "$@"; }

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "expected output to contain: $2"; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=lab-target.example' -keyout "$TMP/leaf.key" -out "$TMP/leaf.csr" >/dev/null 2>&1
[[ -x "$GITM" ]] || fail "gitm.sh is not executable"

profiles=$(run_gitm profiles)
count=$(printf '%s\n' "$profiles" | grep -cE '^(dv|ov|ev)-g3[bc]-(aaa|emsign)$')
[[ "$count" -eq 12 ]] || fail "expected 12 bundled TLS profiles, got $count"

for profile in $profiles; do
    case "$profile" in
        dv-*|ov-*|ev-*) ;;
        *) continue ;;
    esac
    output=$(run_gitm verify-profile "$profile")
    assert_contains "$output" "Profile verified: $profile"
    assert_contains "$output" "CA:TRUE"

    profile_dir="$ROOT/profiles/emudhra/$profile"
    openssl x509 -req -in "$TMP/leaf.csr" -CA "$profile_dir/ca.crt" -CAkey "$profile_dir/ca.key" -set_serial 1 -days 1 -out "$TMP/$profile-leaf.crt" >/dev/null 2>&1
    if [[ -s "$profile_dir/chain.pem" ]]; then
        cat "$profile_dir/ca.crt" "$profile_dir/chain.pem" > "$TMP/$profile-untrusted.pem"
        openssl verify -CAfile "$profile_dir/trust-anchor.pem" -untrusted "$TMP/$profile-untrusted.pem" "$TMP/$profile-leaf.crt" >/dev/null
    else
        openssl verify -CAfile "$profile_dir/trust-anchor.pem" -untrusted "$profile_dir/ca.crt" "$TMP/$profile-leaf.crt" >/dev/null
    fi
done

emsign=$(run_gitm profile-info dv-g3b-emsign)
assert_contains "$emsign" "chain.pem"
assert_contains "$emsign" "EM DV TLS CA - G3B"
assert_contains "$emsign" "emSign Root TLS CA - G3"

aaa=$(run_gitm profile-info dv-g3b-aaa)
assert_contains "$aaa" "EM DV TLS CA - G3B"
assert_contains "$aaa" "AAA Certificate Services"
if printf '%s\n' "$aaa" | grep -q 'chain.pem'; then
    fail "AAA profile must not add an unnecessary parent chain"
fi

emsign_dry=$(run_gitm up --emudhra dv-g3b-emsign --dry-run)
assert_contains "$emsign_dry" "sslsplit"
assert_contains "$emsign_dry" "-C"
assert_contains "$emsign_dry" "dv-g3b-emsign/chain.pem"

aaa_dry=$(run_gitm up --emudhra dv-g3b-aaa --dry-run)
assert_contains "$aaa_dry" "sslsplit"
if printf '%s\n' "$aaa_dry" | grep -q -- ' -C '; then
    fail "AAA dry run unexpectedly includes -C"
fi

plain_strip_dry=$(run_gitm up --strip --dry-run)
assert_contains "$plain_strip_dry" "default MITM-CA key and certificate would be generated"
if printf '%s\n' "$plain_strip_dry" | grep -q 'profiles/emudhra/'; then
    fail "plain --strip unexpectedly selected an eMudhra profile"
fi

auto_dry=$(run_gitm up --strip --emudhra --dry-run)
assert_contains "$auto_dry" "dv-g3b-aaa/ca.crt"
assert_contains "$auto_dry" "dv-g3b-aaa/ca.key"
if printf '%s\n' "$auto_dry" | grep -q -- ' -C '; then
    fail "automatic --strip --emudhra mode unexpectedly includes -C"
fi

mkdir "$TMP/dry-run-cwd"
(
    cd "$TMP/dry-run-cwd"
    run_gitm up --strip --dry-run >/dev/null
)
[[ ! -e "$TMP/dry-run-cwd/mitm.crt" && ! -e "$TMP/dry-run-cwd/mitm.key" ]] || fail "dry run created default CA files"

sample="$ROOT/profiles/emudhra/dv-g3b-aaa"
if run_gitm up --ca-cert "$sample/ca.crt" --dry-run >/dev/null 2>&1; then
    fail "--ca-cert without --ca-key unexpectedly succeeded"
fi
if run_gitm up --ca-key "$sample/ca.key" --dry-run >/dev/null 2>&1; then
    fail "--ca-key without --ca-cert unexpectedly succeeded"
fi
printf 'not a certificate\n' > "$TMP/bad-chain.pem"
if run_gitm up --ca-cert "$sample/ca.crt" --ca-key "$sample/ca.key" --ca-chain "$TMP/bad-chain.pem" --dry-run >/dev/null 2>&1; then
    fail "malformed custom chain unexpectedly succeeded"
fi
if run_gitm up --emudhra dv-g3b-aaa --dry-run unexpected >/dev/null 2>&1; then
    fail "leftover positional argument unexpectedly succeeded"
fi
if run_gitm profiles unexpected >/dev/null 2>&1; then
    fail "profiles accepted a leftover positional argument"
fi

emsign_sample="$ROOT/profiles/emudhra/dv-g3b-emsign"
cat "$emsign_sample/chain.pem" "$emsign_sample/trust-anchor.pem" > "$TMP/full-chain.pem"
printf 'THIS IS NOT A CERTIFICATE\n' >> "$TMP/full-chain.pem"
if run_gitm up --ca-cert "$emsign_sample/ca.crt" --ca-key "$emsign_sample/ca.key" --ca-chain "$TMP/full-chain.pem" --dry-run >/dev/null 2>&1; then
    fail "custom chain with trailing garbage unexpectedly succeeded"
fi

mkdir "$TMP/stubs"
for command in killall ip iw brctl iptables; do
    cat > "$TMP/stubs/$command" <<EOF
#!/usr/bin/env bash
printf '%s\\n' '$command' >> '$TMP/down-actions.log'
EOF
    chmod +x "$TMP/stubs/$command"
done
PATH="$TMP/stubs:$PATH" run_gitm down --dry-run >/dev/null
[[ ! -e "$TMP/down-actions.log" ]] || fail "down --dry-run executed teardown commands"

if run_gitm verify-profile does-not-exist >/dev/null 2>&1; then
    fail "unknown profile unexpectedly verified"
fi

printf 'PASS: bundled eMudhra profiles validate\n'

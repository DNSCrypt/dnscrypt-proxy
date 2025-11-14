#! /bin/sh

DNS_PORT=5300
HTTP_PORT=3053
TEST_COUNT=0

exec 2>error.log

t() {
    TEST_COUNT=$((TEST_COUNT + 1))
    echo "Test #${TEST_COUNT}..."
    false
}

fail() (
    echo "*** Test #${TEST_COUNT} FAILED, line: $1 ***" >&2
)

section() {
    true
}

rm -f blocked-names.log blocked-ips.log query.log nx.log allowed-names.log

t || (
    cd ../dnscrypt-proxy
    go test -mod vendor
    go build -mod vendor -race
) || fail $LINENO

section
sed -e "s/127.0.0.1:53/127.0.0.1:${DNS_PORT}/g" -e "s/# server_names =.*/server_names = ['scaleway-fr']/" ../dnscrypt-proxy/example-dnscrypt-proxy.toml >test-dnscrypt-proxy.toml
../dnscrypt-proxy/dnscrypt-proxy -loglevel 3 -config test-dnscrypt-proxy.toml -pidfile /tmp/dnscrypt-proxy.pidfile &
sleep 5

t ||
    dig -p${DNS_PORT} . @127.0.0.1 | grep -Fq 'root-servers.net.' || fail $LINENO
t || dig -p${DNS_PORT} +dnssec . @127.0.0.1 | grep -Fq 'root-servers.net.' || fail $LINENO
t || dig -p${DNS_PORT} +dnssec . @127.0.0.1 | grep -Fq 'flags: do;' || fail $LINENO
t || dig -p${DNS_PORT} +short one.one.one.one @127.0.0.1 | grep -Fq '1.1.1.1' || fail $LINENO
t || dig -p${DNS_PORT} +dnssec dnscrypt.info @127.0.0.1 | grep -Fq 'flags: qr rd ra ad' || fail $LINENO
t || dig -p${DNS_PORT} +dnssec dnscrypt.info @127.0.0.1 | grep -Fq 'flags: do;' || fail $LINENO

kill $(cat /tmp/dnscrypt-proxy.pidfile)
sleep 5

section
../dnscrypt-proxy/dnscrypt-proxy -loglevel 3 -config test2-dnscrypt-proxy.toml -pidfile /tmp/dnscrypt-proxy.pidfile &
sleep 5

section
t || dig -p${DNS_PORT} A microsoft.com @127.0.0.1 | grep -Fq "NOERROR" || fail $LINENO
t || dig -p${DNS_PORT} A MICROSOFT.COM @127.0.0.1 | grep -Fq "NOERROR" || fail $LINENO

section
t || dig -p${DNS_PORT} AAAA ipv6.google.com @127.0.0.1 | grep -Fq 'locally blocked' || fail $LINENO

section
t || dig -p${DNS_PORT} invalid. @127.0.0.1 | grep -Fq NXDOMAIN || fail $LINENO
t || dig -p${DNS_PORT} +dnssec invalid. @127.0.0.1 | grep -Fq 'flags: do;' || fail $LINENO
t || dig -p${DNS_PORT} PTR 168.192.in-addr.arpa @127.0.0.1 | grep -Fq 'NXDOMAIN' || fail $LINENO
t || dig -p${DNS_PORT} +dnssec PTR 168.192.in-addr.arpa @127.0.0.1 | grep -Fq 'flags: do;' || fail $LINENO

section
t || dig -p${DNS_PORT} +dnssec darpa.mil @127.0.0.1 2>&1 | grep -Fvq 'RRSIG' || fail $LINENO
t || dig -p${DNS_PORT} +dnssec www.darpa.mil @127.0.0.1 2>&1 | grep -Fvq 'RRSIG' || fail $LINENO
t || dig -p${DNS_PORT} A download.windowsupdate.com @127.0.0.1 | grep -Fq "NOERROR" || fail $LINENO

section
t || dig -p${DNS_PORT} +short cloakedunregistered.com @127.0.0.1 | grep -Eq '1.1.1.1|1.0.0.1' || fail $LINENO
t || dig -p${DNS_PORT} +short MX cloakedunregistered.com @127.0.0.1 | grep -Fq 'locally blocked' || fail $LINENO
t || dig -p${DNS_PORT} +short MX example.com @127.0.0.1 | grep -Fvq 'locally blocked' || fail $LINENO
t || dig -p${DNS_PORT} NS cloakedunregistered.com @127.0.0.1 | grep -Fiq 'gtld-servers.net' || fail $LINENO
t || dig -p${DNS_PORT} +short www.cloakedunregistered2.com @127.0.0.1 | grep -Eq '1.1.1.1|1.0.0.1' || fail $LINENO
t || dig -p${DNS_PORT} +short www.dnscrypt-test @127.0.0.1 | grep -Fq '192.168.100.100' || fail $LINENO
t || dig -p${DNS_PORT} a.www.dnscrypt-test @127.0.0.1 | grep -Fq 'NXDOMAIN' || fail $LINENO
t || dig -p${DNS_PORT} +short ptr 101.100.168.192.in-addr.arpa. @127.0.0.1 | grep -Eq 'www.dnscrypt-test.com' || fail $LINENO
t || dig -p${DNS_PORT} +short ptr 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.d.f.ip6.arpa. @127.0.0.1 | grep -Eq 'ipv6.dnscrypt-test.com' || fail $LINENO

section
t || dig -p${DNS_PORT} telemetry.example @127.0.0.1 | grep -Fq 'locally blocked' || fail $LINENO

section
t || dig -p${DNS_PORT} dns.google @127.0.0.1 | grep -Fq 'locally blocked' || fail $LINENO

section
t || dig -p${DNS_PORT} tracker.xdebian.org @127.0.0.1 | grep -Fq 'locally blocked' || fail $LINENO
t || dig -p${DNS_PORT} tracker.debian.org @127.0.0.1 | grep -Fqv 'locally blocked' || fail $LINENO

section
t || curl --insecure -siL https://127.0.0.1:${HTTP_PORT}/ | grep -Fq 'HTTP/2 404' || fail $LINENO
t || curl --insecure -sL https://127.0.0.1:${HTTP_PORT}/dns-query | grep -Fq 'dnscrypt-proxy local DoH server' || fail $LINENO
t ||
    echo yv4BAAABAAAAAAABAAACAAEAACkQAAAAgAAAAA== | base64 -d |
    curl -H'Content-Type: application/dns-message' -H'Accept: application/dns-message' --data-binary @- -D - --insecure https://127.0.0.1:${HTTP_PORT}/dns-query 2>/dev/null |
        grep -Fq application/dns-message || fail $LINENO

kill $(cat /tmp/dnscrypt-proxy.pidfile)

sleep 5

section
t || grep -Fq 'telemetry.example' blocked-names.log || fail $LINENO
t || grep -Fq 'telemetry.*' blocked-names.log || fail $LINENO
t || grep -Fq 'tracker.xdebian.org' blocked-names.log || fail $LINENO
t || grep -Fq 'tracker.*' blocked-names.log || fail $LINENO

section
t || grep -Fq 'dns.google' blocked-ips.log || fail $LINENO
t || grep -Fq '8.8.8.8' blocked-ips.log || fail $LINENO

section
t || grep -Fq 'a.www.dnscrypt-test' nx.log || fail $LINENO

section
t || grep -Fq 'a.www.dnscrypt-test' nx.log || fail $LINENO

section
t || grep -Eq 'microsoft.com.*PASS.*[^-]$' query.log || fail $LINENO
t || grep -Eq 'microsoft.com.*PASS.*-$' query.log || fail $LINENO
t || grep -Eq 'ipv6.google.com.*SYNTH' query.log || fail $LINENO
t || grep -Eq 'invalid.*SYNTH' query.log || fail $LINENO
t || grep -Eq '168.192.in-addr.arpa.*SYNTH' query.log || fail $LINENO
t || grep -Eq 'darpa.mil.*FORWARD' query.log || fail $LINENO
t || grep -Eq 'www.darpa.mil.*FORWARD' query.log || fail $LINENO
t || grep -Eq 'download.windowsupdate.com.*FORWARD' query.log || fail $LINENO
t || grep -Eq 'cloakedunregistered.com.*CLOAK' query.log || fail $LINENO
t || grep -Eq 'www.cloakedunregistered2.com.*CLOAK' query.log || fail $LINENO
t || grep -Eq 'www.dnscrypt-test.*CLOAK' query.log || fail $LINENO
t || grep -Eq 'a.www.dnscrypt-test.*NXDOMAIN' query.log || fail $LINENO
t || grep -Eq 'telemetry.example.*REJECT' query.log || fail $LINENO
t || grep -Eq 'dns.google.*REJECT' query.log || fail $LINENO
t || grep -Eq 'tracker.xdebian.org.*REJECT' query.log || fail $LINENO
t || grep -Eq 'tracker.debian.org.*PASS' query.log || fail $LINENO
t || grep -Eq '[.].*NS.*PASS' query.log || fail $LINENO

section
t || grep -Fq 'tracker.debian.org' allowed-names.log || fail $LINENO
t || grep -Fq '*.tracker.debian' allowed-names.log || fail $LINENO

section
../dnscrypt-proxy/dnscrypt-proxy -loglevel 3 -config test3-dnscrypt-proxy.toml -pidfile /tmp/dnscrypt-proxy.pidfile &
sleep 5

section
t || dig -p${DNS_PORT} A microsoft.com @127.0.0.1 | grep -Fq "NOERROR" || fail $LINENO
t || dig -p${DNS_PORT} A MICROSOFT.COM @127.0.0.1 | grep -Fq "NOERROR" || fail $LINENO

kill $(cat /tmp/dnscrypt-proxy.pidfile)
sleep 5

section
../dnscrypt-proxy/dnscrypt-proxy -loglevel 3 -config test-odoh-proxied.toml -pidfile /tmp/odoh-proxied.pidfile &
sleep 5

section
t || dig -p${DNS_PORT} A microsoft.com @127.0.0.1 | grep -Fq "NOERROR" || fail $LINENO
t || dig -p${DNS_PORT} A cloudflare.com @127.0.0.1 | grep -Fq "NOERROR" || fail $LINENO

kill $(cat /tmp/odoh-proxied.pidfile)
sleep 5

if [ -s error.log ]; then
    cat *.log
    exit 1
fi

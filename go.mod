module github.com/dnscrypt/dnscrypt-proxy

go 1.25.0

exclude google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1

require (
	codeberg.org/miekg/dns v0.6.18
	github.com/BurntSushi/toml v1.6.0
	github.com/VividCortex/ewma v1.2.0
	github.com/coreos/go-systemd v0.22.6.0
	github.com/dchest/safefile v0.0.0-20151022103144-855e8d98f185
	github.com/fsnotify/fsnotify v1.9.0
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/go-immutable-radix v1.3.1
	github.com/hectane/go-acl v0.0.0-20230122075934-ca0b05cb1adb
	github.com/jedisct1/dlog v0.0.0-20241212093805-3c5fd791b405
	github.com/jedisct1/go-clocksmith v0.0.0-20250224222044-e151f21a353a
	github.com/jedisct1/go-dnsstamps v0.0.0-20251112173516-191fc465df31
	github.com/jedisct1/go-hpke-compact v0.0.0-20241212093903-5caa4621366f
	github.com/jedisct1/go-ipcrypt v0.1.1
	github.com/jedisct1/go-minisign v0.0.0-20241212093149-d2f9f49435c7
	github.com/jedisct1/go-sieve-cache v0.1.8
	github.com/jedisct1/xsecretbox v0.0.0-20241212092125-3afc4917ac41
	github.com/k-sone/critbitgo v1.4.0
	github.com/kardianos/service v1.2.4
	github.com/lifenjoiner/dhcpdns v0.0.7
	github.com/powerman/check v1.9.0
	github.com/quic-go/quic-go v0.58.0
	golang.org/x/crypto v0.46.0
	golang.org/x/net v0.48.0
	golang.org/x/sys v0.39.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hashicorp/go-syslog v1.0.0 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/powerman/deepequal v0.1.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/smartystreets/goconvey v1.8.1 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251213004720-97cd9d5aeac2 // indirect
	google.golang.org/grpc v1.77.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

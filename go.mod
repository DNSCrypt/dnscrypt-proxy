module github.com/DNSCrypt/dnscrypt-proxy

go 1.16

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/VividCortex/ewma v1.2.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/dchest/safefile v0.0.0-20151022103144-855e8d98f185
	github.com/hashicorp/go-immutable-radix v1.3.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/hectane/go-acl v0.0.0-20190604041725-da78bae5fc95
	github.com/jedisct1/dlog v0.0.0-20210101122416-354ffe815216
	github.com/jedisct1/go-clocksmith v0.0.0-20210101121932-da382b963868
	github.com/jedisct1/go-dnsstamps v0.0.0-20210101121956-16fbdadcf8f5
	github.com/jedisct1/go-hpke-compact v0.0.0-20210329192501-7ceabaabca65
	github.com/jedisct1/go-minisign v0.0.0-20210106175330-e54e81d562c7
	github.com/jedisct1/xsecretbox v0.0.0-20210330110434-7cb86b57caf0
	github.com/k-sone/critbitgo v1.4.0
	github.com/kardianos/service v1.2.0
	github.com/miekg/dns v1.1.41
	github.com/powerman/check v1.3.1
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/net v0.0.0-20210316092652-d523dce5a7f4
	golang.org/x/sys v0.0.0-20210320140829-1e4c9ba3b0c4
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

package main

import (
	"errors"
	"net"
	"slices"
	"testing"
	"time"
)

func TestNetworkInterfaceFingerprintIsStable(t *testing.T) {
	interfaces := []networkInterfaceSnapshot{
		{
			Name:         "eth0",
			Index:        2,
			MTU:          1500,
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
			Addrs: []*net.IPNet{
				testNetworkMonitorIPNet(t, "192.168.1.10/24"),
				testNetworkMonitorIPNet(t, "2001:db8:1::10/64"),
				testNetworkMonitorIPNet(t, "fe80::10/64"),
			},
		},
		{
			Name:  "vpn0",
			Index: 8,
			MTU:   1280,
			Flags: net.FlagUp | net.FlagPointToPoint,
			Addrs: []*net.IPNet{testNetworkMonitorIPNet(t, "10.8.0.2/24")},
		},
	}
	want := buildNetworkInterfaceFingerprint(interfaces)

	reordered := cloneNetworkMonitorInterfaces(interfaces)
	slices.Reverse(reordered)
	for i := range reordered {
		slices.Reverse(reordered[i].Addrs)
	}
	if got := buildNetworkInterfaceFingerprint(reordered); got != want {
		t.Fatal("interface fingerprint depends on enumeration order")
	}

	changes := []struct {
		name   string
		change func([]networkInterfaceSnapshot)
	}{
		{"name", func(v []networkInterfaceSnapshot) { v[0].Name = "en0" }},
		{"index", func(v []networkInterfaceSnapshot) { v[0].Index++ }},
		{"up state", func(v []networkInterfaceSnapshot) { v[1].Flags &^= net.FlagUp }},
		{"IPv4 address", func(v []networkInterfaceSnapshot) {
			v[0].Addrs[0].IP = net.ParseIP("192.168.1.20")
		}},
		{"IPv6 prefix", func(v []networkInterfaceSnapshot) {
			v[0].Addrs[1].IP = net.ParseIP("2001:db8:2::10")
		}},
		{"non-CIDR mask", func(v []networkInterfaceSnapshot) {
			v[0].Addrs[0].Mask = net.IPMask{0xff, 0x00, 0xff, 0x00}
		}},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneNetworkMonitorInterfaces(interfaces)
			test.change(changed)
			if got := buildNetworkInterfaceFingerprint(changed); got == want {
				t.Fatal("interface fingerprint did not change")
			}
		})
	}

	ignored := []struct {
		name   string
		change func([]networkInterfaceSnapshot)
	}{
		{"MTU", func(v []networkInterfaceSnapshot) { v[0].MTU-- }},
		{"running flag", func(v []networkInterfaceSnapshot) { v[0].Flags |= net.FlagRunning }},
		{"hardware address", func(v []networkInterfaceSnapshot) { v[0].HardwareAddr[5]++ }},
		{"IPv6 host identifier", func(v []networkInterfaceSnapshot) {
			v[0].Addrs[1].IP = net.ParseIP("2001:db8:1::20")
		}},
		{"overlapping IPv6 privacy address", func(v []networkInterfaceSnapshot) {
			v[0].Addrs = append(v[0].Addrs, testNetworkMonitorIPNet(t, "2001:db8:1::20/64"))
		}},
		{"link-local address", func(v []networkInterfaceSnapshot) {
			v[0].Addrs[2].IP = net.ParseIP("fe80::20")
		}},
	}
	for _, test := range ignored {
		t.Run("ignores "+test.name, func(t *testing.T) {
			changed := cloneNetworkMonitorInterfaces(interfaces)
			test.change(changed)
			if got := buildNetworkInterfaceFingerprint(changed); got != want {
				t.Fatal("interface fingerprint changed")
			}
		})
	}

	firstMask := cloneNetworkMonitorInterfaces(interfaces)
	firstMask[0].Addrs[0].Mask = net.IPMask{0xff, 0x00, 0xff, 0x00}
	secondMask := cloneNetworkMonitorInterfaces(firstMask)
	secondMask[0].Addrs[0].Mask = net.IPMask{0xff, 0xff, 0x00, 0xff}
	if buildNetworkInterfaceFingerprint(firstMask) == buildNetworkInterfaceFingerprint(secondMask) {
		t.Fatal("interface fingerprint does not distinguish non-CIDR masks")
	}
}

func TestSnapshotNetworkAddressPreservesHost(t *testing.T) {
	addr := testNetworkMonitorIPNet(t, "192.168.1.10/24")
	got := snapshotNetworkAddress(addr)
	if got == nil || !got.IP.Equal(addr.IP) {
		t.Fatalf("snapshot address = %v, want host address %v", got, addr.IP)
	}
}

func TestNetworkMonitorPassiveChangeWakesProbesBeforeCallbackReturns(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	interfaces := testNetworkMonitorInterfaces(t)
	failing := true
	events := make([]string, 0, 3)
	monitor := newNetworkMonitor()
	monitor.now = func() time.Time { return now }
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) { return interfaces, nil }
	monitor.probe = func(address string) (net.IP, error) {
		if address == monitor.probes[0].address {
			events = append(events, "ipv4")
			if failing {
				return nil, errors.New("IPv4 unavailable")
			}
			return net.ParseIP("192.168.1.10"), nil
		}
		events = append(events, "ipv6")
		if failing {
			return nil, errors.New("IPv6 unavailable")
		}
		return net.ParseIP("2001:db8:1::10"), nil
	}
	monitor.onChange = func() {
		events = append(events, "change")
		if got := monitor.epoch(); got != 1 {
			t.Errorf("epoch in callback = %d, want 1", got)
		}
		monitor.check()
	}

	monitor.init()
	now = now.Add(5 * time.Second)
	monitor.check()
	now = now.Add(5 * time.Second)
	interfaces = append(cloneNetworkMonitorInterfaces(interfaces), networkInterfaceSnapshot{
		Name:  "vpn0",
		Index: 8,
		Flags: net.FlagUp | net.FlagPointToPoint,
		Addrs: []*net.IPNet{testNetworkMonitorIPNet(t, "fe80::8/64")},
	})
	failing = false
	events = events[:0]
	monitor.check()

	wantEvents := []string{"change", "ipv4", "ipv6"}
	if !slices.Equal(events, wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
	if got := monitor.epoch(); got != 1 {
		t.Fatalf("epoch = %d, want 1", got)
	}
	now = now.Add(5 * time.Second)
	monitor.check()
	if got := monitor.epoch(); got != 1 {
		t.Fatalf("stable check changed epoch to %d", got)
	}
}

func TestNetworkMonitorBacksOffFailedFamilyIndependently(t *testing.T) {
	testErrors := []struct {
		name string
		err  error
	}{
		{"plain error", errors.New("unavailable")},
		{"wrapped network error", &net.OpError{Op: "dial", Net: "udp", Err: errors.New("unavailable")}},
	}
	for _, testError := range testErrors {
		t.Run(testError.name, func(t *testing.T) {
			now := time.Unix(1_000_000, 0)
			ipv4Calls := 0
			ipv6Calls := 0
			monitor := newNetworkMonitor()
			monitor.now = func() time.Time { return now }
			monitor.interfaces = func() ([]networkInterfaceSnapshot, error) {
				return testNetworkMonitorInterfaces(t), nil
			}
			monitor.probe = func(address string) (net.IP, error) {
				if address == monitor.probes[0].address {
					ipv4Calls++
					return net.ParseIP("192.168.1.10"), nil
				}
				ipv6Calls++
				return nil, testError.err
			}

			monitor.init()
			for _, elapsed := range []time.Duration{5, 10, 15, 20, 35} {
				now = time.Unix(1_000_000, 0).Add(elapsed * time.Second)
				monitor.check()
			}
			if ipv4Calls != 6 {
				t.Fatalf("IPv4 probes = %d, want 6", ipv4Calls)
			}
			if ipv6Calls != 4 {
				t.Fatalf("IPv6 probes = %d, want 4", ipv6Calls)
			}
		})
	}
}

func TestNetworkMonitorBackoffStopsAtThirtySeconds(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	monitor := newNetworkMonitor()
	monitor.now = func() time.Time { return now }
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) {
		return testNetworkMonitorInterfaces(t), nil
	}
	monitor.probe = func(address string) (net.IP, error) {
		if address == monitor.probes[0].address {
			return net.ParseIP("192.168.1.10"), nil
		}
		return nil, errors.New("IPv6 unavailable")
	}

	monitor.init()
	for _, want := range []time.Duration{
		10 * time.Second,
		20 * time.Second,
		30 * time.Second,
		30 * time.Second,
	} {
		now = monitor.probes[1].retryAt
		monitor.check()
		if got := monitor.probes[1].backoff; got != want {
			t.Fatalf("backoff = %s, want %s", got, want)
		}
		if got := monitor.probes[1].retryAt.Sub(now); got != want {
			t.Fatalf("retry delay = %s, want %s", got, want)
		}
	}
}

func TestNetworkMonitorKeepsProbingAfterInterfaceSnapshotError(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	ipv6Failing := false
	changes := 0
	monitor := newNetworkMonitor()
	monitor.now = func() time.Time { return now }
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) {
		return nil, errors.New("interfaces unavailable")
	}
	monitor.probe = func(address string) (net.IP, error) {
		if address == monitor.probes[0].address {
			return net.ParseIP("192.168.1.10"), nil
		}
		if ipv6Failing {
			return nil, errors.New("IPv6 unavailable")
		}
		return net.ParseIP("2001:db8:1::10"), nil
	}
	monitor.onChange = func() { changes++ }

	monitor.init()
	ipv6Failing = true
	now = now.Add(5 * time.Second)
	monitor.check()
	if changes != 1 || monitor.epoch() != 1 {
		t.Fatalf("active change produced %d callbacks and epoch %d", changes, monitor.epoch())
	}
}

func TestNetworkMonitorProbeRecovery(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	ipv6Failing := false
	ipv6Calls := 0
	changes := 0
	monitor := newNetworkMonitor()
	monitor.now = func() time.Time { return now }
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) {
		return testNetworkMonitorInterfaces(t), nil
	}
	monitor.probe = func(address string) (net.IP, error) {
		if address == monitor.probes[0].address {
			return net.ParseIP("192.168.1.10"), nil
		}
		ipv6Calls++
		if ipv6Failing {
			return nil, errors.New("IPv6 unavailable")
		}
		return net.ParseIP("2001:db8:1::10"), nil
	}
	monitor.onChange = func() { changes++ }
	monitor.init()

	ipv6Failing = true
	now = now.Add(5 * time.Second)
	monitor.check()
	now = now.Add(5 * time.Second)
	monitor.check()
	now = now.Add(5 * time.Second)
	monitor.check()
	if changes != 1 || ipv6Calls != 3 {
		t.Fatalf("during failure: changes = %d, IPv6 probes = %d, want 1 and 3", changes, ipv6Calls)
	}

	ipv6Failing = false
	now = now.Add(5 * time.Second)
	monitor.check()
	if changes != 2 || ipv6Calls != 4 {
		t.Fatalf("after recovery: changes = %d, IPv6 probes = %d, want 2 and 4", changes, ipv6Calls)
	}
	now = now.Add(5 * time.Second)
	monitor.check()
	if changes != 2 {
		t.Fatalf("stable recovery changed callback count to %d", changes)
	}

	ipv6Failing = true
	now = now.Add(5 * time.Second)
	monitor.check()
	now = now.Add(5 * time.Second)
	monitor.check()
	if changes != 3 || ipv6Calls != 7 {
		t.Fatalf("after reset: changes = %d, IPv6 probes = %d, want 3 and 7", changes, ipv6Calls)
	}
}

func TestNetworkMonitorCoalescesFamilyChanges(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	failing := false
	changes := 0
	monitor := newNetworkMonitor()
	monitor.now = func() time.Time { return now }
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) {
		return testNetworkMonitorInterfaces(t), nil
	}
	monitor.probe = func(address string) (net.IP, error) {
		if failing {
			return nil, errors.New("unavailable")
		}
		if address == monitor.probes[0].address {
			return net.ParseIP("192.168.1.10"), nil
		}
		return net.ParseIP("2001:db8:1::10"), nil
	}
	monitor.onChange = func() { changes++ }
	monitor.init()

	failing = true
	now = now.Add(5 * time.Second)
	monitor.check()
	if changes != 1 || monitor.epoch() != 1 {
		t.Fatalf("simultaneous failure produced %d callbacks and epoch %d", changes, monitor.epoch())
	}
	failing = false
	now = now.Add(5 * time.Second)
	monitor.check()
	if changes != 2 || monitor.epoch() != 2 {
		t.Fatalf("simultaneous recovery produced %d callbacks and epoch %d", changes, monitor.epoch())
	}
}

func TestNetworkMonitorInitializationIsIdempotent(t *testing.T) {
	probeCalls := 0
	callbackCalls := 0
	monitor := newNetworkMonitor()
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) {
		return testNetworkMonitorInterfaces(t), nil
	}
	monitor.probe = func(string) (net.IP, error) {
		probeCalls++
		return nil, errors.New("unavailable")
	}
	monitor.onChange = func() { callbackCalls++ }

	monitor.init()
	monitor.init()
	if probeCalls != 2 {
		t.Fatalf("initialization made %d probes, want 2", probeCalls)
	}
	if callbackCalls != 0 || monitor.epoch() != 0 {
		t.Fatalf("initialization produced %d callbacks and epoch %d", callbackCalls, monitor.epoch())
	}
}

func testNetworkMonitorInterfaces(t *testing.T) []networkInterfaceSnapshot {
	t.Helper()
	return []networkInterfaceSnapshot{
		{
			Name:         "eth0",
			Index:        2,
			MTU:          1500,
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
			Addrs: []*net.IPNet{
				testNetworkMonitorIPNet(t, "192.168.1.10/24"),
				testNetworkMonitorIPNet(t, "2001:db8:1::10/64"),
			},
		},
	}
}

func testNetworkMonitorIPNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	ipNet.IP = ip
	return ipNet
}

func cloneNetworkMonitorInterfaces(interfaces []networkInterfaceSnapshot) []networkInterfaceSnapshot {
	cloned := make([]networkInterfaceSnapshot, len(interfaces))
	for i, iface := range interfaces {
		cloned[i] = iface
		cloned[i].HardwareAddr = slices.Clone(iface.HardwareAddr)
		cloned[i].Addrs = make([]*net.IPNet, len(iface.Addrs))
		for j, addr := range iface.Addrs {
			if addr == nil {
				continue
			}
			cloned[i].Addrs[j] = &net.IPNet{
				IP:   slices.Clone(addr.IP),
				Mask: slices.Clone(addr.Mask),
			}
		}
	}
	return cloned
}

package main

import (
	"errors"
	"net"
	"slices"
	"testing"
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

func TestNetworkMonitorNotifiesOnInterfaceChange(t *testing.T) {
	interfaces := testNetworkMonitorInterfaces(t)
	changes := 0
	monitor := newNetworkMonitor()
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) { return interfaces, nil }
	monitor.onChange = func() {
		changes++
		if got := monitor.epoch(); got != uint64(changes) {
			t.Errorf("epoch in callback = %d, want %d", got, changes)
		}
	}

	monitor.init()
	monitor.check()
	if changes != 0 || monitor.epoch() != 0 {
		t.Fatalf("stable network produced %d callbacks and epoch %d", changes, monitor.epoch())
	}

	interfaces = append(cloneNetworkMonitorInterfaces(interfaces), networkInterfaceSnapshot{
		Name:  "vpn0",
		Index: 8,
		Flags: net.FlagUp | net.FlagPointToPoint,
		Addrs: []*net.IPNet{testNetworkMonitorIPNet(t, "10.8.0.2/24")},
	})
	monitor.check()
	if changes != 1 || monitor.epoch() != 1 {
		t.Fatalf("interface change produced %d callbacks and epoch %d", changes, monitor.epoch())
	}

	monitor.check()
	if changes != 1 || monitor.epoch() != 1 {
		t.Fatalf("stable check produced %d callbacks and epoch %d", changes, monitor.epoch())
	}
}

func TestNetworkMonitorFirstCheckOnlyRecordsBaseline(t *testing.T) {
	interfaces := testNetworkMonitorInterfaces(t)
	changes := 0
	monitor := newNetworkMonitor()
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) { return interfaces, nil }
	monitor.onChange = func() { changes++ }

	monitor.check()
	if changes != 0 || monitor.epoch() != 0 {
		t.Fatalf("first check produced %d callbacks and epoch %d", changes, monitor.epoch())
	}
	interfaces = cloneNetworkMonitorInterfaces(interfaces)
	interfaces[0].Addrs[0].IP = net.ParseIP("192.168.1.20")
	monitor.check()
	if changes != 1 || monitor.epoch() != 1 {
		t.Fatalf("change after the baseline produced %d callbacks and epoch %d", changes, monitor.epoch())
	}
}

func TestNetworkMonitorIgnoresInterfaceSnapshotErrors(t *testing.T) {
	interfaces := testNetworkMonitorInterfaces(t)
	failing := false
	changes := 0
	monitor := newNetworkMonitor()
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) {
		if failing {
			return nil, errors.New("interfaces unavailable")
		}
		return interfaces, nil
	}
	monitor.onChange = func() { changes++ }

	monitor.init()
	failing = true
	monitor.check()
	if changes != 0 || monitor.epoch() != 0 {
		t.Fatalf("snapshot error produced %d callbacks and epoch %d", changes, monitor.epoch())
	}

	failing = false
	monitor.check()
	if changes != 0 || monitor.epoch() != 0 {
		t.Fatalf("recovery from a snapshot error produced %d callbacks and epoch %d", changes, monitor.epoch())
	}

	// A failed enumeration keeps the last known fingerprint around, so a change
	// that happens while we are blind is still reported once we can see again.
	failing = true
	monitor.check()
	interfaces = cloneNetworkMonitorInterfaces(interfaces)
	interfaces[0].Addrs[0].IP = net.ParseIP("192.168.1.20")
	monitor.check()
	failing = false
	monitor.check()
	if changes != 1 || monitor.epoch() != 1 {
		t.Fatalf("change during a snapshot error produced %d callbacks and epoch %d", changes, monitor.epoch())
	}
}

func TestNetworkMonitorIgnoresReentrantChecks(t *testing.T) {
	interfaces := testNetworkMonitorInterfaces(t)
	snapshots := 0
	changes := 0
	monitor := newNetworkMonitor()
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) {
		snapshots++
		return interfaces, nil
	}
	monitor.onChange = func() {
		changes++
		monitor.check()
	}

	monitor.init()
	interfaces = cloneNetworkMonitorInterfaces(interfaces)
	interfaces[0].Addrs[0].IP = net.ParseIP("192.168.1.20")
	monitor.check()
	if changes != 1 || monitor.epoch() != 1 {
		t.Fatalf("reentrant check produced %d callbacks and epoch %d", changes, monitor.epoch())
	}
	if snapshots != 2 {
		t.Fatalf("interfaces were sampled %d times, want 2", snapshots)
	}
}

func TestNetworkMonitorInitializationIsIdempotent(t *testing.T) {
	snapshots := 0
	callbackCalls := 0
	monitor := newNetworkMonitor()
	monitor.interfaces = func() ([]networkInterfaceSnapshot, error) {
		snapshots++
		return testNetworkMonitorInterfaces(t), nil
	}
	monitor.onChange = func() { callbackCalls++ }

	monitor.init()
	monitor.init()
	if snapshots != 1 {
		t.Fatalf("initialization sampled the interfaces %d times, want 1", snapshots)
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

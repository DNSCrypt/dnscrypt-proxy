package critbitgo_test

import (
	"math/rand"
	"net"
	"testing"

	"github.com/k-sone/critbitgo"
)

var routeCount int = 10000
var routes []string

func init() {
	routes = make([]string, routeCount)
	random := rand.New(rand.NewSource(0))
	for i := 0; i < len(routes); i++ {
		routes[i] = genRoute(random)
	}
}

func genRoute(rand *rand.Rand) string {
	ip := rand.Int31()
	mask := rand.Intn(33)
	ipnet := &net.IPNet{
		IP:   net.IP{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)},
		Mask: net.CIDRMask(mask, 32),
	}
	return ipnet.String()
}

func buildNet(keys []string) *critbitgo.Net {
	tree := critbitgo.NewNet()
	for i := 0; i < len(keys); i++ {
		tree.AddCIDR(keys[i], nil)
	}
	tree.AddCIDR("0.0.0.0/5", nil)
	return tree
}

func BenchmarkNetBuild(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buildNet(routes)
	}
}

func BenchmarkNetGet(b *testing.B) {
	n := buildNet(routes)
	random := rand.New(rand.NewSource(0))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		k := routes[random.Intn(routeCount)]
		n.GetCIDR(k)
	}
}

func BenchmarkNetDelete(b *testing.B) {
	n := buildNet(routes)
	random := rand.New(rand.NewSource(0))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		k := routes[random.Intn(keyCount)]
		n.DeleteCIDR(k)
	}
}

func BenchmarkNetMatch(b *testing.B) {
	n := buildNet(routes)
	random := rand.New(rand.NewSource(0))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s := genRoute(random)
		n.MatchCIDR(s)
	}
}

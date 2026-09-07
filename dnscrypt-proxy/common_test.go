package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
	"github.com/k-sone/critbitgo"
)

func TestLoadIPRulesErrorLineNumbers(t *testing.T) {
	logFile, err := os.Create(filepath.Join(t.TempDir(), "errors.log"))
	if err != nil {
		t.Fatal(err)
	}
	oldFD, oldLevel := dlog.GetFileDescriptor(), dlog.LogLevel()
	dlog.UseSyslog(false)
	dlog.SetFileDescriptor(logFile)
	dlog.SetLogLevel(dlog.SeverityError)
	t.Cleanup(func() {
		dlog.SetFileDescriptor(oldFD)
		dlog.SetLogLevel(oldLevel)
		logFile.Close()
	})

	for _, tt := range []struct {
		name     string
		rule     string
		networks *critbitgo.Net
	}{
		{"short rule", "*", critbitgo.NewNet()},
		{"empty prefix", ".*", critbitgo.NewNet()},
		{"embedded wildcard", "192.*.2", critbitgo.NewNet()},
		{"invalid CIDR", "192.0.2.0/33", critbitgo.NewNet()},
		{"missing network table", "192.0.2.0/24", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := logFile.Truncate(0); err != nil {
				t.Fatal(err)
			}
			if _, err := logFile.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			ips := make(map[string]any)
			if _, err := LoadIPRules("# Rules\n\n"+tt.rule+"\n192.0.2.1\n", iradix.New(), ips, tt.networks); err != nil {
				t.Fatal(err)
			}
			if ips["192.0.2.1"] != true {
				t.Error("valid rule after the error was not loaded")
			}
			log, err := os.ReadFile(logFile.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(log), "line 3") {
				t.Errorf("error log should identify line 3: %s", log)
			}
		})
	}
}

func TestExtractClientIPStr(t *testing.T) {
	tests := []struct {
		name         string
		pluginsState *PluginsState
		wantIP       string
		wantOK       bool
	}{
		{
			name: "nil clientAddr should return empty",
			pluginsState: &PluginsState{
				clientProto: "tcp",
				clientAddr:  nil,
			},
			wantIP: "",
			wantOK: false,
		},
		{
			name: "valid UDP address",
			pluginsState: &PluginsState{
				clientProto: "udp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.UDPAddr{
							IP:   net.ParseIP("192.168.1.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "192.168.1.1",
			wantOK: true,
		},
		{
			name: "valid TCP address",
			pluginsState: &PluginsState{
				clientProto: "tcp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.TCPAddr{
							IP:   net.ParseIP("10.0.0.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "10.0.0.1",
			wantOK: true,
		},
		{
			name: "unknown protocol",
			pluginsState: &PluginsState{
				clientProto: "unknown",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.TCPAddr{
							IP:   net.ParseIP("10.0.0.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotOK := ExtractClientIPStr(tt.pluginsState)
			if gotIP != tt.wantIP {
				t.Errorf("ExtractClientIPStr() IP = %v, want %v", gotIP, tt.wantIP)
			}
			if gotOK != tt.wantOK {
				t.Errorf("ExtractClientIPStr() OK = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

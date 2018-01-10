package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	ServerNames      []string `toml:"server_names"`
	ListenAddresses  []string `toml:"listen_addresses"`
	Daemonize        bool
	ForceTCP         bool                    `toml:"force_tcp"`
	Timeout          int                     `toml:"timeout_ms"`
	CertRefreshDelay int                     `toml:"cert_refresh_delay"`
	ServersConfig    map[string]ServerConfig `toml:"servers"`
}

func newConfig() Config {
	return Config{
		ListenAddresses:  []string{"127.0.0.1:53"},
		Timeout:          2500,
		CertRefreshDelay: 30,
	}
}

type ServerConfig struct {
	Stamp        string
	ProviderName string `toml:"provider_name"`
	Address      string
	PublicKey    string `toml:"public_key"`
	NoLog        bool   `toml:"no_log"`
	DNSSEC       bool   `toml:"dnssec"`
}

func ConfigLoad(proxy *Proxy, config_file string) error {
	configFile := flag.String("config", "/etc/dnscrypt-proxy/dnscrypt-proxy.toml", "path to the configuration file")
	flag.Parse()
	config := newConfig()
	if _, err := toml.DecodeFile(*configFile, &config); err != nil {
		log.Println(err)
		return err
	}
	proxy.timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.mainProto = "udp"
	if config.ForceTCP {
		proxy.mainProto = "tcp"
	}
	proxy.certRefreshDelay = time.Duration(config.CertRefreshDelay) * time.Minute
	if len(config.ListenAddresses) == 0 {
		return errors.New("No local IP/port configured")
	}
	proxy.listenAddresses = config.ListenAddresses
	proxy.daemonize = config.Daemonize
	if len(config.ServerNames) == 0 {
		for serverName := range config.ServersConfig {
			config.ServerNames = append(config.ServerNames, serverName)
		}
	}
	if len(config.ServerNames) == 0 {
		return errors.New("No servers configured")
	}
	for _, serverName := range config.ServerNames {
		serverConfig, ok := config.ServersConfig[serverName]
		if !ok {
			return fmt.Errorf("No definitions found for server [%v]", serverName)
		}
		var stamp ServerStamp
		var err error
		if len(serverConfig.Stamp) > 0 {
			panic("Stamps are not implemented yet")
		} else {
			stamp, err = NewServerStampFromLegacy(serverConfig.Address, serverConfig.PublicKey, serverConfig.ProviderName)
			if err != nil {
				return err
			}
		}
		proxy.registeredServers = append(proxy.registeredServers,
			RegisteredServer{name: serverName, stamp: stamp})
	}
	return nil
}

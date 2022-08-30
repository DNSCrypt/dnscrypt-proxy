package quic

import (
	"errors"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// Clone clones a Config
func (c *Config) Clone() *Config {
	copy := *c
	return &copy
}

func (c *Config) handshakeTimeout() time.Duration {
	return utils.Max(protocol.DefaultHandshakeTimeout, 2*c.HandshakeIdleTimeout)
}

func validateConfig(config *Config) error {
	if config == nil {
		return nil
	}
	if config.MaxIncomingStreams > 1<<60 {
		return errors.New("invalid value for Config.MaxIncomingStreams")
	}
	if config.MaxIncomingUniStreams > 1<<60 {
		return errors.New("invalid value for Config.MaxIncomingUniStreams")
	}
	return nil
}

// populateServerConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateServerConfig(config *Config) *Config {
	config = populateConfig(config, protocol.DefaultConnectionIDLength)
	if config.MaxTokenAge == 0 {
		config.MaxTokenAge = protocol.TokenValidity
	}
	if config.MaxRetryTokenAge == 0 {
		config.MaxRetryTokenAge = protocol.RetryTokenValidity
	}
	if config.RequireAddressValidation == nil {
		config.RequireAddressValidation = func(net.Addr) bool { return false }
	}
	return config
}

// populateClientConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateClientConfig(config *Config, createdPacketConn bool) *Config {
	defaultConnIDLen := protocol.DefaultConnectionIDLength
	if createdPacketConn {
		defaultConnIDLen = 0
	}

	config = populateConfig(config, defaultConnIDLen)
	return config
}

func populateConfig(config *Config, defaultConnIDLen int) *Config {
	if config == nil {
		config = &Config{}
	}
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}
	conIDLen := config.ConnectionIDLength
	if config.ConnectionIDLength == 0 {
		conIDLen = defaultConnIDLen
	}
	handshakeIdleTimeout := protocol.DefaultHandshakeIdleTimeout
	if config.HandshakeIdleTimeout != 0 {
		handshakeIdleTimeout = config.HandshakeIdleTimeout
	}
	idleTimeout := protocol.DefaultIdleTimeout
	if config.MaxIdleTimeout != 0 {
		idleTimeout = config.MaxIdleTimeout
	}
	initialStreamReceiveWindow := config.InitialStreamReceiveWindow
	if initialStreamReceiveWindow == 0 {
		initialStreamReceiveWindow = protocol.DefaultInitialMaxStreamData
	}
	maxStreamReceiveWindow := config.MaxStreamReceiveWindow
	if maxStreamReceiveWindow == 0 {
		maxStreamReceiveWindow = protocol.DefaultMaxReceiveStreamFlowControlWindow
	}
	initialConnectionReceiveWindow := config.InitialConnectionReceiveWindow
	if initialConnectionReceiveWindow == 0 {
		initialConnectionReceiveWindow = protocol.DefaultInitialMaxData
	}
	maxConnectionReceiveWindow := config.MaxConnectionReceiveWindow
	if maxConnectionReceiveWindow == 0 {
		maxConnectionReceiveWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindow
	}
	maxIncomingStreams := config.MaxIncomingStreams
	if maxIncomingStreams == 0 {
		maxIncomingStreams = protocol.DefaultMaxIncomingStreams
	} else if maxIncomingStreams < 0 {
		maxIncomingStreams = 0
	}
	maxIncomingUniStreams := config.MaxIncomingUniStreams
	if maxIncomingUniStreams == 0 {
		maxIncomingUniStreams = protocol.DefaultMaxIncomingUniStreams
	} else if maxIncomingUniStreams < 0 {
		maxIncomingUniStreams = 0
	}
	connIDGenerator := config.ConnectionIDGenerator
	if connIDGenerator == nil {
		connIDGenerator = &protocol.DefaultConnectionIDGenerator{ConnLen: conIDLen}
	}

	return &Config{
		Versions:                         versions,
		HandshakeIdleTimeout:             handshakeIdleTimeout,
		MaxIdleTimeout:                   idleTimeout,
		MaxTokenAge:                      config.MaxTokenAge,
		MaxRetryTokenAge:                 config.MaxRetryTokenAge,
		RequireAddressValidation:         config.RequireAddressValidation,
		KeepAlivePeriod:                  config.KeepAlivePeriod,
		InitialStreamReceiveWindow:       initialStreamReceiveWindow,
		MaxStreamReceiveWindow:           maxStreamReceiveWindow,
		InitialConnectionReceiveWindow:   initialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:       maxConnectionReceiveWindow,
		AllowConnectionWindowIncrease:    config.AllowConnectionWindowIncrease,
		MaxIncomingStreams:               maxIncomingStreams,
		MaxIncomingUniStreams:            maxIncomingUniStreams,
		ConnectionIDLength:               conIDLen,
		ConnectionIDGenerator:            connIDGenerator,
		StatelessResetKey:                config.StatelessResetKey,
		TokenStore:                       config.TokenStore,
		EnableDatagrams:                  config.EnableDatagrams,
		DisablePathMTUDiscovery:          config.DisablePathMTUDiscovery,
		DisableVersionNegotiationPackets: config.DisableVersionNegotiationPackets,
		Tracer:                           config.Tracer,
	}
}

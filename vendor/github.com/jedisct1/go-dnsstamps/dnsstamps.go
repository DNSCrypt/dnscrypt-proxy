package dnsstamps

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	DefaultPort    = 443
	DefaultDoTPort = 853
	DefaultDNSPort = 53
	StampScheme    = "sdns://"
)

type ServerInformalProperties uint64

const (
	ServerInformalPropertyDNSSEC   = ServerInformalProperties(1) << 0
	ServerInformalPropertyNoLog    = ServerInformalProperties(1) << 1
	ServerInformalPropertyNoFilter = ServerInformalProperties(1) << 2
)

type StampProtoType uint8

const (
	StampProtoTypePlain         = StampProtoType(0x00)
	StampProtoTypeDNSCrypt      = StampProtoType(0x01)
	StampProtoTypeDoH           = StampProtoType(0x02)
	StampProtoTypeTLS           = StampProtoType(0x03)
	StampProtoTypeDoQ           = StampProtoType(0x04)
	StampProtoTypeODoHTarget    = StampProtoType(0x05)
	StampProtoTypeDNSCryptRelay = StampProtoType(0x81)
	StampProtoTypeODoHRelay     = StampProtoType(0x85)
)

func (stampProtoType *StampProtoType) String() string {
	switch *stampProtoType {
	case StampProtoTypePlain:
		return "Plain"
	case StampProtoTypeDNSCrypt:
		return "DNSCrypt"
	case StampProtoTypeDoH:
		return "DoH"
	case StampProtoTypeTLS:
		return "TLS"
	case StampProtoTypeDoQ:
		return "QUIC"
	case StampProtoTypeODoHTarget:
		return "oDoH target"
	case StampProtoTypeDNSCryptRelay:
		return "DNSCrypt relay"
	case StampProtoTypeODoHRelay:
		return "oDoH relay"
	default:
		return "(unknown)"
	}
}

type ServerStamp struct {
	ServerAddrStr string
	ServerPk      []uint8
	Hashes        [][]uint8
	ProviderName  string
	Path          string
	Props         ServerInformalProperties
	Proto         StampProtoType
	BootstrapIPs  []string
}

func NewDNSCryptServerStampFromLegacy(serverAddrStr string, serverPkStr string, providerName string, props ServerInformalProperties) (ServerStamp, error) {
	if net.ParseIP(serverAddrStr) != nil {
		serverAddrStr = fmt.Sprintf("%s:%d", serverAddrStr, DefaultPort)
	}
	serverPk, err := hex.DecodeString(strings.ReplaceAll(serverPkStr, ":", ""))
	if err != nil || len(serverPk) != 32 {
		return ServerStamp{}, fmt.Errorf("Unsupported public key: [%s]", serverPkStr)
	}
	return ServerStamp{
		ServerAddrStr: serverAddrStr,
		ServerPk:      serverPk,
		ProviderName:  providerName,
		Props:         props,
		Proto:         StampProtoTypeDNSCrypt,
	}, nil
}

func NewServerStampFromString(stampStr string) (ServerStamp, error) {
	if !strings.HasPrefix(stampStr, "sdns:") {
		return ServerStamp{}, errors.New("Stamps are expected to start with \"sdns:\"")
	}
	stampStr = stampStr[5:]
	stampStr = strings.TrimPrefix(stampStr, "//")
	bin, err := base64.RawURLEncoding.Strict().DecodeString(stampStr)
	if err != nil {
		return ServerStamp{}, err
	}
	if len(bin) < 1 {
		return ServerStamp{}, errors.New("Stamp is too short")
	}

	if bin[0] == uint8(StampProtoTypePlain) {
		return newPlainDNSServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDNSCrypt) {
		return newDNSCryptServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDoH) {
		return newDoHServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeTLS) {
		return newDoTServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDoQ) {
		return newDoQServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeODoHTarget) {
		return newODoHTargetStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDNSCryptRelay) {
		return newDNSCryptRelayStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeODoHRelay) {
		return newODoHRelayStamp(bin)
	}
	return ServerStamp{}, errors.New("Unsupported stamp version or protocol")
}

func NewRelayAndServerStampFromString(stampStr string) (ServerStamp, ServerStamp, error) {
	if !strings.HasPrefix(stampStr, StampScheme) {
		return ServerStamp{}, ServerStamp{}, errors.New("Stamps are expected to start with \"sdns://\"")
	}
	stampStr = stampStr[7:]
	parts := strings.Split(stampStr, "/")
	if len(parts) != 2 {
		return ServerStamp{}, ServerStamp{}, errors.New("This is not a relay+server stamp")
	}
	relayStamp, err := NewServerStampFromString(StampScheme + parts[0])
	if err != nil {
		return ServerStamp{}, ServerStamp{}, err
	}
	serverStamp, err := NewServerStampFromString(StampScheme + parts[1])
	if err != nil {
		return ServerStamp{}, ServerStamp{}, err
	}
	if relayStamp.Proto != StampProtoTypeDNSCryptRelay && relayStamp.Proto != StampProtoTypeODoHRelay {
		return ServerStamp{}, ServerStamp{}, errors.New("First stamp is not a relay")
	}
	if serverStamp.Proto == StampProtoTypeDNSCryptRelay || serverStamp.Proto == StampProtoTypeODoHRelay {
		return ServerStamp{}, ServerStamp{}, errors.New("Second stamp is a relay")
	}
	return relayStamp, serverStamp, nil
}

// id(u8)=0x00 props 0x00 addrLen(1) serverAddr
func newPlainDNSServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypePlain}
	if len(bin) < 1+8+1+1 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length > binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
	bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
	if colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(stamp.ServerAddrStr) // DefaultDNSPort
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultDNSPort)
	}
	if colIndex >= len(stamp.ServerAddrStr)-1 {
		return stamp, errors.New("Invalid stamp (empty port)")
	}
	ipOnly := stamp.ServerAddrStr[:colIndex]
	if err := validatePort(stamp.ServerAddrStr[colIndex+1:]); err != nil {
		return stamp, errors.New("Invalid stamp (port range)")
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return stamp, errors.New("Invalid stamp (IP address)")
	}
	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// id(u8)=0x01 props addrLen(1) serverAddr pkStrlen(1) pkStr providerNameLen(1) providerName

func newDNSCryptServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDNSCrypt}
	if len(bin) < 66 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
	bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
	if colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(stamp.ServerAddrStr)
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
	}
	if colIndex >= len(stamp.ServerAddrStr)-1 {
		return stamp, errors.New("Invalid stamp (empty port)")
	}
	ipOnly := stamp.ServerAddrStr[:colIndex]
	if err := validatePort(stamp.ServerAddrStr[colIndex+1:]); err != nil {
		return stamp, errors.New("Invalid stamp (port range)")
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return stamp, errors.New("Invalid stamp (IP address)")
	}

	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerPk = bin[pos : pos+length]
	pos += length

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// id(u8)=0x02 props addrLen(1) serverAddr hashLen(1) hash hostNameLen(1) hostName pathLen(1) path

func newDoHServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDoH}
	if len(bin) < 15 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	for {
		vlen := int(bin[pos])
		length = vlen & ^0x80
		if 1+length >= binLen-pos {
			return stamp, errors.New("Invalid stamp")
		}
		pos++
		if length > 0 {
			if length != 32 {
				return stamp, errors.New("Invalid stamp (certificate hash must be 32 bytes)")
			}
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+length])
		}
		pos += length
		if vlen&0x80 != 0x80 {
			break
		}
	}

	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.Path = string(bin[pos : pos+length])
	pos += length

	// Parse optional bootstrap IP addresses (VLP format)
	if pos < binLen {
		for {
			if pos >= binLen {
				break
			}
			vlen := int(bin[pos])
			length = vlen & ^0x80
			if 1+length > binLen-pos {
				return stamp, errors.New("Invalid stamp")
			}
			pos++
			if length > 0 {
				bootstrapIP := string(bin[pos : pos+length])
				stamp.BootstrapIPs = append(stamp.BootstrapIPs, bootstrapIP)
			}
			pos += length
			if vlen&0x80 != 0x80 {
				break
			}
		}
	}

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if err := validateAddrAndHostname(stamp.ServerAddrStr, stamp.ProviderName); err != nil {
		return stamp, err
	}

	return stamp, nil
}

// id(u8)=0x03 props addrLen(1) serverAddr hashLen(1) hash hostNameLen(1) hostName [ bootstrapLen(1) bootstrap ]

func newDoTServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeTLS}
	if len(bin) < 13 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	for {
		vlen := int(bin[pos])
		length = vlen & ^0x80
		if 1+length >= binLen-pos {
			return stamp, errors.New("Invalid stamp")
		}
		pos++
		if length > 0 {
			if length != 32 {
				return stamp, errors.New("Invalid stamp (certificate hash must be 32 bytes)")
			}
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+length])
		}
		pos += length
		if vlen&0x80 != 0x80 {
			break
		}
	}

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	// Parse optional bootstrap IP addresses (VLP format)
	if pos < binLen {
		for {
			if pos >= binLen {
				break
			}
			vlen := int(bin[pos])
			length = vlen & ^0x80
			if 1+length > binLen-pos {
				return stamp, errors.New("Invalid stamp")
			}
			pos++
			if length > 0 {
				bootstrapIP := string(bin[pos : pos+length])
				stamp.BootstrapIPs = append(stamp.BootstrapIPs, bootstrapIP)
			}
			pos += length
			if vlen&0x80 != 0x80 {
				break
			}
		}
	}

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if err := validateAddrAndHostname(stamp.ServerAddrStr, stamp.ProviderName); err != nil {
		return stamp, err
	}

	return stamp, nil
}

// id(u8)=0x04 props addrLen(1) serverAddr hashLen(1) hash hostNameLen(1) hostName [ bootstrapLen(1) bootstrap ]

func newDoQServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDoQ}
	if len(bin) < 13 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	for {
		vlen := int(bin[pos])
		length = vlen & ^0x80
		if 1+length >= binLen-pos {
			return stamp, errors.New("Invalid stamp")
		}
		pos++
		if length > 0 {
			if length != 32 {
				return stamp, errors.New("Invalid stamp (certificate hash must be 32 bytes)")
			}
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+length])
		}
		pos += length
		if vlen&0x80 != 0x80 {
			break
		}
	}

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	// Parse optional bootstrap IP addresses (VLP format)
	if pos < binLen {
		for {
			if pos >= binLen {
				break
			}
			vlen := int(bin[pos])
			length = vlen & ^0x80
			if 1+length > binLen-pos {
				return stamp, errors.New("Invalid stamp")
			}
			pos++
			if length > 0 {
				bootstrapIP := string(bin[pos : pos+length])
				stamp.BootstrapIPs = append(stamp.BootstrapIPs, bootstrapIP)
			}
			pos += length
			if vlen&0x80 != 0x80 {
				break
			}
		}
	}

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if err := validateAddrAndHostname(stamp.ServerAddrStr, stamp.ProviderName); err != nil {
		return stamp, err
	}

	return stamp, nil
}

// id(u8)=0x05 props hostNameLen(1) hostName pathLen(1) path

func newODoHTargetStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeODoHTarget}
	if len(bin) < 12 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.Path = string(bin[pos : pos+length])
	pos += length

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if _, err := stripAndValidatePort(stamp.ProviderName); err != nil {
		return stamp, err
	}

	return stamp, nil
}

// id(u8)=0x81 addrLen(1) serverAddr

func newDNSCryptRelayStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDNSCryptRelay}
	if len(bin) < 9 {
		return stamp, errors.New("Stamp is too short")
	}
	binLen := len(bin)
	pos := 1
	length := int(bin[pos])
	if 1+length > binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
	bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
	if colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(stamp.ServerAddrStr)
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
	}
	if colIndex >= len(stamp.ServerAddrStr)-1 {
		return stamp, errors.New("Invalid stamp (empty port)")
	}
	ipOnly := stamp.ServerAddrStr[:colIndex]
	if err := validatePort(stamp.ServerAddrStr[colIndex+1:]); err != nil {
		return stamp, errors.New("Invalid stamp (port range)")
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return stamp, errors.New("Invalid stamp (IP address)")
	}
	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// id(u8)=0x85 props addrLen(1) serverAddr hashLen(1) hash hostNameLen(1) hostName pathLen(1) path

func newODoHRelayStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeODoHRelay}
	if len(bin) < 13 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	for {
		vlen := int(bin[pos])
		length = vlen & ^0x80
		if 1+length >= binLen-pos {
			return stamp, errors.New("Invalid stamp")
		}
		pos++
		if length > 0 {
			if length != 32 {
				return stamp, errors.New("Invalid stamp (certificate hash must be 32 bytes)")
			}
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+length])
		}
		pos += length
		if vlen&0x80 != 0x80 {
			break
		}
	}

	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.Path = string(bin[pos : pos+length])
	pos += length

	// Parse optional bootstrap IP addresses (VLP format)
	if pos < binLen {
		for {
			if pos >= binLen {
				break
			}
			vlen := int(bin[pos])
			length = vlen & ^0x80
			if 1+length > binLen-pos {
				return stamp, errors.New("Invalid stamp")
			}
			pos++
			if length > 0 {
				bootstrapIP := string(bin[pos : pos+length])
				stamp.BootstrapIPs = append(stamp.BootstrapIPs, bootstrapIP)
			}
			pos += length
			if vlen&0x80 != 0x80 {
				break
			}
		}
	}

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if err := validateAddrAndHostname(stamp.ServerAddrStr, stamp.ProviderName); err != nil {
		return stamp, err
	}

	return stamp, nil
}

func validatePort(port string) error {
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return errors.New("Invalid port")
	}
	return nil
}

func splitOptionalPort(s string) (host, port string) {
	colIndex := strings.LastIndex(s, ":")
	bracketIndex := strings.LastIndex(s, "]")
	if colIndex < bracketIndex || colIndex < 0 {
		return s, ""
	}
	return s[:colIndex], s[colIndex+1:]
}

func stripAndValidatePort(s string) (string, error) {
	host, port := splitOptionalPort(s)
	if port == "" {
		if strings.HasSuffix(s, ":") {
			return "", errors.New("Invalid stamp (empty port)")
		}
		return s, nil
	}
	if err := validatePort(port); err != nil {
		return "", errors.New("Invalid stamp (port range)")
	}
	return host, nil
}

func validateAddrAndHostname(addr, hostname string) error {
	if len(addr) > 0 {
		ip := addr
		if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
			ip = ip[1 : len(ip)-1]
		} else if strings.ContainsRune(ip, ':') {
			return errors.New("Invalid stamp (IP address)")
		}
		if net.ParseIP(ip) == nil {
			return errors.New("Invalid stamp (IP address)")
		}
	}
	if _, err := stripAndValidatePort(hostname); err != nil {
		return err
	}
	return nil
}

func stripDefaultPort(s string, defaultPort int) string {
	return strings.TrimSuffix(s, ":"+strconv.Itoa(defaultPort))
}

func encodeAddrAndHostname(addr, hostname string, defaultPort int) (string, string) {
	if host, port := splitOptionalPort(addr); port != "" {
		addr = host
		if hostname != "" {
			if _, hostPort := splitOptionalPort(hostname); hostPort == "" {
				hostname = hostname + ":" + port
			}
		}
	}
	return addr, stripDefaultPort(hostname, defaultPort)
}

func appendHashes(bin []uint8, hashes [][]uint8) []uint8 {
	if len(hashes) == 0 {
		return append(bin, uint8(0))
	}
	last := len(hashes) - 1
	for i, hash := range hashes {
		vlen := len(hash)
		if i < last {
			vlen |= 0x80
		}
		bin = append(bin, uint8(vlen))
		bin = append(bin, hash...)
	}
	return bin
}

func appendBootstrapIPs(bin []uint8, bootstrapIPs []string) []uint8 {
	last := len(bootstrapIPs) - 1
	for i, bootstrapIP := range bootstrapIPs {
		vlen := len(bootstrapIP)
		if i < last {
			vlen |= 0x80
		}
		bin = append(bin, uint8(vlen))
		bin = append(bin, []uint8(bootstrapIP)...)
	}
	return bin
}

func (stamp *ServerStamp) String() string {
	if stamp.Proto == StampProtoTypePlain {
		return stamp.plainStrng()
	} else if stamp.Proto == StampProtoTypeDNSCrypt {
		return stamp.dnsCryptString()
	} else if stamp.Proto == StampProtoTypeDoH {
		return stamp.dohString()
	} else if stamp.Proto == StampProtoTypeTLS {
		return stamp.dotString()
	} else if stamp.Proto == StampProtoTypeDoQ {
		return stamp.doqString()
	} else if stamp.Proto == StampProtoTypeODoHTarget {
		return stamp.oDohTargetString()
	} else if stamp.Proto == StampProtoTypeDNSCryptRelay {
		return stamp.dnsCryptRelayString()
	} else if stamp.Proto == StampProtoTypeODoHRelay {
		return stamp.oDohRelayString()
	}
	panic("Unsupported protocol")
}

func (stamp *ServerStamp) plainStrng() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypePlain)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	serverAddrStr := stripDefaultPort(stamp.ServerAddrStr, DefaultDNSPort)
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)
	str := base64.RawURLEncoding.EncodeToString(bin)

	return StampScheme + str
}

func (stamp *ServerStamp) dnsCryptString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeDNSCrypt)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	serverAddrStr := stripDefaultPort(stamp.ServerAddrStr, DefaultPort)
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	bin = append(bin, uint8(len(stamp.ServerPk)))
	bin = append(bin, stamp.ServerPk...)

	bin = append(bin, uint8(len(stamp.ProviderName)))
	bin = append(bin, []uint8(stamp.ProviderName)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return StampScheme + str
}

func (stamp *ServerStamp) dohString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeDoH)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	addr, providerName := encodeAddrAndHostname(stamp.ServerAddrStr, stamp.ProviderName, DefaultPort)
	bin = append(bin, uint8(len(addr)))
	bin = append(bin, []uint8(addr)...)

	bin = appendHashes(bin, stamp.Hashes)

	bin = append(bin, uint8(len(providerName)))
	bin = append(bin, []uint8(providerName)...)

	bin = append(bin, uint8(len(stamp.Path)))
	bin = append(bin, []uint8(stamp.Path)...)

	bin = appendBootstrapIPs(bin, stamp.BootstrapIPs)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return StampScheme + str
}

func (stamp *ServerStamp) dotString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeTLS)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	addr, providerName := encodeAddrAndHostname(stamp.ServerAddrStr, stamp.ProviderName, DefaultDoTPort)
	bin = append(bin, uint8(len(addr)))
	bin = append(bin, []uint8(addr)...)

	bin = appendHashes(bin, stamp.Hashes)

	bin = append(bin, uint8(len(providerName)))
	bin = append(bin, []uint8(providerName)...)

	bin = appendBootstrapIPs(bin, stamp.BootstrapIPs)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return StampScheme + str
}

func (stamp *ServerStamp) doqString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeDoQ)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	addr, providerName := encodeAddrAndHostname(stamp.ServerAddrStr, stamp.ProviderName, DefaultDoTPort)
	bin = append(bin, uint8(len(addr)))
	bin = append(bin, []uint8(addr)...)

	bin = appendHashes(bin, stamp.Hashes)

	bin = append(bin, uint8(len(providerName)))
	bin = append(bin, []uint8(providerName)...)

	bin = appendBootstrapIPs(bin, stamp.BootstrapIPs)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return StampScheme + str
}

func (stamp *ServerStamp) oDohTargetString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeODoHTarget)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	providerName := stripDefaultPort(stamp.ProviderName, DefaultPort)
	bin = append(bin, uint8(len(providerName)))
	bin = append(bin, []uint8(providerName)...)

	bin = append(bin, uint8(len(stamp.Path)))
	bin = append(bin, []uint8(stamp.Path)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return StampScheme + str
}

func (stamp *ServerStamp) dnsCryptRelayString() string {
	bin := make([]uint8, 1)
	bin[0] = uint8(StampProtoTypeDNSCryptRelay)

	serverAddrStr := stripDefaultPort(stamp.ServerAddrStr, DefaultPort)
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return StampScheme + str
}

func (stamp *ServerStamp) oDohRelayString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeODoHRelay)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	addr, providerName := encodeAddrAndHostname(stamp.ServerAddrStr, stamp.ProviderName, DefaultPort)
	bin = append(bin, uint8(len(addr)))
	bin = append(bin, []uint8(addr)...)

	bin = appendHashes(bin, stamp.Hashes)

	bin = append(bin, uint8(len(providerName)))
	bin = append(bin, []uint8(providerName)...)

	bin = append(bin, uint8(len(stamp.Path)))
	bin = append(bin, []uint8(stamp.Path)...)

	bin = appendBootstrapIPs(bin, stamp.BootstrapIPs)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return StampScheme + str
}

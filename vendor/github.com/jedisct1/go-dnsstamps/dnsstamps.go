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

const DefaultPort = 443

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
}

func NewDNSCryptServerStampFromLegacy(serverAddrStr string, serverPkStr string, providerName string, props ServerInformalProperties) (ServerStamp, error) {
	if net.ParseIP(serverAddrStr) != nil {
		serverAddrStr = fmt.Sprintf("%s:%d", serverAddrStr, DefaultPort)
	}
	serverPk, err := hex.DecodeString(strings.Replace(serverPkStr, ":", "", -1))
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
	if bin[0] == uint8(StampProtoTypeDNSCrypt) {
		return newDNSCryptServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDoH) {
		return newDoHServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeODoHTarget) {
		return newODoHTargetStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDNSCryptRelay) {
		return newDNSCryptRelayStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeODoHRelay) {
		return newODoHRelayStamp(bin)
	}
	return ServerStamp{}, errors.New("Unsupported stamp version or protocol")
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
	portOnly := stamp.ServerAddrStr[colIndex+1:]
	if _, err := strconv.ParseUint(portOnly, 10, 16); err != nil {
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
	if len(bin) < 22 {
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

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if len(stamp.ServerAddrStr) > 0 {
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
		portOnly := stamp.ServerAddrStr[colIndex+1:]
		if _, err := strconv.ParseUint(portOnly, 10, 16); err != nil {
			return stamp, errors.New("Invalid stamp (port range)")
		}
		if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
			return stamp, errors.New("Invalid stamp (IP address)")
		}
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

	return stamp, nil
}

// id(u8)=0x81 addrLen(1) serverAddr

func newDNSCryptRelayStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDNSCryptRelay}
	if len(bin) < 13 {
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
	portOnly := stamp.ServerAddrStr[colIndex+1:]
	if _, err := strconv.ParseUint(portOnly, 10, 16); err != nil {
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

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if len(stamp.ServerAddrStr) > 0 {
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
		portOnly := stamp.ServerAddrStr[colIndex+1:]
		if _, err := strconv.ParseUint(portOnly, 10, 16); err != nil {
			return stamp, errors.New("Invalid stamp (port range)")
		}
		if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
			return stamp, errors.New("Invalid stamp (IP address)")
		}
	}

	return stamp, nil
}

func (stamp *ServerStamp) String() string {
	if stamp.Proto == StampProtoTypeDNSCrypt {
		return stamp.dnsCryptString()
	} else if stamp.Proto == StampProtoTypeDoH {
		return stamp.dohString()
	} else if stamp.Proto == StampProtoTypeODoHTarget {
		return stamp.oDohTargetString()
	} else if stamp.Proto == StampProtoTypeDNSCryptRelay {
		return stamp.dnsCryptRelayString()
	} else if stamp.Proto == StampProtoTypeODoHRelay {
		return stamp.oDohRelayString()
	}
	panic("Unsupported protocol")
}

func (stamp *ServerStamp) dnsCryptString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeDNSCrypt)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	serverAddrStr := stamp.ServerAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(DefaultPort)) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(DefaultPort))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	bin = append(bin, uint8(len(stamp.ServerPk)))
	bin = append(bin, stamp.ServerPk...)

	bin = append(bin, uint8(len(stamp.ProviderName)))
	bin = append(bin, []uint8(stamp.ProviderName)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "sdns://" + str
}

func (stamp *ServerStamp) dohString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeDoH)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	serverAddrStr := stamp.ServerAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(DefaultPort)) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(DefaultPort))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	if len(stamp.Hashes) == 0 {
		bin = append(bin, uint8(0))
	} else {
		last := len(stamp.Hashes) - 1
		for i, hash := range stamp.Hashes {
			vlen := len(hash)
			if i < last {
				vlen |= 0x80
			}
			bin = append(bin, uint8(vlen))
			bin = append(bin, hash...)
		}
	}

	bin = append(bin, uint8(len(stamp.ProviderName)))
	bin = append(bin, []uint8(stamp.ProviderName)...)

	bin = append(bin, uint8(len(stamp.Path)))
	bin = append(bin, []uint8(stamp.Path)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "sdns://" + str
}

func (stamp *ServerStamp) oDohTargetString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeODoHTarget)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	bin = append(bin, uint8(len(stamp.ProviderName)))
	bin = append(bin, []uint8(stamp.ProviderName)...)

	bin = append(bin, uint8(len(stamp.Path)))
	bin = append(bin, []uint8(stamp.Path)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "sdns://" + str
}

func (stamp *ServerStamp) dnsCryptRelayString() string {
	bin := make([]uint8, 1)
	bin[0] = uint8(StampProtoTypeDNSCryptRelay)

	serverAddrStr := stamp.ServerAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(DefaultPort)) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(DefaultPort))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "sdns://" + str
}

func (stamp *ServerStamp) oDohRelayString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeODoHRelay)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	serverAddrStr := stamp.ServerAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(DefaultPort)) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(DefaultPort))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	if len(stamp.Hashes) == 0 {
		bin = append(bin, uint8(0))
	} else {
		last := len(stamp.Hashes) - 1
		for i, hash := range stamp.Hashes {
			vlen := len(hash)
			if i < last {
				vlen |= 0x80
			}
			bin = append(bin, uint8(vlen))
			bin = append(bin, hash...)
		}
	}

	bin = append(bin, uint8(len(stamp.ProviderName)))
	bin = append(bin, []uint8(stamp.ProviderName)...)

	bin = append(bin, uint8(len(stamp.Path)))
	bin = append(bin, []uint8(stamp.Path)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "sdns://" + str
}

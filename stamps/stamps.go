package stamps

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/crypto/ed25519"
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
	StampProtoTypePlain    = StampProtoType(0x00)
	StampProtoTypeDNSCrypt = StampProtoType(0x01)
	StampProtoTypeDoH      = StampProtoType(0x02)
)

func (stampProtoType *StampProtoType) String() string {
	switch *stampProtoType {
	case StampProtoTypePlain:
		return "Plain"
	case StampProtoTypeDNSCrypt:
		return "DNSCrypt"
	case StampProtoTypeDoH:
		return "DoH"
	default:
		panic("Unexpected protocol")
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
	if err != nil || len(serverPk) != ed25519.PublicKeySize {
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
	if !strings.HasPrefix(stampStr, "sdns://") && !strings.HasPrefix(stampStr, "dnsc://") {
		return ServerStamp{}, errors.New("Stamps are expected to start with sdns://")
	}
	bin, err := base64.RawURLEncoding.DecodeString(stampStr[7:])
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

	len := int(bin[pos])
	if 1+len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+len])
	pos += len
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(stamp.ServerAddrStr, "["), "]")) != nil {
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
	}

	len = int(bin[pos])
	if 1+len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerPk = bin[pos : pos+len]
	pos += len

	len = int(bin[pos])
	if len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+len])
	pos += len

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// id(u8)=0x02 props addrLen(1) serverAddr hashLen(1) hash providerNameLen(1) providerName pathLen(1) path

func newDoHServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDoH}
	if len(bin) < 22 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	len := int(bin[pos])
	if 1+len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+len])
	pos += len

	for {
		vlen := int(bin[pos])
		len = vlen & ^0x80
		if 1+len >= binLen-pos {
			return stamp, errors.New("Invalid stamp")
		}
		pos++
		if len > 0 {
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+len])
		}
		pos += len
		if vlen&0x80 != 0x80 {
			break
		}
	}

	len = int(bin[pos])
	if 1+len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+len])
	pos += len

	len = int(bin[pos])
	if len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.Path = string(bin[pos : pos+len])
	pos += len

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if net.ParseIP(strings.TrimRight(strings.TrimLeft(stamp.ServerAddrStr, "["), "]")) != nil {
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
	}

	return stamp, nil
}

func (stamp *ServerStamp) String() string {
	if stamp.Proto == StampProtoTypeDNSCrypt {
		return stamp.dnsCryptString()
	} else if stamp.Proto == StampProtoTypeDoH {
		return stamp.dohString()
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

	last := len(stamp.Hashes) - 1
	for i, hash := range stamp.Hashes {
		vlen := len(hash)
		if i < last {
			vlen |= 0x80
		}
		bin = append(bin, uint8(vlen))
		bin = append(bin, hash...)
	}

	bin = append(bin, uint8(len(stamp.ProviderName)))
	bin = append(bin, []uint8(stamp.ProviderName)...)

	bin = append(bin, uint8(len(stamp.Path)))
	bin = append(bin, []uint8(stamp.Path)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "sdns://" + str
}

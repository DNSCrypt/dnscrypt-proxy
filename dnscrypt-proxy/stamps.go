package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/jedisct1/dlog"
	"golang.org/x/crypto/ed25519"
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
	serverAddrStr string
	serverPk      []uint8
	hashes        [][]uint8
	providerName  string
	path          string
	props         ServerInformalProperties
	proto         StampProtoType
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
		serverAddrStr: serverAddrStr,
		serverPk:      serverPk,
		providerName:  providerName,
		props:         props,
		proto:         StampProtoTypeDNSCrypt,
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
	stamp := ServerStamp{proto: StampProtoTypeDNSCrypt}
	if len(bin) < 66 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	len := int(bin[pos])
	if 1+len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.serverAddrStr = string(bin[pos : pos+len])
	pos += len
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(stamp.serverAddrStr, "["), "]")) != nil {
		stamp.serverAddrStr = fmt.Sprintf("%s:%d", stamp.serverAddrStr, DefaultPort)
	}

	len = int(bin[pos])
	if 1+len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.serverPk = bin[pos : pos+len]
	pos += len

	len = int(bin[pos])
	if len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.providerName = string(bin[pos : pos+len])
	pos += len

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// id(u8)=0x02 props addrLen(1) serverAddr hashLen(1) hash providerNameLen(1) providerName pathLen(1) path

func newDoHServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{proto: StampProtoTypeDoH, hashes: [][]byte{}}
	if len(bin) < 22 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	len := int(bin[pos])
	if 1+len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.serverAddrStr = string(bin[pos : pos+len])
	pos += len

	for {
		vlen := int(bin[pos])
		len = vlen & ^0x80
		if 1+len >= binLen-pos {
			return stamp, errors.New("Invalid stamp")
		}
		pos++
		if len > 0 {
			stamp.hashes = append(stamp.hashes, bin[pos:pos+len])
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
	stamp.providerName = string(bin[pos : pos+len])
	pos += len

	len = int(bin[pos])
	if len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.path = string(bin[pos : pos+len])
	pos += len

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if net.ParseIP(strings.TrimRight(strings.TrimLeft(stamp.serverAddrStr, "["), "]")) != nil {
		stamp.serverAddrStr = fmt.Sprintf("%s:%d", stamp.serverAddrStr, DefaultPort)
	}

	return stamp, nil
}

func (stamp *ServerStamp) String() string {
	if stamp.proto == StampProtoTypeDNSCrypt {
		return stamp.dnsCryptString()
	} else if stamp.proto == StampProtoTypeDoH {
		return stamp.dohString()
	}
	dlog.Fatal("Unsupported protocol")
	return ""
}

func (stamp *ServerStamp) dnsCryptString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeDNSCrypt)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.props))

	serverAddrStr := stamp.serverAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(DefaultPort)) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(DefaultPort))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	bin = append(bin, uint8(len(stamp.serverPk)))
	bin = append(bin, stamp.serverPk...)

	bin = append(bin, uint8(len(stamp.providerName)))
	bin = append(bin, []uint8(stamp.providerName)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "sdns://" + str
}

func (stamp *ServerStamp) dohString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeDoH)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.props))

	serverAddrStr := stamp.serverAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(DefaultPort)) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(DefaultPort))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	last := len(stamp.hashes) - 1
	for i, hash := range stamp.hashes {
		vlen := len(hash)
		if i < last {
			vlen |= 0x80
		}
		bin = append(bin, uint8(vlen))
		bin = append(bin, hash...)
	}

	bin = append(bin, uint8(len(stamp.providerName)))
	bin = append(bin, []uint8(stamp.providerName)...)

	bin = append(bin, uint8(len(stamp.path)))
	bin = append(bin, []uint8(stamp.path)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "sdns://" + str
}

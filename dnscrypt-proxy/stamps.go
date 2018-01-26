package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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

type ServerStamp struct {
	serverAddrStr string
	serverPk      []uint8
	hash          []uint8
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
	if bin[0] != uint8(StampProtoTypeDNSCrypt) {
		return newDNSCryptServerStamp(bin)
	}
	return ServerStamp{}, errors.New("Unsupported stamp version or protocol")
}

// id(u8)=0x02 props addrLen(1) serverAddr pkStrlen(1) pkStr providerNameLen(1) providerName

func newDNSCryptServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{}
	if len(bin) < 24 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	len := int(bin[pos])
	if len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.serverAddrStr = string(bin[pos : pos+len])
	pos += len

	len = int(bin[pos])
	if len >= binLen-pos {
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
	stamp := ServerStamp{}

	stamp.props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	len := int(bin[pos])
	if len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.serverAddrStr = string(bin[pos : pos+len])
	pos += len

	len = int(bin[pos])
	if len >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.hash = bin[pos : pos+len]
	pos += len

	len = int(bin[pos])
	if len >= binLen-pos {
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

	bin = append(bin, uint8(len(stamp.serverAddrStr)))
	bin = append(bin, []uint8(stamp.serverAddrStr)...)

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

	bin = append(bin, uint8(len(stamp.serverAddrStr)))
	bin = append(bin, []uint8(stamp.serverAddrStr)...)

	bin = append(bin, uint8(len(stamp.hash)))
	bin = append(bin, []uint8(stamp.hash)...)

	bin = append(bin, uint8(len(stamp.providerName)))
	bin = append(bin, []uint8(stamp.providerName)...)

	bin = append(bin, uint8(len(stamp.path)))
	bin = append(bin, []uint8(stamp.path)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "sdns://" + str
}

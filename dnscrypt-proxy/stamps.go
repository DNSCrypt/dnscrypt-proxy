package main

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

type ServerStamp struct {
	serverAddrStr string
	serverPkStr   string
	providerName  string
	props         ServerInformalProperties
}

func NewServerStampFromLegacy(serverAddrStr string, serverPkStr string, providerName string, props ServerInformalProperties) (ServerStamp, error) {
	if net.ParseIP(serverAddrStr) != nil {
		serverAddrStr = fmt.Sprintf("%s:%d", serverAddrStr, DefaultPort)
	}
	return ServerStamp{
		serverAddrStr: serverAddrStr,
		serverPkStr:   serverPkStr,
		providerName:  providerName,
		props:         props,
	}, nil
}

// id(u8) props addrLen(1) serverAddr pkStrlen(1) pkStr providerNameLen(1) providerName

func NewServerStampFromString(stampStr string) (ServerStamp, error) {
	stamp := ServerStamp{}
	if !strings.HasPrefix(stampStr, "sdns://") && !strings.HasPrefix(stampStr, "dnsc://") {
		return stamp, errors.New("Stamps are expected to start with sdns://")
	}
	bin, err := base64.RawURLEncoding.DecodeString(stampStr[7:])
	if err != nil {
		return stamp, err
	}
	if len(bin) < 24 {
		return stamp, errors.New("Stamp is too short")
	}
	if bin[0] != 0x01 {
		return stamp, errors.New("Unsupported stamp version")
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
	stamp.serverPkStr = string(bin[pos : pos+len])
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

func (stamp *ServerStamp) String() string {
	bin := make([]uint8, 9)
	bin[0] = 0x01
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.props))

	bin = append(bin, uint8(len(stamp.serverAddrStr)))
	bin = append(bin, []uint8(stamp.serverAddrStr)...)

	bin = append(bin, uint8(len(stamp.serverPkStr)))
	bin = append(bin, []uint8(stamp.serverPkStr)...)

	bin = append(bin, uint8(len(stamp.providerName)))
	bin = append(bin, []uint8(stamp.providerName)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return "dnsc://" + str
}

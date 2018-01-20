package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
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

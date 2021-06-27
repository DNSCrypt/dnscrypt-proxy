package main

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/jedisct1/dlog"
	hpkecompact "github.com/jedisct1/go-hpke-compact"
)

const (
	odohVersion     = uint16(0x0001)
	odohTestVersion = uint16(0xff06)
	maxODoHConfigs  = 10
)

type ODoHTargetConfig struct {
	suite     *hpkecompact.Suite
	keyID     []byte
	publicKey []byte
}

func encodeLengthValue(b []byte) []byte {
	lengthBuffer := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(b)))
	return append(lengthBuffer, b...)
}

func parseODoHTargetConfig(config []byte) (ODoHTargetConfig, error) {
	if len(config) < 8 {
		return ODoHTargetConfig{}, fmt.Errorf("Malformed config")
	}
	kemID := binary.BigEndian.Uint16(config[0:2])
	kdfID := binary.BigEndian.Uint16(config[2:4])
	aeadID := binary.BigEndian.Uint16(config[4:6])
	publicKeyLength := binary.BigEndian.Uint16(config[6:8])
	publicKey := config[8:]
	if len(publicKey) != int(publicKeyLength) {
		return ODoHTargetConfig{}, fmt.Errorf("Malformed config")
	}

	suite, err := hpkecompact.NewSuite(hpkecompact.KemID(kemID), hpkecompact.KdfID(kdfID), hpkecompact.AeadID(aeadID))
	if err != nil {
		return ODoHTargetConfig{}, err
	}

	_, _, err = suite.NewClientContext(publicKey, []byte("odoh query"), nil)
	if err != nil {
		return ODoHTargetConfig{}, err
	}

	keyID, err := suite.Expand(suite.Extract(config, nil), []byte("odoh key id"), uint16(suite.Hash().Size()))
	if err != nil {
		return ODoHTargetConfig{}, err
	}

	return ODoHTargetConfig{
		suite:     suite,
		publicKey: publicKey,
		keyID:     encodeLengthValue(keyID),
	}, nil
}

func parseODoHTargetConfigs(configs []byte) ([]ODoHTargetConfig, error) {
	if len(configs) <= 2 {
		return nil, fmt.Errorf("Server didn't return any ODoH configurations")
	}
	length := binary.BigEndian.Uint16(configs)
	if len(configs) != int(length)+2 {
		return nil, fmt.Errorf("Malformed configs")
	}

	targets := make([]ODoHTargetConfig, 0)
	offset := 2
	for {
		if offset+4 > len(configs) || len(targets) >= maxODoHConfigs {
			break
		}
		configVersion := binary.BigEndian.Uint16(configs[offset : offset+2])
		configLength := binary.BigEndian.Uint16(configs[offset+2 : offset+4])
		if configVersion == odohVersion || configVersion == odohTestVersion {
			if configVersion != odohVersion {
				dlog.Debugf("Server still uses the legacy 0x%x ODoH version", configVersion)
			}
			target, err := parseODoHTargetConfig(configs[offset+4 : offset+4+int(configLength)])
			if err == nil {
				targets = append(targets, target)
			}
		}
		offset = offset + int(configLength) + 4
	}
	return targets, nil
}

type ODoHQuery struct {
	suite         *hpkecompact.Suite
	ctx           hpkecompact.ClientContext
	odohPlaintext []byte
	odohMessage   []byte
}

func (t ODoHTargetConfig) encryptQuery(query []byte) (ODoHQuery, error) {
	clientCtx, encryptedSharedSecret, err := t.suite.NewClientContext(t.publicKey, []byte("odoh query"), nil)
	if err != nil {
		return ODoHQuery{}, err
	}

	odohPlaintext := make([]byte, 4+len(query))
	binary.BigEndian.PutUint16(odohPlaintext[0:2], uint16(len(query)))
	copy(odohPlaintext[2:], query)

	aad := append([]byte{0x01}, t.keyID...)
	ciphertext, err := clientCtx.EncryptToServer(odohPlaintext, aad)
	if err != nil {
		return ODoHQuery{}, err
	}

	encryptedMessage := encodeLengthValue(append(encryptedSharedSecret, ciphertext...))
	odohMessage := append(append([]byte{0x01}, t.keyID...), encryptedMessage...)

	return ODoHQuery{
		suite:         t.suite,
		odohPlaintext: odohPlaintext,
		odohMessage:   odohMessage,
		ctx:           clientCtx,
	}, nil
}

func (q ODoHQuery) decryptResponse(response []byte) ([]byte, error) {
	if len(response) < 3 {
		return nil, fmt.Errorf("Malformed response")
	}

	messageType := response[0]
	if messageType != uint8(0x02) {
		return nil, fmt.Errorf("Malformed response")
	}

	responseNonceLength := binary.BigEndian.Uint16(response[1:3])
	if len(response) < 5+int(responseNonceLength) {
		return nil, fmt.Errorf("Malformed response")
	}

	responseNonceEnc := response[1 : 3+responseNonceLength]

	secret, err := q.ctx.Export([]byte("odoh response"), q.suite.KeyBytes)
	if err != nil {
		return nil, err
	}

	salt := append(q.odohPlaintext, responseNonceEnc...)
	prk := q.suite.Extract(secret, salt)
	key, err := q.suite.Expand(prk, []byte("odoh key"), q.suite.KeyBytes)
	if err != nil {
		return nil, err
	}
	nonce, err := q.suite.Expand(prk, []byte("odoh nonce"), q.suite.NonceBytes)
	if err != nil {
		return nil, err
	}

	cipher, err := q.suite.NewRawCipher(key)
	if err != nil {
		return nil, err
	}

	ctLength := binary.BigEndian.Uint16(response[3+int(responseNonceLength) : 5+int(responseNonceLength)])
	if int(ctLength) != len(response[5+int(responseNonceLength):]) {
		return nil, fmt.Errorf("Malformed response")
	}

	ct := response[5+int(responseNonceLength):]
	aad := response[0 : 3+int(responseNonceLength)]

	responsePlaintext, err := cipher.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, err
	}

	responseLength := binary.BigEndian.Uint16(responsePlaintext[0:2])
	valid := 1
	for i := 4 + int(responseLength); i < len(responsePlaintext); i++ {
		valid = valid & subtle.ConstantTimeByteEq(response[i], 0x00)
	}
	if valid != 1 {
		return nil, fmt.Errorf("Malformed response")
	}

	return responsePlaintext[2 : 2+int(responseLength)], nil
}

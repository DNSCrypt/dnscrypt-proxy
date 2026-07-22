package main

import (
	"bytes"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/jedisct1/dlog"
	"github.com/jedisct1/xsecretbox"
	"golang.org/x/crypto/hkdf"
)

const (
	PQXWingPublicKeySize  = 1216
	PQXWingCiphertextSize = 1120
	PQClientMagicLen      = 8
	PQProfileExtSize      = 12
	PQControlVersion      = 0x01
	PQExtVersion          = 0x01
	PQKdfID               = 0x01
	PQAeadID              = 0x01
	PQResumedPaddingFloor = 256
)

var (
	PQESVersion    = [2]byte{0x00, 0x03}
	PQResumeMagic  = [8]byte{'P', 'Q', 'R', 'e', 's', 'u', 'm', 'e'}
	PQControlMagic = [4]byte{'P', 'Q', 'D', 'R'}
)

// pqProfileExtension is the signed <extensions> field of a PQ certificate.
func pqProfileExtension() []byte {
	ext := make([]byte, PQProfileExtSize)
	copy(ext[0:3], "PQD")
	ext[3] = PQExtVersion
	ext[4] = PQESVersion[0]
	ext[5] = PQESVersion[1]
	ext[6] = PQKdfID
	ext[7] = PQAeadID
	binary.BigEndian.PutUint16(ext[8:10], PQXWingPublicKeySize)
	binary.BigEndian.PutUint16(ext[10:12], PQXWingCiphertextSize)
	return ext
}

func hkdfSha256(salt, ikm, info []byte, outLen int) []byte {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, outLen)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

// pqCertContext builds the HKDF info that binds the shared key to the exact
// signed certificate. binCert is the full 1320-byte PQ certificate.
func pqCertContext(binCert []byte) []byte {
	ctx := make([]byte, 0, 14+2+2+PQXWingPublicKeySize+8+4+4+4+PQProfileExtSize)
	ctx = append(ctx, "DNSCrypt-PQ-v1"...)
	ctx = append(ctx, binCert[4:6]...)       // es-version
	ctx = append(ctx, binCert[6:8]...)       // protocol-minor-version
	ctx = append(ctx, binCert[72:1288]...)   // resolver-pk
	ctx = append(ctx, binCert[1288:1296]...) // client-magic
	ctx = append(ctx, binCert[1296:1300]...) // serial
	ctx = append(ctx, binCert[1300:1304]...) // ts-start
	ctx = append(ctx, binCert[1304:1308]...) // ts-end
	ctx = append(ctx, binCert[1308:1320]...) // extensions
	return ctx
}

// pqDeriveSharedKey derives <shared-key> for a query that carries a ciphertext.
func pqDeriveSharedKey(kemSS []byte, clientMagic [8]byte, certContext, ct []byte) [32]byte {
	salt := make([]byte, 0, 10)
	salt = append(salt, PQESVersion[0], PQESVersion[1])
	salt = append(salt, clientMagic[:]...)
	info := make([]byte, 0, len(certContext)+len(ct))
	info = append(info, certContext...)
	info = append(info, ct...)
	var key [32]byte
	copy(key[:], hkdfSha256(salt, kemSS, info, 32))
	return key
}

// pqResumeSecret derives the resumption secret from the shared key of a query
// that carried a ciphertext.
func pqResumeSecret(sharedKey [32]byte, clientMagic [8]byte, clientNonce []byte) [32]byte {
	salt := make([]byte, 0, 8+len(clientNonce))
	salt = append(salt, clientMagic[:]...)
	salt = append(salt, clientNonce...)
	var out [32]byte
	copy(out[:], hkdfSha256(salt, sharedKey[:], []byte("DNSCrypt-PQ-resume-secret-v1"), 32))
	return out
}

// pqResumedSharedKey derives the per-query key for a resumed query.
func pqResumedSharedKey(resumeSecret [32]byte, clientMagic [8]byte, clientNonce, ticket []byte) [32]byte {
	salt := make([]byte, 0, 8+len(clientNonce))
	salt = append(salt, clientMagic[:]...)
	salt = append(salt, clientNonce...)
	th := sha256.Sum256(ticket)
	info := make([]byte, 0, 27+32)
	info = append(info, "DNSCrypt-PQ-resumed-query-v1"...)
	info = append(info, th[:]...)
	var key [32]byte
	copy(key[:], hkdfSha256(salt, resumeSecret[:], info, 32))
	return key
}

// pqPad applies ISO/IEC 7816-4 padding to the next multiple of 64, with a
// minimum floor (itself a multiple of 64).
func pqPad(packet []byte, floor int) []byte {
	target := (len(packet) + 1 + 63) &^ 63
	if target < floor {
		target = floor
	}
	padded := make([]byte, target)
	copy(padded, packet)
	padded[len(packet)] = 0x80
	return padded
}

// pqEncapsulate runs an X-Wing encapsulation against the resolver public key.
func pqEncapsulate(pk []byte) (kemSS, ct []byte, err error) {
	return xwing.Encapsulate(pk, nil)
}

// pqSessionState holds a server's reusable PQ key material.
type pqSessionState struct {
	mu           sync.Mutex
	ticket       []byte
	resumeSecret [32]byte
	expiry       time.Time
	epoch        uint64
	encap        []byte
	encapKey     [32]byte
	encapEpoch   uint64
}

func newPqSessionState(c CryptoConstruction) *pqSessionState {
	if c != XWingPQ {
		return nil
	}
	return &pqSessionState{}
}

func (s *pqSessionState) store(ticket []byte, resumeSecret [32]byte, expiry time.Time, epoch uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ticket = append([]byte(nil), ticket...)
	s.resumeSecret = resumeSecret
	s.expiry = expiry
	s.epoch = epoch
}

func (s *pqSessionState) get(currentEpoch uint64) (ticket []byte, resumeSecret [32]byte, ok bool) {
	if s == nil {
		return nil, [32]byte{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ticket == nil || !time.Now().Before(s.expiry) {
		return nil, [32]byte{}, false
	}
	if s.epoch != currentEpoch {
		s.ticket = nil
		s.resumeSecret = [32]byte{}
		s.expiry = time.Time{}
		return nil, [32]byte{}, false
	}
	return append([]byte(nil), s.ticket...), s.resumeSecret, true
}

func (s *pqSessionState) getCachedEncapsulation(currentEpoch uint64) (ct []byte, key [32]byte, ok bool) {
	if s == nil {
		return nil, [32]byte{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.encap == nil {
		return nil, [32]byte{}, false
	}
	if s.encapEpoch != currentEpoch {
		s.encap = nil
		s.encapKey = [32]byte{}
		return nil, [32]byte{}, false
	}
	return append([]byte(nil), s.encap...), s.encapKey, true
}

func (s *pqSessionState) storeEncapsulation(ct []byte, key [32]byte, epoch uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encap = append([]byte(nil), ct...)
	s.encapKey = key
	s.encapEpoch = epoch
}

// pqResumedOverhead is the wire size of a resumed query around its encrypted
// padded payload.
func pqResumedOverhead(ticketLen int) int {
	return len(PQResumeMagic) + 2 + ticketLen + HalfNonceSize + TagSize
}

// pqUDPPacketLimit is the largest UDP datagram worth sending to this server,
// honoring the same fragmentation workaround as the classic path.
func pqUDPPacketLimit(serverInfo *ServerInfo) int {
	if serverInfo.knownBugs.fragmentsBlocked {
		return MaxDNSUDPSafePacketSize
	}
	return MaxDNSUDPPacketSize
}

// pqResumedPaddingFloor returns the padding floor for a resumed query. Over
// UDP, the encrypted response can never be larger than the query, so the
// query is grown to the regular UDP question size target, leaving the
// resolver the same response budget as a classic query.
func (proxy *Proxy) pqResumedPaddingFloor(serverInfo *ServerInfo, ticketLen int, proto string) int {
	if proto != "udp" {
		return PQResumedPaddingFloor
	}
	overhead := pqResumedOverhead(ticketLen)
	want := proxy.questionSizeEstimator.MinQuestionSize() - overhead
	return Max(PQResumedPaddingFloor, Min((want+63)&^63, (pqUDPPacketLimit(serverInfo)-overhead)&^63))
}

// encryptPQ builds a PQ query: a resumed query when a valid ticket is held,
// otherwise a query that carries an X-Wing ciphertext, reusing the cached
// encapsulation when one is available for the current network epoch.
func (proxy *Proxy) encryptPQ(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, queryEpoch uint64, err error) {
	queryEpoch = proxy.networkEpoch()
	nonce := make([]byte, NonceSize)
	clientNonce = make([]byte, HalfNonceSize)
	if _, err = crypto_rand.Read(clientNonce); err != nil {
		return nil, nil, nil, queryEpoch, err
	}
	copy(nonce, clientNonce)

	if ticket, resumeSecret, ok := serverInfo.pqSession.get(queryEpoch); ok {
		key := pqResumedSharedKey(resumeSecret, serverInfo.MagicQuery, clientNonce, ticket)
		padded := pqPad(packet, proxy.pqResumedPaddingFloor(serverInfo, len(ticket), proto))
		ct := xsecretbox.Seal(nil, nonce, padded, key[:])
		out := make([]byte, 0, len(PQResumeMagic)+2+len(ticket)+HalfNonceSize+len(ct))
		out = append(out, PQResumeMagic[:]...)
		var tl [2]byte
		binary.BigEndian.PutUint16(tl[:], uint16(len(ticket)))
		out = append(out, tl[:]...)
		out = append(out, ticket...)
		out = append(out, clientNonce...)
		out = append(out, ct...)
		return &key, out, clientNonce, queryEpoch, nil
	}

	ctKem, key, ok := serverInfo.pqSession.getCachedEncapsulation(queryEpoch)
	if !ok {
		var kemSS []byte
		if kemSS, ctKem, err = pqEncapsulate(serverInfo.PqPublicKey); err != nil {
			return nil, nil, nil, queryEpoch, err
		}
		key = pqDeriveSharedKey(kemSS, serverInfo.MagicQuery, serverInfo.PqCertContext, ctKem)
		serverInfo.pqSession.storeEncapsulation(ctKem, key, queryEpoch)
	}
	padded := pqPad(packet, 64)
	ct := xsecretbox.Seal(nil, nonce, padded, key[:])
	out := make([]byte, 0, PQClientMagicLen+len(ctKem)+HalfNonceSize+len(ct))
	out = append(out, serverInfo.MagicQuery[:]...)
	out = append(out, ctKem...)
	out = append(out, clientNonce...)
	out = append(out, ct...)
	return &key, out, clientNonce, queryEpoch, nil
}

// pqStripControl removes the PQ response control block (storing any ticket it
// carries) and returns the padded DNS response body.
func (proxy *Proxy) pqStripControl(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	clientNonce, plaintext []byte,
	queryEpoch uint64,
) ([]byte, error) {
	if len(plaintext) < 2 {
		return nil, errors.New("PQ response too short")
	}
	controlLen := int(binary.BigEndian.Uint16(plaintext[0:2]))
	if 2+controlLen > len(plaintext) {
		return nil, errors.New("PQ control block overflows response")
	}
	control := plaintext[2 : 2+controlLen]
	body := plaintext[2+controlLen:]
	if controlLen > 0 {
		proxy.pqProcessControl(serverInfo, sharedKey, clientNonce, control, queryEpoch)
	}
	return body, nil
}

func (proxy *Proxy) pqProcessControl(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	clientNonce, control []byte,
	queryEpoch uint64,
) {
	if len(control) < 11 {
		return
	}
	if !bytes.Equal(control[0:4], PQControlMagic[:]) || control[4] != PQControlVersion {
		return
	}
	lifetime := binary.BigEndian.Uint32(control[5:9])
	ticketLen := int(binary.BigEndian.Uint16(control[9:11]))
	if 11+ticketLen > len(control) {
		return
	}
	ticket := control[11 : 11+ticketLen]
	if pqResumedOverhead(len(ticket))+PQResumedPaddingFloor > MaxDNSUDPPacketSize {
		dlog.Debugf("[%v] discarded an oversized PQ resumption ticket (%d bytes)", serverInfo.Name, len(ticket))
		return
	}
	if queryEpoch != proxy.networkEpoch() {
		dlog.Debugf("[%v] discarded a PQ resumption ticket after a network change", serverInfo.Name)
		return
	}
	resumeSecret := pqResumeSecret(*sharedKey, serverInfo.MagicQuery, clientNonce)
	expiry := time.Now().Add(time.Duration(lifetime) * time.Second)
	serverInfo.pqSession.store(ticket, resumeSecret, expiry, queryEpoch)
	dlog.Debugf("[%v] stored a PQ resumption ticket (lifetime %ds)", serverInfo.Name, lifetime)
}

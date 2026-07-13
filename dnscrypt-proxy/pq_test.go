package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/jedisct1/xsecretbox"
)

func iotaBytes(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestPQAppendix3Vectors checks the client's PQ crypto against the pinned
// values of Appendix 3 of the draft, the same anchor the server validates.
func TestPQAppendix3Vectors(t *testing.T) {
	clientMagic := [8]byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18}
	dnsQuery := mustHex("12340100000100000000000003777777076578616d706c6503636f6d0000010001")

	// X-Wing keygen + deterministic encapsulation.
	rseed := iotaBytes(32, 0x20)
	peseed := iotaBytes(64, 0x40)
	_, pk := xwing.DeriveKeyPair(rseed)
	pkb, _ := pk.MarshalBinary()
	if got := hex.EncodeToString(hashSum(pkb)); got != "a1f324bc0701f1234fbba7b11901023b3644f3bb8c6eb4ee4368d7e859eb6228" {
		t.Fatalf("resolver-pk mismatch: %s", got)
	}
	kemSS, ct, err := xwing.Encapsulate(pkb, peseed)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(kemSS); got != "8dac8602d4ce5e27e81335b54b25fdcaea86e56613214ee0522db4a5e0a38d50" {
		t.Fatalf("kem-ss mismatch: %s", got)
	}

	// Build the certificate bytes the cert-context is derived from.
	binCert := make([]byte, 1320)
	copy(binCert[0:4], []byte{0x44, 0x4e, 0x53, 0x43})
	binCert[4], binCert[5] = 0x00, 0x03
	copy(binCert[72:1288], pkb)
	copy(binCert[1288:1296], clientMagic[:])
	copy(binCert[1296:1300], []byte{0x00, 0x00, 0x00, 0x01})
	copy(binCert[1300:1304], []byte{0x68, 0x00, 0x00, 0x00})
	copy(binCert[1304:1308], []byte{0x68, 0x01, 0x51, 0x80})
	copy(binCert[1308:1320], pqProfileExtension())

	certCtx := pqCertContext(binCert)
	sharedKey := pqDeriveSharedKey(kemSS, clientMagic, certCtx, ct)
	if got := hex.EncodeToString(sharedKey[:]); got != "e6d4ab9cffc9b49e2a64d80d7eb2dde280f806b89e834d596ad385b1dd75e9ef" {
		t.Fatalf("shared-key mismatch: %s", got)
	}

	// Full query: encrypted-query and the wire packet.
	qNonce := iotaBytes(12, 0xb0)
	qNonce24 := append(append([]byte{}, qNonce...), make([]byte, 12)...)
	padded := pqPad(dnsQuery, 64)
	if len(padded) != 64 {
		t.Fatalf("padded query length: %d", len(padded))
	}
	encQuery := xsecretbox.Seal(nil, qNonce24, padded, sharedKey[:])
	if got := hex.EncodeToString(encQuery); got != "c41764468cb42d3a837c51234c08be714af49e1a6830ea6da28178e9e280d76bac1b87fd7f56515f2b2cc3d4715aaa42907c282db1edff0bc3b92cd535a710e264859a5bdaf67c17ffa6e1c6f6e02a50" {
		t.Fatalf("encrypted-query mismatch: %s", got)
	}
	fullQuery := append([]byte{}, clientMagic[:]...)
	fullQuery = append(fullQuery, ct...)
	fullQuery = append(fullQuery, qNonce...)
	fullQuery = append(fullQuery, encQuery...)
	if len(fullQuery) != 1220 {
		t.Fatalf("full query length: %d", len(fullQuery))
	}
	if got := hex.EncodeToString(hashSum(fullQuery)); got != "65c3421776283f503779916e7b5c32d0d41c885508ad892b349688db6c901233" {
		t.Fatalf("full query wire mismatch: %s", got)
	}

	// Resumption secret derivation matches the server's.
	rs := pqResumeSecret(sharedKey, clientMagic, qNonce)
	if got := hex.EncodeToString(rs[:]); got != "df158804e3f8ddf383ff7c9d3128491b29437a894936ec72c68aed8a9553272b" {
		t.Fatalf("resume-secret mismatch: %s", got)
	}

	// Resumed query against the pinned ticket.
	ticket := mustHex("00000001d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e1d90c86474574e0e51e82d8a29938896b0999e827138f8f452f21e044d9809f65a013cfad8981be94c1354178b3e03dd518c28bcbaab962aa45246e446de7763288aa4a01e207725a0ae7bc95452fef3743f6083deb10cd23e2881e8d9307fc2f43bce1a97e")
	rqNonce := iotaBytes(12, 0xf0)
	resumedKey := pqResumedSharedKey(rs, clientMagic, rqNonce, ticket)
	if got := hex.EncodeToString(resumedKey[:]); got != "e61f03acb2ee2ef01b952a0c312c60653267d47a2766fcfd804747fdf2fe789f" {
		t.Fatalf("resumed shared-key mismatch: %s", got)
	}
	rqNonce24 := append(append([]byte{}, rqNonce...), make([]byte, 12)...)
	rpadded := pqPad(dnsQuery, 256)
	rencQuery := xsecretbox.Seal(nil, rqNonce24, rpadded, resumedKey[:])
	resumeQuery := append([]byte{}, PQResumeMagic[:]...)
	resumeQuery = append(resumeQuery, 0x00, 0x82)
	resumeQuery = append(resumeQuery, ticket...)
	resumeQuery = append(resumeQuery, rqNonce...)
	resumeQuery = append(resumeQuery, rencQuery...)
	if len(resumeQuery) != 424 {
		t.Fatalf("resume query length: %d", len(resumeQuery))
	}
	if got := hex.EncodeToString(hashSum(resumeQuery)); got != "34be2e331b4d7c7e808e968c5efc9f25675a9de9064cb33f7c66950e0e4e6db7" {
		t.Fatalf("resume query wire mismatch: %s", got)
	}
}

func TestPQSessionResumptionEpoch(t *testing.T) {
	state := newPqSessionState(XWingPQ)
	ticket := []byte("ticket")
	var resumeSecret [32]byte
	resumeSecret[0] = 42

	state.store(ticket, resumeSecret, time.Now().Add(time.Minute), 7)
	gotTicket, gotSecret, ok := state.get(7)
	if !ok {
		t.Fatal("expected ticket for matching epoch")
	}
	if string(gotTicket) != string(ticket) || gotSecret != resumeSecret {
		t.Fatal("unexpected ticket or resume secret")
	}

	gotTicket[0] = 'T'
	gotTicket, _, ok = state.get(8)
	if ok || gotTicket != nil {
		t.Fatal("expected epoch mismatch to reject ticket")
	}
	if state.ticket != nil || state.resumeSecret != [32]byte{} || !state.expiry.IsZero() {
		t.Fatal("expected epoch mismatch to clear stored ticket material")
	}
}

// TestEncryptPQReusesEncapsulation checks that post-quantum queries reuse a
// single X-Wing key exchange instead of running a fresh one every time, and
// that a network change forces a new one.
func TestEncryptPQReusesEncapsulation(t *testing.T) {
	monitor := newNetworkMonitor()
	monitor.epochValue.Store(1)
	proxy := &Proxy{netMonitor: monitor}

	_, pk := xwing.DeriveKeyPair(iotaBytes(32, 0x20))
	pkb, _ := pk.MarshalBinary()
	serverInfo := &ServerInfo{
		Name:               "test",
		CryptoConstruction: XWingPQ,
		PqPublicKey:        pkb,
		PqCertContext:      iotaBytes(48, 0x01),
		MagicQuery:         [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		pqSession:          newPqSessionState(XWingPQ),
	}
	query := mustHex("12340100000100000000000003777777076578616d706c6503636f6d0000010001")

	ctOf := func(out []byte) []byte {
		return out[PQClientMagicLen : PQClientMagicLen+PQXWingCiphertextSize]
	}

	key1, out1, _, _, err := proxy.encryptPQ(serverInfo, query, "udp")
	if err != nil {
		t.Fatal(err)
	}
	key2, out2, _, _, err := proxy.encryptPQ(serverInfo, query, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctOf(out1), ctOf(out2)) {
		t.Fatal("expected the X-Wing ciphertext to be reused across queries")
	}
	if *key1 != *key2 {
		t.Fatal("expected the shared key to be reused across queries")
	}

	monitor.epochValue.Store(2)
	_, out3, _, _, err := proxy.encryptPQ(serverInfo, query, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ctOf(out1), ctOf(out3)) {
		t.Fatal("expected a new key exchange after a network change")
	}
}

func TestPQProcessControlDiscardsTicketAfterNetworkChange(t *testing.T) {
	monitor := newNetworkMonitor()
	monitor.epochValue.Store(2)
	proxy := &Proxy{netMonitor: monitor}
	serverInfo := &ServerInfo{
		Name:      "test",
		pqSession: newPqSessionState(XWingPQ),
	}
	sharedKey := &[32]byte{1, 2, 3}
	clientNonce := []byte("abcdefghijkl")
	control := buildTestPQControl([]byte("ticket"), 60)

	proxy.pqProcessControl(serverInfo, sharedKey, clientNonce, control, 1)
	if _, _, ok := serverInfo.pqSession.get(2); ok {
		t.Fatal("expected ticket from old epoch to be discarded")
	}

	proxy.pqProcessControl(serverInfo, sharedKey, clientNonce, control, 2)
	if ticket, _, ok := serverInfo.pqSession.get(2); !ok || string(ticket) != "ticket" {
		t.Fatal("expected ticket to be stored when query epoch still matches")
	}
}

func buildTestPQControl(ticket []byte, lifetime uint32) []byte {
	control := append([]byte{}, PQControlMagic[:]...)
	control = append(control, PQControlVersion)
	var lifetimeBytes [4]byte
	binary.BigEndian.PutUint32(lifetimeBytes[:], lifetime)
	control = append(control, lifetimeBytes[:]...)
	var ticketLen [2]byte
	binary.BigEndian.PutUint16(ticketLen[:], uint16(len(ticket)))
	control = append(control, ticketLen[:]...)
	control = append(control, ticket...)
	return control
}

func hashSum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

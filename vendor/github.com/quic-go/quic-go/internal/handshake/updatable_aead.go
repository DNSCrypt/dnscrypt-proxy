package handshake

import (
	"crypto"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// defaultKeyUpdateInterval is the maximum number of packets we send or receive before initiating a key update.
const defaultKeyUpdateInterval = 100 * 1000

var keyUpdateInterval atomic.Uint64

func init() {
	keyUpdateInterval.Store(defaultKeyUpdateInterval)
}

func SetKeyUpdateInterval(v uint64) (reset func()) {
	old := keyUpdateInterval.Swap(v)
	return func() { keyUpdateInterval.Store(old) }
}

// FirstKeyUpdateInterval is the maximum number of packets we send or receive before initiating the first key update.
// It's a package-level variable to allow modifying it for testing purposes.
var FirstKeyUpdateInterval uint64 = 100

type updatableAEAD struct {
	suite cipherSuite

	keyPhase           protocol.KeyPhase
	largestAcked       protocol.PacketNumber
	firstPacketNumber  protocol.PacketNumber
	handshakeConfirmed bool

	invalidPacketCount uint64

	// Time when the keys should be dropped. Keys are dropped on the next call to Open().
	prevRcvAEADExpiry monotime.Time
	prevRcvAEAD       cipher.AEAD

	lowestRcvdWithCurrentKey protocol.PacketNumber
	firstSentWithCurrentKey  protocol.PacketNumber
	numRcvdWithCurrentKey    uint64
	numSentWithCurrentKey    uint64
	rcvAEAD                  cipher.AEAD
	sendAEAD                 cipher.AEAD
	// caches cipher.AEAD.Overhead(). This speeds up calls to Overhead().
	aeadOverhead int

	nextRcvAEAD           cipher.AEAD
	nextSendAEAD          cipher.AEAD
	nextRcvTrafficSecret  []byte
	nextSendTrafficSecret []byte

	headerDecrypter headerProtector
	headerEncrypter headerProtector

	rttStats *utils.RTTStats

	qlogger qlogwriter.Recorder
	logger  utils.Logger
	version protocol.Version

	nonceBuf [8]byte
}

var (
	_ ShortHeaderOpener = &updatableAEAD{}
	_ ShortHeaderSealer = &updatableAEAD{}
)

func newUpdatableAEAD(rttStats *utils.RTTStats, qlogger qlogwriter.Recorder, logger utils.Logger, version protocol.Version) *updatableAEAD {
	return &updatableAEAD{
		firstPacketNumber:        protocol.InvalidPacketNumber,
		largestAcked:             protocol.InvalidPacketNumber,
		lowestRcvdWithCurrentKey: protocol.InvalidPacketNumber,
		firstSentWithCurrentKey:  protocol.InvalidPacketNumber,
		rttStats:                 rttStats,
		qlogger:                  qlogger,
		logger:                   logger,
		version:                  version,
	}
}

func (a *updatableAEAD) rollKeys() {
	if a.prevRcvAEAD != nil {
		a.logger.Debugf("Dropping key phase %d ahead of scheduled time. Drop time was: %s", a.keyPhase-1, a.prevRcvAEADExpiry)
		if a.qlogger != nil {
			a.qlogger.RecordEvent(qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: a.keyPhase - 1,
			})
			a.qlogger.RecordEvent(qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: a.keyPhase - 1,
			})
		}
		a.prevRcvAEADExpiry = 0
	}

	a.keyPhase++
	a.lowestRcvdWithCurrentKey = protocol.InvalidPacketNumber
	a.firstSentWithCurrentKey = protocol.InvalidPacketNumber
	a.numRcvdWithCurrentKey = 0
	a.numSentWithCurrentKey = 0
	a.prevRcvAEAD = a.rcvAEAD
	a.rcvAEAD = a.nextRcvAEAD
	a.sendAEAD = a.nextSendAEAD

	a.nextRcvTrafficSecret = a.getNextTrafficSecret(a.suite.Hash, a.nextRcvTrafficSecret)
	a.nextSendTrafficSecret = a.getNextTrafficSecret(a.suite.Hash, a.nextSendTrafficSecret)
	a.nextRcvAEAD = createAEAD(a.suite, a.nextRcvTrafficSecret, a.version)
	a.nextSendAEAD = createAEAD(a.suite, a.nextSendTrafficSecret, a.version)
}

func (a *updatableAEAD) startKeyDropTimer(now monotime.Time) {
	d := 3 * a.rttStats.PTO(true)
	a.logger.Debugf("Starting key drop timer to drop key phase %d (in %s)", a.keyPhase-1, d)
	a.prevRcvAEADExpiry = now.Add(d)
}

func (a *updatableAEAD) getNextTrafficSecret(hash crypto.Hash, ts []byte) []byte {
	label := "quic ku"
	if a.version == protocol.Version2 {
		label = "quicv2 ku"
	}
	return hkdfExpandLabel(hash, ts, []byte{}, label, hash.Size())
}

// SetReadKey sets the read key.
// For the client, this function is called before SetWriteKey.
// For the server, this function is called after SetWriteKey.
func (a *updatableAEAD) SetReadKey(suite cipherSuite, trafficSecret []byte) {
	a.rcvAEAD = createAEAD(suite, trafficSecret, a.version)
	a.headerDecrypter = newHeaderProtector(suite, trafficSecret, false, a.version)
	if a.suite.ID == 0 { // suite is not set yet
		a.setAEADParameters(a.rcvAEAD, suite)
	}

	a.nextRcvTrafficSecret = a.getNextTrafficSecret(suite.Hash, trafficSecret)
	a.nextRcvAEAD = createAEAD(suite, a.nextRcvTrafficSecret, a.version)
}

// SetWriteKey sets the write key.
// For the client, this function is called after SetReadKey.
// For the server, this function is called before SetReadKey.
func (a *updatableAEAD) SetWriteKey(suite cipherSuite, trafficSecret []byte) {
	a.sendAEAD = createAEAD(suite, trafficSecret, a.version)
	a.headerEncrypter = newHeaderProtector(suite, trafficSecret, false, a.version)
	if a.suite.ID == 0 { // suite is not set yet
		a.setAEADParameters(a.sendAEAD, suite)
	}

	a.nextSendTrafficSecret = a.getNextTrafficSecret(suite.Hash, trafficSecret)
	a.nextSendAEAD = createAEAD(suite, a.nextSendTrafficSecret, a.version)
}

func (a *updatableAEAD) setAEADParameters(aead cipher.AEAD, suite cipherSuite) {
	if aead.NonceSize() != len(a.nonceBuf) {
		panic("unexpected nonce size")
	}
	a.aeadOverhead = aead.Overhead()
	a.suite = suite
}

func (a *updatableAEAD) Open(dst, src []byte, rcvTime monotime.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	dec, err := a.open(dst, src, rcvTime, pn, kp, ad)
	if err == ErrDecryptionFailed {
		a.invalidPacketCount++
		// RFC 9001, Section 6.6 counts failures across all keys.
		// To avoid sharing a counter with the long header openers, we subtract their limits:
		// Initial (twice, after a Retry), Handshake and 0-RTT.
		// Closing earlier than required doesn't matter in practice:
		// an attacker still needs more than 2^35 forged packets.
		if a.invalidPacketCount >= a.suite.IntegrityLimit()-4*protocol.InvalidPacketLimitLongHeader {
			return nil, &qerr.TransportError{ErrorCode: qerr.AEADLimitReached}
		}
	}
	return dec, err
}

func (a *updatableAEAD) open(dst, src []byte, rcvTime monotime.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	if a.prevRcvAEAD != nil && !a.prevRcvAEADExpiry.IsZero() && rcvTime.After(a.prevRcvAEADExpiry) {
		a.prevRcvAEAD = nil
		a.logger.Debugf("Dropping key phase %d", a.keyPhase-1)
		a.prevRcvAEADExpiry = 0
		if a.qlogger != nil {
			a.qlogger.RecordEvent(qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: a.keyPhase - 1,
			})
			a.qlogger.RecordEvent(qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: a.keyPhase - 1,
			})
		}
	}
	binary.BigEndian.PutUint64(a.nonceBuf[:], uint64(pn))
	if kp != a.keyPhase.Bit() {
		if a.keyPhase > 0 && a.lowestRcvdWithCurrentKey == protocol.InvalidPacketNumber || pn < a.lowestRcvdWithCurrentKey {
			if a.prevRcvAEAD == nil {
				return nil, ErrKeysDropped
			}
			// we updated the key, but the peer hasn't updated yet
			dec, err := a.prevRcvAEAD.Open(dst, a.nonceBuf[:], src, ad)
			if err != nil {
				err = ErrDecryptionFailed
			}
			return dec, err
		}
		// try opening the packet with the next key phase
		dec, err := a.nextRcvAEAD.Open(dst, a.nonceBuf[:], src, ad)
		if err != nil {
			return nil, ErrDecryptionFailed
		}
		// Opening succeeded. Check if the peer was allowed to update.
		if a.keyPhase > 0 && a.firstSentWithCurrentKey == protocol.InvalidPacketNumber {
			return nil, &qerr.TransportError{
				ErrorCode:    qerr.KeyUpdateError,
				ErrorMessage: "keys updated too quickly",
			}
		}
		a.rollKeys()
		a.logger.Debugf("Peer updated keys to %d", a.keyPhase)
		// The peer initiated this key update. It's safe to drop the keys for the previous generation now.
		// Start a timer to drop the previous key generation.
		a.startKeyDropTimer(rcvTime)
		if a.qlogger != nil {
			a.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger:  qlog.KeyUpdateRemote,
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: a.keyPhase,
			})
			a.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger:  qlog.KeyUpdateRemote,
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: a.keyPhase,
			})
		}
		a.lowestRcvdWithCurrentKey = pn
		return dec, err
	}
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	dec, err := a.rcvAEAD.Open(dst, a.nonceBuf[:], src, ad)
	if err != nil {
		return dec, ErrDecryptionFailed
	}
	a.numRcvdWithCurrentKey++
	if a.lowestRcvdWithCurrentKey == protocol.InvalidPacketNumber {
		// We initiated the key updated, and now we received the first packet protected with the new key phase.
		// Therefore, we are certain that the peer rolled its keys as well. Start a timer to drop the old keys.
		if a.keyPhase > 0 {
			a.logger.Debugf("Peer confirmed key update to phase %d", a.keyPhase)
			a.startKeyDropTimer(rcvTime)
		}
		a.lowestRcvdWithCurrentKey = pn
	} else {
		a.lowestRcvdWithCurrentKey = min(a.lowestRcvdWithCurrentKey, pn)
	}
	return dec, err
}

func (a *updatableAEAD) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	if a.firstSentWithCurrentKey == protocol.InvalidPacketNumber {
		a.firstSentWithCurrentKey = pn
	}
	if a.firstPacketNumber == protocol.InvalidPacketNumber {
		a.firstPacketNumber = pn
	}
	a.numSentWithCurrentKey++
	binary.BigEndian.PutUint64(a.nonceBuf[:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return a.sendAEAD.Seal(dst, a.nonceBuf[:], src, ad)
}

func (a *updatableAEAD) SetLargestAcked(pn protocol.PacketNumber) error {
	if a.firstSentWithCurrentKey != protocol.InvalidPacketNumber &&
		pn >= a.firstSentWithCurrentKey && a.numRcvdWithCurrentKey == 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.KeyUpdateError,
			ErrorMessage: fmt.Sprintf("received ACK for key phase %d, but peer didn't update keys", a.keyPhase),
		}
	}
	a.largestAcked = pn
	return nil
}

func (a *updatableAEAD) SetHandshakeConfirmed() {
	a.handshakeConfirmed = true
}

func (a *updatableAEAD) updateAllowed() bool {
	if !a.handshakeConfirmed {
		return false
	}
	// the first key update is allowed as soon as the handshake is confirmed
	return a.keyPhase == 0 ||
		// Subsequent key updates are allowed as soon as a packet sent with the current keys was acknowledged.
		// We don't wait 3 PTOs as recommended by RFC 9001, Section 6.5,
		// since that only matters at very high packet rates.
		(a.firstSentWithCurrentKey != protocol.InvalidPacketNumber &&
			a.largestAcked != protocol.InvalidPacketNumber &&
			a.largestAcked >= a.firstSentWithCurrentKey)
}

func (a *updatableAEAD) shouldInitiateKeyUpdate() bool {
	if !a.updateAllowed() {
		return false
	}
	// Initiate the first key update shortly after the handshake, in order to exercise the key update mechanism.
	if a.keyPhase == 0 {
		if a.numRcvdWithCurrentKey >= FirstKeyUpdateInterval || a.numSentWithCurrentKey >= FirstKeyUpdateInterval {
			return true
		}
	}
	if a.numRcvdWithCurrentKey >= keyUpdateInterval.Load() {
		a.logger.Debugf("Received %d packets with current key phase. Initiating key update to the next key phase: %d", a.numRcvdWithCurrentKey, a.keyPhase+1)
		return true
	}
	if a.numSentWithCurrentKey >= keyUpdateInterval.Load() {
		a.logger.Debugf("Sent %d packets with current key phase. Initiating key update to the next key phase: %d", a.numSentWithCurrentKey, a.keyPhase+1)
		return true
	}
	return false
}

func (a *updatableAEAD) KeyPhase() protocol.KeyPhaseBit {
	if a.shouldInitiateKeyUpdate() {
		a.rollKeys()
		if a.qlogger != nil {
			a.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger:  qlog.KeyUpdateLocal,
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: a.keyPhase,
			})
			a.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger:  qlog.KeyUpdateLocal,
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: a.keyPhase,
			})
		}
	}
	return a.keyPhase.Bit()
}

func (a *updatableAEAD) Overhead() int {
	return a.aeadOverhead
}

func (a *updatableAEAD) EncryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	a.headerEncrypter.EncryptHeader(sample, firstByte, hdrBytes)
}

func (a *updatableAEAD) DecryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	a.headerDecrypter.DecryptHeader(sample, firstByte, hdrBytes)
}

func (a *updatableAEAD) FirstPacketNumber() protocol.PacketNumber {
	return a.firstPacketNumber
}

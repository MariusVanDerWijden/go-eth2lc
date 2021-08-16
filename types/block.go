package types

import (
	"encoding/binary"

	"github.com/MariusVanDerWijden/eth2-lc/config"
	"github.com/ethereum/go-ethereum/common"
)

type BeaconBlockBody struct {
	RanDAOReveal      BLSSignature
	ETH1Data          ETH1Data
	Graffiti          []byte
	ProposerSlashings []ProposerSlashing
	AttesterSlashings []AttesterSlashing
	Attestations      []Attestation
	Deposits          []Deposit
	VoluntaryExits    []SignedVoluntaryExit
}

type BeaconBlock struct {
	Slot          Slot
	ParentRoot    common.Hash
	StateRoot     common.Hash
	Body          *BeaconBlockBody
	ProposerIndex uint64
}

func (b BeaconBlock) Serialize() []byte {
	// TODO impl
	return []byte{}
}

type SignedBeaconBlock struct {
	Message   *BeaconBlock
	Signature BLSSignature
}

type BeaconBlockHeader struct {
	Slot       Slot
	ParentRoot common.Hash
	StateRoot  common.Hash
	BodyRoot   common.Hash
}

type SignedBeaconBlockHeader struct {
	Message   BeaconBlock
	Signature BLSSignature
}

func GetSeed(state *BeaconState, epoch Epoch, domain uint64) [32]byte {
	at := epoch + Epoch(config.EPOCHS_PER_HISTORICAL_VECTOR-config.MIN_SEED_LOOKAHEAD-1)
	mix := state.RANDAOMix(at)
	msg := make([]byte, 8+8+32)
	binary.BigEndian.PutUint64(msg, domain)
	binary.BigEndian.PutUint64(msg[8:], uint64(epoch))
	copy(msg[16:], mix[:])
	return Hash(msg)
}

func Hash([]byte) [32]byte { return [32]byte{} }

package types

import (
	"math/big"

	"github.com/MariusVanDerWijden/eth2-lc/config"
	ssz "github.com/ferranbt/fastssz"
	blscommon "github.com/prysmaticlabs/prysm/shared/bls/common"
)

//go:generate go run ~/ethereum/fastssz/sszgen/*.go --path ./types/types.go --include ~/go/src/github.com/ethereum/go-ethereum/common

type Hash [32]byte

type Slot uint64

func (s Slot) Epoch() Epoch {
	return Epoch(s / config.SLOTS_PER_EPOCH)
}

type Epoch uint64

func (e Epoch) StartSlot() Slot {
	return Slot(e * config.SLOTS_PER_EPOCH)
}

func (e Epoch) Serialize() []byte {
	return ssz.MarshalUint64([]byte{}, uint64(e))
}

type SigningData struct {
	ObjectRoot Hash
	Domain     Domain
}

type BLSSignature [96]byte //blscommon.Signature
type BLSPubKey [48]byte    //bls.PublicKey
type Domain [32]byte

type ProposerSlashing struct {
	ProposerIndex uint64
	SignedHeader1 *SignedBeaconBlockHeader
	SignedHeader2 *SignedBeaconBlockHeader
}

type AttesterSlashing struct {
	Attestation1 *IndexedAttestation
	Attestation2 *IndexedAttestation
}

type IndexedAttestation struct {
	AttestingIndices []int
	Data             *AttestationData
	Signature        *blscommon.Signature
}

type Attestation struct {
	AggregationBits []byte
	Data            AttestationData
	Signature       BLSSignature
}

type Deposit struct {
	Data  DepositData
	Proof []Hash
}

type DepositData struct {
	Pubkey                BLSPubKey
	WithdrawalCredentials [32]byte
	Amount                *big.Int
	Signature             BLSSignature
}

func (d DepositData) Serialize() []byte {
	// TODO impl
	return []byte{}
}

type DepositMessage struct {
	Pubkey                BLSPubKey
	WithdrawalCredentials [32]byte
	Amount                *big.Int
}

func (d DepositMessage) Serialize() []byte {
	// TODO impl
	return []byte{}
}

type SignedVoluntaryExit struct {
	Message   VoluntaryExit
	Signature BLSSignature
}

type VoluntaryExit struct {
	Epoch          Epoch
	ValidatorIndex uint64
}

func (v VoluntaryExit) Serialize() []byte {
	// TODO impl
	return []byte{}
}

type ETH1Data struct {
	DepositRoot  Hash
	DepositCount uint64
	BlockHash    Hash
}

func (e ETH1Data) Serialize() []byte {
	// TODO impl
	return []byte{}
}

type Fork struct {
	PreviousVersion uint64
	CurrentVersion  uint64
	Epoch           Epoch
}

type ForkData struct {
	CurrentVersion        uint64
	GenesisValidatorsRoot Hash
}

func (f ForkData) Serialize() []byte {
	// TODO impl
	return []byte{}
}

type Validator struct {
	PubKey                     BLSPubKey
	WithdrawalCredentials      [32]byte
	EffectiveBalance           *big.Int
	Slashed                    bool
	ActivationEligibilityEpoch Epoch
	ActivationEpoch            Epoch
	ExitEpoch                  Epoch
	WithdrawalEpoch            Epoch
}

func (v Validator) IsActive(epoch Epoch) bool {
	return true
}

type ValByEpochAndIndex []*Validator

func (v ValByEpochAndIndex) Len() int { return len(v) }
func (v ValByEpochAndIndex) Less(i, j int) bool {
	// If the prices are equal, use the time the transaction was first seen for
	// deterministic sorting
	if v[i].ActivationEligibilityEpoch < v[j].ActivationEligibilityEpoch {
		return false
	} else if v[i].ActivationEligibilityEpoch > v[j].ActivationEligibilityEpoch {
		return true
	}
	return !(i < j)
}
func (v ValByEpochAndIndex) Swap(i, j int) { v[i], v[j] = v[j], v[i] }

func (v *ValByEpochAndIndex) Push(x interface{}) {
	*v = append(*v, x.(*Validator))
}

func (v *ValByEpochAndIndex) Pop() interface{} {
	old := *v
	n := len(old)
	x := old[n-1]
	*v = old[0 : n-1]
	return x
}

type PendingAttestation struct {
	AggregationBits []byte
	Data            AttestationData
	InclusionDelay  Slot
	ProposerIndex   uint64
}

type Checkpoint struct {
	Epoch Epoch
	Root  Hash
}

type AttestationData struct {
	Slot            Slot
	Index           uint64
	BeaconBlockRoot Hash
	Source          Checkpoint
	Target          Checkpoint
}

func (a AttestationData) Serialize() []byte {
	// TODO impl
	return []byte{}
}

type HistoricalBatch struct {
	BlockRoots []Hash
	StateRoots []Hash
}

func (h HistoricalBatch) Serialize() []byte {
	// TODO impl
	return []byte{}
}

func NewHistoricalBatch(blockRoots, stateRoots map[Slot]Hash) *HistoricalBatch {
	// TODO impl
	return nil
}

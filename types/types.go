package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/prysmaticlabs/prysm/shared/bls"
	blscommon "github.com/prysmaticlabs/prysm/shared/bls/common"
)

type Slot uint64
type Epoch uint64

type BLSSignature blscommon.Signature
type BLSPubKey bls.PublicKey
type Domain uint64

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
	Proof []common.Hash
}

type DepositData struct {
	Pubkey                BLSPubKey
	WithdrawalCredentials [32]byte
	Amount                *big.Int
	Signature             BLSSignature
}

type DepositMessage struct {
	Pubkey                BLSPubKey
	WithdrawalCredentials [32]byte
	Amount                *big.Int
}

type SignedVoluntaryExit struct {
	Message   VoluntaryExit
	Signature BLSSignature
}

type VoluntaryExit struct {
	Epoch          Epoch
	ValidatorIndex uint64
}

type ETH1Data struct {
	DepositRoot  common.Hash
	DepositCount uint64
	BlockHash    common.Hash
}

type Fork struct {
	PreviousVersion uint64
	CurrentVersion  uint64
	Epoch           uint64
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

func (v *Validator) IsActive(epoch Epoch) bool {
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
	Root  common.Hash
}

type AttestationData struct {
	Slot            Slot
	Index           uint64
	BeaconBlockRoot common.Hash
	Source          Checkpoint
	Target          Checkpoint
}

type HistoricalBatch struct {
	BlockRoots []common.Hash
	StateRoots []common.Hash
}

func NewHistoricalBatch(blockRoots, stateRoots map[Slot]common.Hash) *HistoricalBatch {
	return nil
}

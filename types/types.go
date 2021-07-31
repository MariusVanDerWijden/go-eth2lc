package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/prysmaticlabs/prysm/shared/bls"
)

type Slot uint64
type Epoch uint64

type BLSSignature bls.Signature
type BLSPubKey bls.PublicKey

type ProposerSlashing []byte
type AttesterSlashing []byte
type Attestation []byte
type Deposit []byte
type VoluntaryExit []byte

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

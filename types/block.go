package types

import "github.com/ethereum/go-ethereum/common"

type BeaconBlockBody struct {
	RanDAOReveal      BLSSignature
	ETH1Data          ETH1Data
	Graffiti          []byte
	ProposerSlashings []ProposerSlashing
	AttesterSlashings []AttesterSlashing
	Attestations      []Attestation
	Deposits          []Deposit
	VoluntaryExits    []VoluntaryExit
}

type BeaconBlock struct {
	Slot       Slot
	ParentRoot common.Hash
	StateRoot  common.Hash
	Body       *BeaconBlockBody
}

type SignedBeaconBlock struct {
	Message   BeaconBlock
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

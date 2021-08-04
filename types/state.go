package types

import (
	"math/big"

	"github.com/MariusVanDerWijden/eth2-lc/config"
	"github.com/ethereum/go-ethereum/common"
	bitfield "github.com/prysmaticlabs/go-bitfield"
)

type BeaconState struct {
	GenesisTime                 uint64
	Slot                        Slot
	Fork                        Fork
	LatestBlockHeader           *BeaconBlockHeader
	BlockRoots                  map[Slot]common.Hash
	StateRoots                  map[Slot]common.Hash
	HistoricalRoots             map[Slot]common.Hash
	ETH1Data                    ETH1Data
	ETH1DataVotes               []ETH1Data
	ETH1DepositIndex            uint64
	Validators                  []*Validator
	Balances                    []*big.Int
	RanDAOMix                   [][32]byte
	Slashings                   map[Epoch]*big.Int
	PreviousEpochAttestations   []PendingAttestation
	CurrentEpochAttestations    []PendingAttestation
	JustificationBits           bitfield.Bitvector4
	PreviousJustifiedCheckpoint Checkpoint
	CurrentJustifiedCheckpoint  Checkpoint
	FinalizedCheckpoint         Checkpoint
}

func (b *BeaconState) IncreaseBalance(index uint64, balance *big.Int) {}

func (b *BeaconState) DecreaseBalance(index uint64, balance *big.Int) {}

func (b *BeaconState) GetBlockRoot(epoch Epoch) common.Hash {
	return common.Hash{}
}

func (b *BeaconState) TotalActiveBalance() *big.Int {
	return big.NewInt(0)
}

func (b *BeaconState) TotalActiveBalanceTimesTwo() *big.Int {
	return big.NewInt(0)
}

func (b *BeaconState) GetAttestingBalanceTimesThree(attesters []PendingAttestation) *big.Int {
	return big.NewInt(0)
}

func (b *BeaconState) TotalBalance(unslashedAttIndicies map[int]struct{}) *big.Int {
	return big.NewInt(0)
}

func (b *BeaconState) BaseReward(index int) *big.Int {
	return big.NewInt(0)
}

func (b *BeaconState) ValidatorChurnLimit() int {
	return 0
}

func (b *BeaconState) Epoch() Epoch {
	return Epoch(b.Slot / config.SLOTS_PER_EPOCH)
}

func (b *BeaconState) PrevEpoch() Epoch {
	if epoch := b.Epoch(); epoch != config.GENESIS_EPOCH {
		return Epoch(epoch - 1)
	}
	return Epoch(config.GENESIS_EPOCH)
}

func (b *BeaconState) CurrentProposer() (*Validator, uint64) {
	index := getBeaconProposerIndex(b)
	return b.Validators[index], index
}

func getBeaconProposerIndex(state *BeaconState) uint64 {
	// TODO impl
	return 0
}

func (b *BeaconState) RANDAOMix(epoch Epoch) [32]byte {
	return [32]byte{}
}

func (b *BeaconState) IndexedAttestation(att Attestation) *IndexedAttestation {
	// TODO impl
	return &IndexedAttestation{}
}

func (b *BeaconState) ValidatorPubkeys() map[BLSPubKey]uint64 {
	pubKeys := make(map[BLSPubKey]uint64)
	for index, val := range b.Validators {
		pubKeys[val.PubKey] = uint64(index)
	}
	return pubKeys
}

func (b *BeaconState) AddValidator(val *Validator, amount *big.Int) {
	b.Validators = append(b.Validators, val)
	b.Balances = append(b.Balances, amount)
}

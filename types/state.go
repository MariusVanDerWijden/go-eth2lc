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
	LatestBlockHeader           BeaconBlockHeader
	BlockRoots                  map[Slot]common.Hash
	StateRoots                  map[Slot]common.Hash
	HistoricalRoots             map[Slot]common.Hash
	ETH1Data                    ETH1Data
	ETH1DataVotes               []ETH1Data
	ETH1DepositIndex            uint64
	Validators                  []Validator
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

func (b *BeaconState) IncreaseBalance(index int, balance *big.Int) {}

func (b *BeaconState) DecreaseBalance(index int, balance *big.Int) {}

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

func (b *BeaconState) Epoch() Epoch {
	return Epoch(b.Slot / config.SLOTS_PER_EPOCH)
}

func (b *BeaconState) PrevEpoch() Epoch {
	if epoch := b.Epoch(); epoch != config.GENESIS_EPOCH {
		return Epoch(epoch - 1)
	}
	return Epoch(config.GENESIS_EPOCH)
}

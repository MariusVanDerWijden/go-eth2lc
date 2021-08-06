package types

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/MariusVanDerWijden/eth2-lc/config"
	"github.com/ethereum/go-ethereum/common"
	bitfield "github.com/prysmaticlabs/go-bitfield"
)

type BeaconState struct {
	GenesisTime                 uint64
	GenesisValidatorsRoot       common.Hash
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

func (b *BeaconState) Serialize() []byte {
	// TODO impl
	return []byte{}
}

func (b *BeaconState) IncreaseBalance(index uint64, balance *big.Int) {
	b.Balances[index].Add(b.Balances[index], balance)
}

func (b *BeaconState) DecreaseBalance(index uint64, balance *big.Int) {
	b.Balances[index].Sub(b.Balances[index], balance)
	if b.Balances[index].Cmp(common.Big0) < 0 {
		b.Balances[index] = common.Big0
	}
}

func (b *BeaconState) BlockRoot(epoch Epoch) common.Hash {
	return b.BlockRootBySlot(epoch.StartSlot())
}

func (b *BeaconState) BlockRootBySlot(slot Slot) common.Hash {
	if slot >= b.Slot || b.Slot > slot+config.SLOTS_PER_HISTORICAL_ROOT {
		panic("invalid slots in block root per slot")
	}
	return b.BlockRoots[slot%config.SLOTS_PER_HISTORICAL_ROOT]
}

func (b *BeaconState) TotalActiveBalance() *big.Int {
	sum := big.NewInt(0)
	for _, val := range b.Validators {
		if val.IsActive(b.Epoch()) {
			sum.Add(sum, val.EffectiveBalance)
		}
	}
	return sum
}

func (b *BeaconState) TotalActiveBalanceTimesTwo() *big.Int {
	bal := b.TotalActiveBalance()
	return new(big.Int).Mul(bal, big.NewInt(2))
}

func (b *BeaconState) GetAttestingBalanceTimesThree(attesters []PendingAttestation) *big.Int {

	// TODO impl
	return big.NewInt(0)
}

func (b *BeaconState) TotalBalance(unslashedAttIndicies map[int]struct{}) *big.Int {
	sum := big.NewInt(0)
	for index := range unslashedAttIndicies {
		sum.Add(sum, b.Validators[index].EffectiveBalance)
	}
	return sum
}

func (b *BeaconState) BaseReward(index int) *big.Int {
	totalBalance := b.TotalActiveBalance()
	effectiveBal := b.Validators[index].EffectiveBalance
	bal := new(big.Int).Mul(effectiveBal, big.NewInt(config.BASE_REWARD_FACTOR))
	bal.Div(bal, new(big.Int).Sqrt(totalBalance))
	bal.Div(bal, big.NewInt(config.BASE_REWARDS_PER_EPOCH))
	return bal
}

func (b *BeaconState) ValidatorChurnLimit() int {
	// TODO impl
	activeValIndices := b.GetActiveValidatorIndices(b.Epoch())
	max := len(activeValIndices)
	if max < config.MIN_PER_EPOCH_CHURN_LIMIT {
		max = config.MIN_PER_EPOCH_CHURN_LIMIT
	}
	return max / config.CHURN_LIMIT_QUOTIENT
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
	index := b.getBeaconProposerIndex()
	return b.Validators[index], index
}

func (b *BeaconState) getBeaconProposerIndex() uint64 {
	epoch := b.Epoch()
	s := make([]byte, 40)
	s2 := GetSeed(b, epoch, config.DOMAIN_BEACON_PROPOSER)
	copy(s, s2[:])
	binary.BigEndian.PutUint64(s[32:], uint64(b.Slot))
	seed := Hash(s)
	indices := b.GetActiveValidatorIndices(epoch)
	return computeProposerIndex(b, indices, seed)
}

func (b *BeaconState) RANDAOMix(epoch Epoch) [32]byte {
	return b.RanDAOMix[epoch]
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

func (b *BeaconState) MaxExitEpoch() Epoch {
	// exit_epochs = [v.exit_epoch for v in state.validators if v.exit_epoch != FAR_FUTURE_EPOCH]
	var max Epoch
	for _, v := range b.Validators {
		if v.ExitEpoch != config.FAR_FUTURE_EPOCH {
			if v.ExitEpoch > max {
				max = v.ExitEpoch
			}
		}
	}
	return max
}

func (b *BeaconState) ExitQueueChurn(epoch Epoch) int {
	var res int
	for _, val := range b.Validators {
		if val.ExitEpoch == epoch {
			res++
		}
	}
	return res
}

func (b *BeaconState) GetActiveValidatorIndices(epoch Epoch) []int {
	var indices []int
	for index, val := range b.Validators {
		if val.IsActive(epoch) {
			indices = append(indices, index)
		}
	}
	return indices
}

func (b *BeaconState) MatchingSourceAttests(epoch Epoch) []PendingAttestation {
	if epoch != b.Epoch() && epoch != b.PrevEpoch() {
		panic(fmt.Sprintf("matching source attest with invalid epoch: %v want %v or %v", epoch, b.Epoch(), b.PrevEpoch()))
	}
	if epoch == b.Epoch() {
		return b.CurrentEpochAttestations
	}
	return b.PreviousEpochAttestations
}

func (b *BeaconState) MatchingTargetAttests(epoch Epoch) (target []PendingAttestation) {
	source := b.MatchingSourceAttests(epoch)
	for _, att := range source {
		if att.Data.Target.Root == b.BlockRoot(epoch) {
			target = append(target, att)
		}
	}
	return
}

func (b *BeaconState) MatchingAttests(epoch Epoch) (source, target, head []PendingAttestation) {
	source = b.MatchingSourceAttests(epoch)
	for _, att := range source {
		if att.Data.Target.Root == b.BlockRoot(epoch) {
			target = append(target, att)
		}
	}
	for _, att := range target {
		if att.Data.BeaconBlockRoot == b.BlockRootBySlot(att.Data.Slot) {
			head = append(head, att)
		}
	}
	return
}

func computeProposerIndex(state *BeaconState, indices []int, seed [32]byte) uint64 {
	if len(indices) <= 0 {
		panic("not enough proposers in computeProposerIndex")
	}
	MAX_RANDOM_BYTE := 1<<8 - 1
	i := uint64(0)
	total := uint64(len(indices))
	for {
		candidateIndex := indices[ComputeShuffledIndex(i%total, total, seed)]
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i/32))
		randomByte := Hash(append(seed[:], b...))[i%32]
		effBal := new(big.Int).Mul(state.Validators[candidateIndex].EffectiveBalance, big.NewInt(int64(MAX_RANDOM_BYTE)))
		if effBal.Cmp(new(big.Int).Mul(big.NewInt(config.MAX_EFFECTIVE_BALANCE), big.NewInt(int64(randomByte)))) >= 0 {
			return uint64(candidateIndex)
		}
		i++
	}
}

func ComputeShuffledIndex(index, indexCount uint64, seed [32]byte) uint64 {
	if index >= indexCount {
		panic(fmt.Sprintf("index invalid: %v %v", index, indexCount))
	}

	// Swap or not (https://link.springer.com/content/pdf/10.1007%2F978-3-642-32009-5_1.pdf)
	// See the 'generalized domain' algorithm on page 3
	for currentRound := 0; currentRound < config.SHUFFLE_ROUND_COUNT; currentRound++ {
		s := append(seed[:], byte(uint8(currentRound)))
		h := Hash(s)
		pivot := binary.BigEndian.Uint64(h[:]) % indexCount
		flip := (pivot + indexCount - index) % indexCount
		position := flip
		if position < index {
			position = index
		}
		p := uint32(position / 256)
		pBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(pBytes, p)
		s2 := append(s, pBytes...)
		source := Hash(s2)
		by := source[(position%256)/8]
		bit := (by >> byte(position) % 8) % 2
		if bit != 0 {
			index = flip
		}
	}
	return index
}

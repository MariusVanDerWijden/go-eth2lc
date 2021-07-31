package core

import (
	"fmt"

	"github.com/MariusVanDerWijden/eth2-lc/config"
	"github.com/MariusVanDerWijden/eth2-lc/types"
	"github.com/ethereum/go-ethereum/common"
)

func StateTransition(state *types.BeaconState, signedBlock types.SignedBeaconBlock, validate bool) (*types.BeaconState, error) {
	block := signedBlock.Message
	if err := processSlots(state, block.Slot); err != nil {
		return nil, err
	}
	if validate {
		if err := verifyBlockSignature(state, signedBlock); err != nil {
			return nil, err
		}
	}
	processBlock(state, block)
	if validate {
		if got := hashTreeRoot(state); block.StateRoot != got {
			return nil, fmt.Errorf("invalid state root, got %v, want %v", got, block.StateRoot)
		}
	}
	return state, nil
}

func processSlots(state *types.BeaconState, slot types.Slot) error {
	if state.Slot > slot {
		return fmt.Errorf("invalid slot old: %v new %v", state.Slot, slot)
	}
	for ; state.Slot < slot; state.Slot += types.Slot(1) {
		processSlot(state)
		if (state.Slot+1)%config.SLOTS_PER_EPOCH == 0 {
			processEpoch(state)
		}
	}
	return nil
}

func processSlot(state *types.BeaconState) {
	prevStateRoot := hashTreeRoot(state)
	state.StateRoots[state.Slot%config.SLOTS_PER_HISTORICAL_ROOT] = prevStateRoot
	if (state.LatestBlockHeader.StateRoot == common.Hash{}) {
		state.LatestBlockHeader.StateRoot = prevStateRoot
	}
	prevStateRoot = hashTreeRootHeader(state.LatestBlockHeader)
	state.BlockRoots[state.Slot%config.SLOTS_PER_HISTORICAL_ROOT] = prevStateRoot
}

func verifyBlockSignature(state *types.BeaconState, signedBlock types.SignedBeaconBlock) error {
	return nil
}
func hashTreeRoot(state *types.BeaconState) common.Hash {
	return common.Hash{}
}
func hashTreeRootHeader(header types.BeaconBlockHeader) common.Hash {
	return common.Hash{}
}

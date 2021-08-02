package core

import (
	"container/heap"
	"math/big"

	"github.com/MariusVanDerWijden/eth2-lc/config"
	"github.com/MariusVanDerWijden/eth2-lc/types"
)

func processEpoch(state *types.BeaconState) {
	processJustificationFinalization(state)
	processRewardsPenalties(state)
	processRegistryUpdates(state)
	// process_reveal_deadlines
	// process_challenge_deadlines
	processSlashings(state)
	processFinalUpdates(state)
	// after_process_final_updates
}

func processJustificationFinalization(state *types.BeaconState) {
	currentEpoch := state.Epoch()
	if currentEpoch <= config.GENESIS_EPOCH+1 {
		return
	}
	prevEpoch := state.PrevEpoch()
	oldPrevJustifiedCheckpoint := state.PreviousJustifiedCheckpoint
	oldCurJustifiedCheckpoint := state.CurrentJustifiedCheckpoint

	state.PreviousJustifiedCheckpoint = state.CurrentJustifiedCheckpoint
	state.JustificationBits.Shift(1)
	state.JustificationBits.SetBitAt(0, false)

	matchTargetAttests := getMatchingTargetAttests(state, prevEpoch)
	if state.GetAttestingBalanceTimesThree(matchTargetAttests).Cmp(state.TotalActiveBalanceTimesTwo()) > 0 {
		state.CurrentJustifiedCheckpoint = types.Checkpoint{
			Epoch: prevEpoch,
			Root:  state.GetBlockRoot(prevEpoch),
		}
		state.JustificationBits.SetBitAt(1, true)
	}
	matchTargetAttests = getMatchingTargetAttests(state, currentEpoch)
	if state.GetAttestingBalanceTimesThree(matchTargetAttests).Cmp(state.TotalActiveBalanceTimesTwo()) > 0 {
		state.CurrentJustifiedCheckpoint = types.Checkpoint{
			Epoch: currentEpoch,
			Root:  state.GetBlockRoot(currentEpoch),
		}
		state.JustificationBits.SetBitAt(0, true)
	}

	bits := state.JustificationBits.Bytes()[0]
	// 0x00001110 The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
	if bits&0x0E == 0x0E && oldPrevJustifiedCheckpoint.Epoch+3 == currentEpoch {
		state.FinalizedCheckpoint = oldPrevJustifiedCheckpoint
	}
	// 0x00000110 The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
	if bits&0x06 == 0x06 && oldPrevJustifiedCheckpoint.Epoch+2 == currentEpoch {
		state.FinalizedCheckpoint = oldPrevJustifiedCheckpoint
	}
	// 0x00000111 The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
	if bits&0x07 == 0x07 && oldCurJustifiedCheckpoint.Epoch+2 == currentEpoch {
		state.FinalizedCheckpoint = oldCurJustifiedCheckpoint
	}
	// 0x00000011 The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
	if bits&0x03 == 0x03 && oldCurJustifiedCheckpoint.Epoch+1 == currentEpoch {
		state.FinalizedCheckpoint = oldCurJustifiedCheckpoint
	}
}

func processRewardsPenalties(state *types.BeaconState) {
	if state.Epoch() == config.GENESIS_EPOCH {
		return
	}
	rewards, penalties := getAttestationDeltas(state)
	for index := 0; index < len(state.Validators); index++ {
		state.IncreaseBalance(index, rewards[index])
		state.DecreaseBalance(index, penalties[index])
	}
}

func getAttestationDeltas(state *types.BeaconState) ([]*big.Int, []*big.Int) {
	prevEpoch := state.PrevEpoch()
	totalBal := state.TotalActiveBalance()
	rewards := make([]*big.Int, len(state.Validators))
	penalties := make([]*big.Int, len(state.Validators))
	ellValidatorIndices := make([]int, 0, len(state.Validators))
	for i, val := range state.Validators {
		if val.IsActive(prevEpoch) || (val.Slashed && prevEpoch+1 < val.WithdrawalEpoch) {
			ellValidatorIndices = append(ellValidatorIndices, i)
		}
	}
	matchSourceAtts := getMatchingSourceAttests(state, prevEpoch)
	matchTargetAtts := getMatchingTargetAttests(state, prevEpoch)
	matchHeadAtts := getMatchingHeadAttests(state, prevEpoch)

	allAtts := append(matchSourceAtts, matchTargetAtts...)
	allAtts = append(allAtts, matchHeadAtts...)

	// Micro-incentives for matching FFG source, FFG target, and head
	for _, atts := range [][]types.PendingAttestation{matchSourceAtts, matchTargetAtts, matchHeadAtts} {
		// TODO heres a bug, its in range of 3 not all
		unslashedAttIndicies := getUnslashedAttIndices(state, atts)
		attestingBalance := state.TotalBalance(unslashedAttIndicies)
		for _, index := range ellValidatorIndices {
			if _, ok := unslashedAttIndicies[index]; ok {
				b := new(big.Int).Mul(state.BaseReward(index), attestingBalance)
				rewards[index].Add(rewards[index], new(big.Int).Div(b, totalBal))
			} else {
				penalties[index].Add(rewards[index], state.BaseReward(index))
			}
		}
	}
	// Proposer and inclusion delay micro-rewards
	for index := range getUnslashedAttIndices(state, matchSourceAtts) {
		min := func(index int, atts []types.PendingAttestation) types.PendingAttestation {
			min := atts[0]
			for _, a := range atts {
				if _, ok := getAttestingIndices(state, a.Data, a.AggregationBits)[index]; ok {
					if min.InclusionDelay > a.InclusionDelay {
						min = a
					}
				}
			}
			return min
		}
		attestation := min(index, matchSourceAtts)
		proposerReward := new(big.Int).Div(state.BaseReward(index), big.NewInt(config.PROPOSER_REWARD_QUOTIENT))
		rewards[attestation.ProposerIndex].Add(rewards[attestation.ProposerIndex], proposerReward)
		maxAttestReward := new(big.Int).Sub(state.BaseReward(index), proposerReward)
		rewards[index].Add(rewards[index], new(big.Int).Sub(maxAttestReward, big.NewInt(int64(attestation.InclusionDelay))))
	}
	// Inactivity penalty
	finalityDelay := prevEpoch - state.FinalizedCheckpoint.Epoch
	if finalityDelay > config.MIN_EPOCHS_TO_INACTIVITY_PENALTY {
		matchTargetAttIndices := getUnslashedAttIndices(state, matchTargetAtts)
		for _, index := range ellValidatorIndices {
			penalties[index].Add(penalties[index], new(big.Int).Mul(big.NewInt(config.BASE_REWARDS_PER_EPOCH), state.BaseReward(index)))
			if _, ok := matchTargetAttIndices[index]; !ok {
				effectiveBalance := state.Validators[index].EffectiveBalance
				b := new(big.Int).Div(new(big.Int).Mul(effectiveBalance, big.NewInt(int64(finalityDelay))), big.NewInt(config.INACTIVITY_PENALTY_QUOTIENT))
				penalties[index].Add(penalties[index], b)
			}
		}
	}
	return rewards, penalties
}

func processRegistryUpdates(state *types.BeaconState) {
	// Process activation eligibility and ejections
	for index, val := range state.Validators {
		if isElegibleForActivationQueue(val) {
			val.ActivationEligibilityEpoch = state.Epoch() + 1
		}
		if val.IsActive(state.Epoch()) && val.EffectiveBalance.Cmp(big.NewInt(config.EJECTION_BALANCE)) <= 0 {
			initiateValidatorExit(state, index)
		}
	}
	// Queue validators eligible for activation and not yet dequeued for activation
	sorted := types.ValByEpochAndIndex(state.Validators)
	heap.Init(&sorted)
	for i := 0; i < state.ValidatorChurnLimit(); i++ {
		validator := sorted.Pop().(*types.Validator)
		validator.ActivationEpoch = computeActivationExitEpoch(state.Epoch())
	}
}

func processSlashings(state *types.BeaconState) {
	epoch := state.Epoch()
	totalBalance := state.TotalActiveBalance()
	increment := big.NewInt(config.EFFECTIVE_BALANCE_INCREMENT)
	for index, validator := range state.Validators {
		if validator.Slashed && epoch+config.EPOCHS_PER_SLASHINGS_VECTOR/2 == validator.WithdrawalEpoch {
			var sum *big.Int
			for _, s := range state.Slashings {
				sum.Add(sum, s)
			}
			sum.Mul(sum, big.NewInt(3))
			if sum.Cmp(totalBalance) > 0 {
				sum = totalBalance
			}
			penaltyNumerator := new(big.Int).Div(validator.EffectiveBalance, new(big.Int).Mul(increment, sum))
			state.DecreaseBalance(index, penaltyNumerator)
		}
	}
}

func processFinalUpdates(state *types.BeaconState) {
	epoch := state.Epoch()
	nextEpoch := epoch + 1
	// Reset eth1 data votes
	if state.Slot+1%config.SLOTS_PER_ETH1_VOTING_PERIOD == 0 {
		state.ETH1DataVotes = make([]types.ETH1Data, 0)
	}
	// Update effective balances with hyteresis
	for index, val := range state.Validators {
		balance := state.Balances[index]
		if balance.Cmp(val.EffectiveBalance) < 0 || new(big.Int).Add(val.EffectiveBalance, big.NewInt(config.EFFECTIVE_BALANCE_INCREMENT)).Cmp(balance) < 0 {
			min := new(big.Int).Sub(balance, new(big.Int).Mod(balance, big.NewInt(config.EFFECTIVE_BALANCE_INCREMENT)))
			if min.Cmp(big.NewInt(config.MAX_EFFECTIVE_BALANCE)) < 0 {
				min = big.NewInt(config.MAX_EFFECTIVE_BALANCE)
			}
			val.EffectiveBalance = min
		}
	}
	// Reset slashings
	state.Slashings[nextEpoch%config.EPOCHS_PER_SLASHINGS_VECTOR] = big.NewInt(0)
	state.RanDAOMix[nextEpoch%config.EPOCHS_PER_SLASHINGS_VECTOR] = getRandaoMix(state, epoch)
	// Set historical root accumulator
	if nextEpoch%(config.SLOTS_PER_HISTORICAL_ROOT/config.SLOTS_PER_EPOCH) == 0 {
		historicalBatch := types.NewHistoricalBatch(state.BlockRoots, state.StateRoots)
		state.HistoricalRoots[types.Slot(len(state.HistoricalRoots)-1)] = hashTreeHistoricalBatch(historicalBatch)
	}
	// Rotate current/previous epoch attestations
	state.PreviousEpochAttestations = state.CurrentEpochAttestations
	state.CurrentEpochAttestations = make([]types.PendingAttestation, 0)
}

func getMatchingTargetAttests(beaconstate *types.BeaconState, epoch types.Epoch) []types.PendingAttestation {
	// TODO impl
	return []types.PendingAttestation{}
}

func getMatchingSourceAttests(beaconstate *types.BeaconState, epoch types.Epoch) []types.PendingAttestation {
	// TODO impl
	return []types.PendingAttestation{}
}

func getMatchingHeadAttests(beaconstate *types.BeaconState, epoch types.Epoch) []types.PendingAttestation {
	// TODO impl
	return []types.PendingAttestation{}
}

func getUnslashedAttIndices(beaconstate *types.BeaconState, atts []types.PendingAttestation) map[int]struct{} {
	// TODO impl
	return nil
}

func getAttestingIndices(beaconstate *types.BeaconState, data types.AttestationData, aggrBits []byte) map[int]struct{} {
	// TODO impl
	return nil
}

func isElegibleForActivationQueue(val *types.Validator) bool {
	// TODO impl
	return true
}

func initiateValidatorExit(beaconstate *types.BeaconState, index int) error {
	return nil
}

func computeActivationExitEpoch(epoch types.Epoch) types.Epoch {
	return types.Epoch(0)
}

func getRandaoMix(beaconstate *types.BeaconState, epoch types.Epoch) [32]byte {
	return [32]byte{}
}

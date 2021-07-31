package core

import (
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
	if bits^0x0E == 0 && oldPrevJustifiedCheckpoint.Epoch+3 == currentEpoch {
		state.FinalizedCheckpoint = oldPrevJustifiedCheckpoint
	}
	// 0x00000110 The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
	if bits^0x06 == 0 && oldPrevJustifiedCheckpoint.Epoch+2 == currentEpoch {
		state.FinalizedCheckpoint = oldPrevJustifiedCheckpoint
	}
	// 0x00000111 The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
	if bits^0x07 == 0 && oldCurJustifiedCheckpoint.Epoch+2 == currentEpoch {
		state.FinalizedCheckpoint = oldCurJustifiedCheckpoint
	}
	// 0x00000011 The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
	if bits^0x03 == 0 && oldCurJustifiedCheckpoint.Epoch+1 == currentEpoch {
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
	/*
			def get_attestation_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
		    previous_epoch = get_previous_epoch(state)
		    total_balance = get_total_active_balance(state)
		    rewards = [Gwei(0) for _ in range(len(state.validators))]
		    penalties = [Gwei(0) for _ in range(len(state.validators))]
		    eligible_validator_indices = [
		        ValidatorIndex(index) for index, v in enumerate(state.validators)
		        if is_active_validator(v, previous_epoch) or (v.slashed and previous_epoch + 1 < v.withdrawable_epoch)
		    ]

		    # Micro-incentives for matching FFG source, FFG target, and head
		    matching_source_attestations = get_matching_source_attestations(state, previous_epoch)
		    matching_target_attestations = get_matching_target_attestations(state, previous_epoch)
		    matching_head_attestations = get_matching_head_attestations(state, previous_epoch)
		    for attestations in (matching_source_attestations, matching_target_attestations, matching_head_attestations):
		        unslashed_attesting_indices = get_unslashed_attesting_indices(state, attestations)
		        attesting_balance = get_total_balance(state, unslashed_attesting_indices)
		        for index in eligible_validator_indices:
		            if index in unslashed_attesting_indices:
		                rewards[index] += get_base_reward(state, index) * attesting_balance // total_balance
		            else:
		                penalties[index] += get_base_reward(state, index)

		    # Proposer and inclusion delay micro-rewards
		    for index in get_unslashed_attesting_indices(state, matching_source_attestations):
		        attestation = min([
		            a for a in matching_source_attestations
		            if index in get_attesting_indices(state, a.data, a.aggregation_bits)
		        ], key=lambda a: a.inclusion_delay)
		        proposer_reward = Gwei(get_base_reward(state, index) // PROPOSER_REWARD_QUOTIENT)
		        rewards[attestation.proposer_index] += proposer_reward
		        max_attester_reward = get_base_reward(state, index) - proposer_reward
		        rewards[index] += Gwei(max_attester_reward // attestation.inclusion_delay)

		    # Inactivity penalty
		    finality_delay = previous_epoch - state.finalized_checkpoint.epoch
		    if finality_delay > MIN_EPOCHS_TO_INACTIVITY_PENALTY:
		        matching_target_attesting_indices = get_unslashed_attesting_indices(state, matching_target_attestations)
		        for index in eligible_validator_indices:
		            penalties[index] += Gwei(BASE_REWARDS_PER_EPOCH * get_base_reward(state, index))
		            if index not in matching_target_attesting_indices:
		                effective_balance = state.validators[index].effective_balance
		                penalties[index] += Gwei(effective_balance * finality_delay // INACTIVITY_PENALTY_QUOTIENT)

		    return rewards, penalties
	*/
	return rewards, penalties
}

func processRegistryUpdates(state *types.BeaconState) {
	/*
			def process_registry_updates(state: BeaconState) -> None:
		    # Process activation eligibility and ejections
		    for index, validator in enumerate(state.validators):
		        if is_eligible_for_activation_queue(validator):
		            validator.activation_eligibility_epoch = get_current_epoch(state) + 1

		        if is_active_validator(validator, get_current_epoch(state)) and validator.effective_balance <= EJECTION_BALANCE:
		            initiate_validator_exit(state, ValidatorIndex(index))

		    # Queue validators eligible for activation and not yet dequeued for activation
		    activation_queue = sorted([
		        index for index, validator in enumerate(state.validators)
		        if is_eligible_for_activation(state, validator)
		        # Order by the sequence of activation_eligibility_epoch setting and then index
		    ], key=lambda index: (state.validators[index].activation_eligibility_epoch, index))
		    # Dequeued validators for activation up to churn limit
		    for index in activation_queue[:get_validator_churn_limit(state)]:
		        validator = state.validators[index]
		        validator.activation_epoch = compute_activation_exit_epoch(get_current_epoch(state))
	*/
}

func processSlashings(state *types.BeaconState) {
	/*
			def process_slashings(state: BeaconState) -> None:
		    epoch = get_current_epoch(state)
		    total_balance = get_total_active_balance(state)
		    for index, validator in enumerate(state.validators):
		        if validator.slashed and epoch + EPOCHS_PER_SLASHINGS_VECTOR // 2 == validator.withdrawable_epoch:
		            increment = EFFECTIVE_BALANCE_INCREMENT  # Factored out from penalty numerator to avoid uint64 overflow
		            penalty_numerator = validator.effective_balance // increment * min(sum(state.slashings) * 3, total_balance)
		            penalty = penalty_numerator // total_balance * increment
		            decrease_balance(state, ValidatorIndex(index), penalty)
	*/
}

func processFinalUpdates(state *types.BeaconState) {
	/*
			def process_final_updates(state: BeaconState) -> None:
		    current_epoch = get_current_epoch(state)
		    next_epoch = Epoch(current_epoch + 1)
		    # Reset eth1 data votes
		    if (state.slot + 1) % SLOTS_PER_ETH1_VOTING_PERIOD == 0:
		        state.eth1_data_votes = []
		    # Update effective balances with hysteresis
		    for index, validator in enumerate(state.validators):
		        balance = state.balances[index]
		        HALF_INCREMENT = EFFECTIVE_BALANCE_INCREMENT // 2
		        if balance < validator.effective_balance or validator.effective_balance + 3 * HALF_INCREMENT < balance:
		            validator.effective_balance = min(balance - balance % EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)
		    # Reset slashings
		    state.slashings[next_epoch % EPOCHS_PER_SLASHINGS_VECTOR] = Gwei(0)
		    # Set randao mix
		    state.randao_mixes[next_epoch % EPOCHS_PER_HISTORICAL_VECTOR] = get_randao_mix(state, current_epoch)
		    # Set historical root accumulator
		    if next_epoch % (SLOTS_PER_HISTORICAL_ROOT // SLOTS_PER_EPOCH) == 0:
		        historical_batch = HistoricalBatch(block_roots=state.block_roots, state_roots=state.state_roots)
		        state.historical_roots.append(hash_tree_root(historical_batch))
		    # Rotate current/previous epoch attestations
		    state.previous_epoch_attestations = state.current_epoch_attestations
		    state.current_epoch_attestations = []
	*/
}

func getMatchingTargetAttests(beaconstate *types.BeaconState, epoch types.Epoch) []types.PendingAttestation {
	return []types.PendingAttestation{}
}

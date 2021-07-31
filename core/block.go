package core

import (
	"github.com/MariusVanDerWijden/eth2-lc/types"
)

func processBlock(state *types.BeaconState, signedBlock types.BeaconBlock) {
	/*
	   def process_block(state: BeaconState, block: BeaconBlock) -> None:
	       process_block_header(state, block)
	       process_randao(state, block.body)
	       process_eth1_data(state, block.body)
	       process_operations(state, block.body)
	*/
}

func processBlockHeader(state *types.BeaconState, signedBlock types.BeaconBlock) {
	/*
			ef process_block_header(state: BeaconState, block: BeaconBlock) -> None:
		    # Verify that the slots match
		    assert block.slot == state.slot
		    # Verify that the parent matches
		    assert block.parent_root == hash_tree_root(state.latest_block_header)
		    # Cache current block as the new latest block
		    state.latest_block_header = BeaconBlockHeader(
		        slot=block.slot,
		        parent_root=block.parent_root,
		        state_root=Bytes32(),  # Overwritten in the next process_slot call
		        body_root=hash_tree_root(block.body),
		    )

		    # Verify proposer is not slashed
		    proposer = state.validators[get_beacon_proposer_index(state)]
		    assert not proposer.slashed
	*/
}

func processRanDAO() {
	/*
			def process_randao(state: BeaconState, body: BeaconBlockBody) -> None:
		    epoch = get_current_epoch(state)
		    # Verify RANDAO reveal
		    proposer = state.validators[get_beacon_proposer_index(state)]
		    signing_root = compute_signing_root(epoch, get_domain(state, DOMAIN_RANDAO))
		    assert bls.Verify(proposer.pubkey, signing_root, body.randao_reveal)
		    # Mix in RANDAO reveal
		    mix = xor(get_randao_mix(state, epoch), hash(body.randao_reveal))
		    state.randao_mixes[epoch % EPOCHS_PER_HISTORICAL_VECTOR] = mix
	*/
}

func processETH1Data() {
	/*
			def process_eth1_data(state: BeaconState, body: BeaconBlockBody) -> None:
		    state.eth1_data_votes.append(body.eth1_data)
		    if state.eth1_data_votes.count(body.eth1_data) * 2 > SLOTS_PER_ETH1_VOTING_PERIOD:
		        state.eth1_data = body.eth1_data
	*/
}

func processOperations() {
	/*
			def process_operations(state: BeaconState, body: BeaconBlockBody) -> None:
		    # Verify that outstanding deposits are processed up to the maximum number of deposits
		    assert len(body.deposits) == min(MAX_DEPOSITS, state.eth1_data.deposit_count - state.eth1_deposit_index)

		    for operations, function in (
		        (body.proposer_slashings, process_proposer_slashing),
		        (body.attester_slashings, process_attester_slashing),
		        (body.attestations, process_attestation),
		        (body.deposits, process_deposit),
		        (body.voluntary_exits, process_voluntary_exit),
		        # @process_shard_receipt_proofs
		    ):
		        for operation in operations:
		            function(state, operation)
	*/
}

func processProposerSlashing() {
	/*
			def process_proposer_slashing(state: BeaconState, proposer_slashing: ProposerSlashing) -> None:
		    # Verify header slots match
		    assert proposer_slashing.signed_header_1.message.slot == proposer_slashing.signed_header_2.message.slot
		    # Verify the headers are different
		    assert proposer_slashing.signed_header_1 != proposer_slashing.signed_header_2
		    # Verify the proposer is slashable
		    proposer = state.validators[proposer_slashing.proposer_index]
		    assert is_slashable_validator(proposer, get_current_epoch(state))
		    # Verify signatures
		    for signed_header in (proposer_slashing.signed_header_1, proposer_slashing.signed_header_2):
		        domain = get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(signed_header.message.slot))
		        signing_root = compute_signing_root(signed_header.message, domain)
		        assert bls.Verify(proposer.pubkey, signing_root, signed_header.signature)

		    slash_validator(state, proposer_slashing.proposer_index)
	*/
}

func isSlashableValidator() {
	/*
			ef is_slashable_validator(validator: Validator, epoch: Epoch) -> bool:
		    """
		    Check if ``validator`` is slashable.
		    """
		    return (not validator.slashed) and (validator.activation_epoch <= epoch < validator.withdrawable_epoch)
	*/
}

func SlashValidator() {
	/*
			def slash_validator(state: BeaconState,
		                    slashed_index: ValidatorIndex,
		                    whistleblower_index: ValidatorIndex=None) -> None:
		    """
		    Slash the validator with index ``slashed_index``.
		    """
		    epoch = get_current_epoch(state)
		    initiate_validator_exit(state, slashed_index)
		    validator = state.validators[slashed_index]
		    validator.slashed = True
		    validator.withdrawable_epoch = max(validator.withdrawable_epoch, Epoch(epoch + EPOCHS_PER_SLASHINGS_VECTOR))
		    state.slashings[epoch % EPOCHS_PER_SLASHINGS_VECTOR] += validator.effective_balance
		    decrease_balance(state, slashed_index, validator.effective_balance // MIN_SLASHING_PENALTY_QUOTIENT)

		    # Apply proposer and whistleblower rewards
		    proposer_index = get_beacon_proposer_index(state)
		    if whistleblower_index is None:
		        whistleblower_index = proposer_index
		    whistleblower_reward = Gwei(validator.effective_balance // WHISTLEBLOWER_REWARD_QUOTIENT)
		    proposer_reward = Gwei(whistleblower_reward // PROPOSER_REWARD_QUOTIENT)
		    increase_balance(state, proposer_index, proposer_reward)
		    increase_balance(state, whistleblower_index, whistleblower_reward - proposer_reward)
	*/
}

func processAttesterSlashing() {
	/*
			def process_attester_slashing(state: BeaconState, attester_slashing: AttesterSlashing) -> None:
		    attestation_1 = attester_slashing.attestation_1
		    attestation_2 = attester_slashing.attestation_2
		    assert is_slashable_attestation_data(attestation_1.data, attestation_2.data)
		    assert is_valid_indexed_attestation(state, attestation_1)
		    assert is_valid_indexed_attestation(state, attestation_2)

		    slashed_any = False
		    indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices)
		    for index in sorted(indices):
		        if is_slashable_validator(state.validators[index], get_current_epoch(state)):
		            slash_validator(state, index)
		            slashed_any = True
		    assert slashed_any
	*/
}

func isSlashableAttestationData() {
	/*
			ef is_slashable_attestation_data(data_1: AttestationData, data_2: AttestationData) -> bool:
		    """
		    Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG rules.
		    """
		    return (
		        # Double vote
		        (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
		        # Surround vote
		        (data_1.source.epoch < data_2.source.epoch and data_2.target.epoch < data_1.target.epoch)
		    )
	*/
}

func isValidIndexedAttestation() {
	/*
			def is_valid_indexed_attestation(state: BeaconState, indexed_attestation: IndexedAttestation) -> bool:
		    """
		    Check if ``indexed_attestation`` has valid indices and signature.
		    """
		    indices = indexed_attestation.attesting_indices

		    # Verify max number of indices
		    if not len(indices) <= MAX_VALIDATORS_PER_COMMITTEE:
		        return False
		    # Verify indices are sorted and unique
		    if not indices == sorted(set(indices)):
		        return False
		    # Verify aggregate signature
		    pubkeys = [state.validators[i].pubkey for i in indices]
		    domain = get_domain(state, DOMAIN_BEACON_ATTESTER, indexed_attestation.data.target.epoch)
		    signing_root = compute_signing_root(indexed_attestation.data, domain)
		    return bls.FastAggregateVerify(pubkeys, signing_root, indexed_attestation.signature)
	*/
}

func processAttestation() {
	/*
			def process_attestation(state: BeaconState, attestation: Attestation) -> None:
		    data = attestation.data
		    assert data.index < get_committee_count_at_slot(state, data.slot)
		    assert data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))
		    assert data.target.epoch == compute_epoch_at_slot(data.slot)
		    assert data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot <= data.slot + SLOTS_PER_EPOCH

		    committee = get_beacon_committee(state, data.slot, data.index)
		    assert len(attestation.aggregation_bits) == len(committee)

		    pending_attestation = PendingAttestation(
		        data=data,
		        aggregation_bits=attestation.aggregation_bits,
		        inclusion_delay=state.slot - data.slot,
		        proposer_index=get_beacon_proposer_index(state),
		    )

		    if data.target.epoch == get_current_epoch(state):
		        assert data.source == state.current_justified_checkpoint
		        state.current_epoch_attestations.append(pending_attestation)
		    else:
		        assert data.source == state.previous_justified_checkpoint
		        state.previous_epoch_attestations.append(pending_attestation)

		    # Verify signature
		    assert is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))
	*/
}

func processDeposit() {
	/*
			def process_deposit(state: BeaconState, deposit: Deposit) -> None:
		    # Verify the Merkle branch
		    assert is_valid_merkle_branch(
		        leaf=hash_tree_root(deposit.data),
		        branch=deposit.proof,
		        depth=DEPOSIT_CONTRACT_TREE_DEPTH + 1,  # Add 1 for the List length mix-in
		        index=state.eth1_deposit_index,
		        root=state.eth1_data.deposit_root,
		    )

		    # Deposits must be processed in order
		    state.eth1_deposit_index += 1

		    pubkey = deposit.data.pubkey
		    amount = deposit.data.amount
		    validator_pubkeys = [v.pubkey for v in state.validators]
		    if pubkey not in validator_pubkeys:
		        # Verify the deposit signature (proof of possession) which is not checked by the deposit contract
		        deposit_message = DepositMessage(
		            pubkey=deposit.data.pubkey,
		            withdrawal_credentials=deposit.data.withdrawal_credentials,
		            amount=deposit.data.amount,
		        )
		        domain = compute_domain(DOMAIN_DEPOSIT)  # Fork-agnostic domain since deposits are valid across forks
		        signing_root = compute_signing_root(deposit_message, domain)
		        if not bls.Verify(pubkey, signing_root, deposit.data.signature):
		            return

		        # Add validator and balance entries
		        state.validators.append(Validator(
		            pubkey=pubkey,
		            withdrawal_credentials=deposit.data.withdrawal_credentials,
		            activation_eligibility_epoch=FAR_FUTURE_EPOCH,
		            activation_epoch=FAR_FUTURE_EPOCH,
		            exit_epoch=FAR_FUTURE_EPOCH,
		            withdrawable_epoch=FAR_FUTURE_EPOCH,
		            effective_balance=min(amount - amount % EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE),
		        ))
		        state.balances.append(amount)
		    else:
		        # Increase balance by deposit amount
		        index = ValidatorIndex(validator_pubkeys.index(pubkey))
		        increase_balance(state, index, amount)
	*/
}

func processVoluntaryExit() {
	/*
			def process_voluntary_exit(state: BeaconState, signed_voluntary_exit: SignedVoluntaryExit) -> None:
		    voluntary_exit = signed_voluntary_exit.message
		    validator = state.validators[voluntary_exit.validator_index]
		    # Verify the validator is active
		    assert is_active_validator(validator, get_current_epoch(state))
		    # Verify exit has not been initiated
		    assert validator.exit_epoch == FAR_FUTURE_EPOCH
		    # Exits must specify an epoch when they become valid; they are not valid before then
		    assert get_current_epoch(state) >= voluntary_exit.epoch
		    # Verify the validator has been active long enough
		    assert get_current_epoch(state) >= validator.activation_epoch + PERSISTENT_COMMITTEE_PERIOD
		    # Verify signature
		    domain = get_domain(state, DOMAIN_VOLUNTARY_EXIT, voluntary_exit.epoch)
		    signing_root = compute_signing_root(voluntary_exit, domain)
		    assert bls.Verify(validator.pubkey, signing_root, signed_voluntary_exit.signature)
		    # Initiate exit
		    initiate_validator_exit(state, voluntary_exit.validator_index)
	*/
}

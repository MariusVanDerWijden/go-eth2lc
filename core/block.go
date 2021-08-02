package core

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/MariusVanDerWijden/eth2-lc/config"
	"github.com/MariusVanDerWijden/eth2-lc/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/golang/go/src/sort"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/shared/bls"
)

func processBlock(state *types.BeaconState, block *types.BeaconBlock) error {
	if err := processBlockHeader(state, block); err != nil {
		return err
	}

	if err := processRanDAO(state, block.Body); err != nil {
		return err
	}
	processETH1Data(state, block.Body)
	return processOperations(state, block.Body)
}

func processBlockHeader(state *types.BeaconState, block *types.BeaconBlock) error {
	// Verify the slots
	if block.Slot != state.Slot {
		return fmt.Errorf("invalid slot: block %v, state %v", block.Slot, state.Slot)
	}
	// Verify matching parents
	if state := hashTreeRootHeader(state.LatestBlockHeader); block.ParentRoot != state {
		return fmt.Errorf("invalid parent root: block %v, state %v", block.ParentRoot, state)
	}
	// Cache current block as new latest block
	state.LatestBlockHeader = &types.BeaconBlockHeader{
		Slot:       block.Slot,
		ParentRoot: block.ParentRoot,
		StateRoot:  common.Hash{},
		BodyRoot:   hashTreeRootBody(block.Body),
	}
	proposer, _ := state.CurrentProposer()
	if proposer.Slashed {
		return errors.Errorf("proposer %v was slashed", proposer.PubKey)
	}
	return nil
}

func processRanDAO(state *types.BeaconState, body *types.BeaconBlockBody) error {
	epoch := state.Epoch()
	// Verify RANDAO reveal
	proposer, _ := state.CurrentProposer()
	signingRoot := computeSigningRoot(epoch, getDomain(state, config.DOMAIN_RANDAO))
	if ok, err := bls.VerifyMultipleSignatures([][]byte{body.RanDAOReveal.Marshal()}, [][32]byte{signingRoot}, []bls.PublicKey{proposer.PubKey}); err != nil {
		return err
	} else if !ok {
		return errors.New("verify Randao reveal failed")
	}
	// Mix in RANDAO reveal
	// TODO check which hash function they use here
	hash := func([]byte) [32]byte { return [32]byte{} }
	var mix [32]byte
	s := state.RANDAOMix(epoch)
	h := hash(body.RanDAOReveal.Marshal())
	for i := 0; i < len(mix); i++ {
		mix[i] = s[i] ^ h[i]
	}
	state.RanDAOMix[epoch%config.EPOCHS_PER_HISTORICAL_VECTOR] = mix
	return nil
}

func processETH1Data(state *types.BeaconState, body *types.BeaconBlockBody) {
	state.ETH1DataVotes = append(state.ETH1DataVotes, body.ETH1Data)
	// TODO check if this is actually length and why the docs says state.eth1_data_votes.count(body.eth1_data) * 2 > SLOTS_PER_ETH1_VOTING_PERIOD:
	if len(state.ETH1DataVotes)*2 > config.SLOTS_PER_ETH1_VOTING_PERIOD {
		state.ETH1Data = body.ETH1Data
	}
}

func processOperations(state *types.BeaconState, body *types.BeaconBlockBody) error {
	min := state.ETH1Data.DepositCount - state.ETH1DepositIndex
	if min > config.MAX_DEPOSITS {
		min = config.MAX_DEPOSITS
	}
	if len(body.Deposits) != int(min) {
		return errors.Errorf("invalid deposits processed: got %v want %v", len(body.Deposits), min)
	}
	operations := []func() error{
		func() error { return processProposerSlashings(state, body.ProposerSlashings) },
		func() error { return processAttesterSlashings(state, body.AttesterSlashings) },
		func() error { return processAttestations(body.Attestations) },
		func() error { return processDeposits(body.Deposits) },
		func() error { return processVoluntaryExits(body.VoluntaryExits) },
	}
	for _, ops := range operations {
		if err := ops(); err != nil {
			return err
		}
	}
	return nil
}

func processProposerSlashings(state *types.BeaconState, slashings []types.ProposerSlashing) error {
	for _, slashing := range slashings {
		if slashing.SignedHeader1.Message.Slot != slashing.SignedHeader2.Message.Slot {
			return fmt.Errorf("invalid slashing slots: msg1 %v, msg2 %v", slashing.SignedHeader1.Message.Slot, slashing.SignedHeader2.Message.Slot)
		}
		if slashing.SignedHeader1 == slashing.SignedHeader2 {
			return errors.New("invalid slashing: signed headers are equal")
		}
		proposer := state.Validators[slashing.ProposerIndex]
		if !isSlashableValidator(proposer, state.Epoch()) {
			return errors.New("invalid slashing: proposer not slashable")
		}
		// Verify signatures
		verfiySigs := func(header *types.SignedBeaconBlockHeader) error {
			domain := getDomain(state, config.DOMAIN_BEACON_PROPOSER)
			signingRoot := computeSigningRootBlock(header.Message, domain)
			if ok, err := bls.VerifyMultipleSignatures([][]byte{header.Signature.Marshal()}, [][32]byte{signingRoot}, []bls.PublicKey{proposer.PubKey}); err != nil {
				return err
			} else if !ok {
				return errors.New("verify Randao reveal failed")
			}
			return nil
		}
		if err := verfiySigs(slashing.SignedHeader1); err != nil {
			return err
		}
		if err := verfiySigs(slashing.SignedHeader2); err != nil {
			return err
		}
		return SlashValidator(state, slashing.ProposerIndex, -1)
	}
	return nil
}

func isSlashableValidator(val *types.Validator, epoch types.Epoch) bool {
	return !val.Slashed && (val.ActivationEpoch <= epoch && epoch < val.WithdrawalEpoch)
}

func SlashValidator(state *types.BeaconState, index, whistleblower int) error {
	epoch := state.Epoch()
	if err := initiateValidatorExit(state, index); err != nil {
		return err
	}
	validator := state.Validators[index]
	validator.Slashed = true
	max := epoch + config.EPOCHS_PER_SLASHINGS_VECTOR
	if validator.WithdrawalEpoch > max {
		max = validator.WithdrawalEpoch
	}
	validator.WithdrawalEpoch = max
	slashings := new(big.Int).Add(state.Slashings[epoch%config.EPOCHS_PER_SLASHINGS_VECTOR], validator.EffectiveBalance)
	state.Slashings[epoch%config.EPOCHS_PER_SLASHINGS_VECTOR] = slashings
	state.DecreaseBalance(index, new(big.Int).Div(validator.EffectiveBalance, big.NewInt(config.MIN_SLASHING_PENALTY_QUOTIENT)))
	// Apply proposer and whistleblower rewards
	_, proposerIndex := state.CurrentProposer()
	if whistleblower < 0 {
		whistleblower = proposerIndex
	}
	whistleblowerReward := new(big.Int).Div(validator.EffectiveBalance, big.NewInt(config.WHISTLEBLOWER_REWARD_QUOTIENT))
	proposerReward := new(big.Int).Div(whistleblowerReward, big.NewInt(config.PROPOSER_REWARD_QUOTIENT))
	state.IncreaseBalance(proposerIndex, proposerReward)
	state.IncreaseBalance(whistleblower, new(big.Int).Sub(whistleblowerReward, proposerReward))
	return nil
}

func processAttesterSlashings(state *types.BeaconState, slashings []types.AttesterSlashing) error {
	for _, slashing := range slashings {
		att1 := slashing.Attestation1
		att2 := slashing.Attestation2
		if !isSlashableAttestationData(att1.Data, att2.Data) {
			return errors.New("no slashable attestation")
		}
		if !isValidIndexedAttestation(state, att1) {
			return errors.New("first attestation is not valid")
		}
		if !isValidIndexedAttestation(state, att2) {
			return errors.New("second attestation is not valid")
		}
		slashedAny := false
		indices := SetIntersection(att1.AttestingIndices, att2.AttestingIndices)
		sort.Sort(indices)
		for _, index := range indices {
			if isSlashableValidator(state.Validators[index], state.Epoch()) {
				if err := SlashValidator(state, index, -1); err != nil {
					return err
				}
				slashedAny = true
			}
		}
		if !slashedAny {
			return errors.New("no validators slashed in slashing")
		}
	}
	return nil
}

func isSlashableAttestationData(att1, att2 *types.AttestationData) bool {
	doubleVote := (att1 != att2 && att1.Target.Epoch == att2.Target.Epoch)
	surroundVote := (att1.Source.Epoch < att2.Source.Epoch && att2.Target.Epoch < att1.Target.Epoch)
	return doubleVote || surroundVote
}

func isValidIndexedAttestation(state *types.BeaconState, att *types.IndexedAttestation) bool {
	indices := att.AttestingIndices
	// Verify max number of indices
	if len(indices) > config.MAX_VALIDATORS_PER_COMMITTEE {
		return false
	}
	// Verify indices are sorted and unique
	sorted := indices
	sort.Sort(sorted)
	for i := range indices {
		if indices[i] != sorted[i] {
			return false
		}
	}

	// Verify aggregate signature

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
	return false
}

func processAttestations([]types.Attestation) error {
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
	return nil
}

func processDeposits([]types.Deposit) error {
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
	return nil
}

func processVoluntaryExits([]types.VoluntaryExit) error {
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
	return nil
}

func getDomain(state *types.BeaconState, domain int) types.Domain {
	// TODO impl
	return types.Domain(domain)
}

func getDomainAtEpoch(state *types.BeaconState, domain int, epoch types.Epoch) types.Domain {
	// TODO impl
	return types.Domain(domain)
}

func computeSigningRoot(epoch types.Epoch, domain types.Domain) common.Hash {
	// TODO impl
	return common.Hash{}
}

func computeSigningRootBlock(block types.BeaconBlock, domain types.Domain) common.Hash {
	// TODO impl
	return common.Hash{}
}

func initiateValidatorExit(state *types.BeaconState, index int) error {
	// TODO impl
	return nil
}

func SetIntersection(a, b []int) []int {
	// TODO impl
	return []int{}
}

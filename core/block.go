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
		func() error { return processAttestations(state, body.Attestations) },
		func() error { return processDeposits(state, body.Deposits) },
		func() error { return processVoluntaryExits(state, body.VoluntaryExits) },
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

func SlashValidator(state *types.BeaconState, index uint64, whistleblower int) error {
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
		whistleblower = int(proposerIndex)
	}
	whistleblowerReward := new(big.Int).Div(validator.EffectiveBalance, big.NewInt(config.WHISTLEBLOWER_REWARD_QUOTIENT))
	proposerReward := new(big.Int).Div(whistleblowerReward, big.NewInt(config.PROPOSER_REWARD_QUOTIENT))
	state.IncreaseBalance(proposerIndex, proposerReward)
	state.IncreaseBalance(uint64(whistleblower), new(big.Int).Sub(whistleblowerReward, proposerReward))
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
				if err := SlashValidator(state, uint64(index), -1); err != nil {
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
	pubKeys := make([]types.BLSPubKey, 0, len(indices))
	for _, i := range indices {
		pubKeys = append(pubKeys, state.Validators[i].PubKey)
	}
	domain := getDomainAtEpoch(state, config.DOMAIN_BEACON_ATTESTER, att.Data.Target.Epoch)
	signingRoot := computeSigningRootAttestationData(att.Data, domain)
	_ = signingRoot
	return true
	// TODO verify aggregates signature
	// return bls.FastAggregateVerify(pubkeys, signing_root, indexed_attestation.signature)
}

func processAttestations(state *types.BeaconState, atts []types.Attestation) error {
	for _, att := range atts {
		data := att.Data
		if size := getCommitteCountAtSlot(state, data.Slot); data.Index >= size {
			return fmt.Errorf("invalid attestation index: %v size %v", data.Index, size)
		}
		if data.Target.Epoch != state.PrevEpoch() && data.Target.Epoch != state.Epoch() {
			return fmt.Errorf("invalid epoch in attestation: %v want %v or %v", data.Target.Epoch, state.PrevEpoch(), state.Epoch())
		}
		if epoch := computeEpochAtSlot(data.Slot); data.Target.Epoch != epoch {
			return fmt.Errorf("invalid epoch in attestation: %v want %v", data.Target.Epoch, epoch)
		}
		if data.Slot+config.MIN_ATTESTATION_INCLUSION_DELAY > state.Slot {
			return fmt.Errorf("invalid slot in attestation: %v state %v ", data.Slot, state.Slot)
		}
		if state.Slot > data.Slot+config.SLOTS_PER_EPOCH {
			return fmt.Errorf("invalid slot in attestation: state %v data %v", state.Slot, data.Slot+config.SLOTS_PER_EPOCH)
		}

		comittee := getBeaconComittee(state, data.Slot, data.Index)
		if len(att.AggregationBits) != len(comittee) {
			return fmt.Errorf("invalid aggr-bits size in attestation: %v comittee %v", len(att.AggregationBits), len(comittee))
		}

		_, proposerIndex := state.CurrentProposer()
		pendingAttestation := types.PendingAttestation{
			Data:            data,
			AggregationBits: att.AggregationBits,
			InclusionDelay:  state.Slot - data.Slot,
			ProposerIndex:   proposerIndex,
		}

		if data.Target.Epoch == state.Epoch() {
			if data.Source != state.CurrentJustifiedCheckpoint {
				return fmt.Errorf("invalid source in attestation: %v want %v", data.Source, state.CurrentJustifiedCheckpoint)
			}
			state.CurrentEpochAttestations = append(state.CurrentEpochAttestations, pendingAttestation)
		} else {
			if data.Source != state.PreviousJustifiedCheckpoint {
				return fmt.Errorf("invalid source in attestation: %v want %v", data.Source, state.PreviousJustifiedCheckpoint)
			}
			state.PreviousEpochAttestations = append(state.PreviousEpochAttestations, pendingAttestation)
		}
		// verify signature
		if !isValidIndexedAttestation(state, state.IndexedAttestation(att)) {
			return fmt.Errorf("invalid indexed attestation")
		}
	}
	return nil
}

func processDeposits(state *types.BeaconState, deposits []types.Deposit) error {
	for _, deposit := range deposits {
		// Verify the merkle branch
		if !isValidMerkleBranch(hashTreeRoot(deposit.Data), deposit.Proof, config.DEPOSIT_CONTRACT_TREE_DEPTH+1, state.ETH1DepositIndex, state.ETH1Data.DepositRoot) {
			return errors.New("invalid merkle tree for deposit")
		}
		// Process deposits in order
		state.ETH1DepositIndex += 1

		pubkey := deposit.Data.Pubkey
		amount := deposit.Data.Amount
		pks := state.ValidatorPubkeys()

		if index, ok := pks[pubkey]; !ok {
			// New validator
			// Verify the deposit signature (proof of possession)
			depositMessage := types.DepositMessage{
				Pubkey:                deposit.Data.Pubkey,
				WithdrawalCredentials: deposit.Data.WithdrawalCredentials,
				Amount:                deposit.Data.Amount,
			}
			domain := computeDomain(config.DOMAIN_DEPOSIT)
			signingRoot := computeSigningRootDepositMessage(depositMessage, domain)
			if !Verify(pubkey, signingRoot, deposit.Data.Signature) {
				// TODO check if a wrongly signed deposit is just ignored as done here
				break
			}

			effectiveBalance := new(big.Int).Sub(amount, new(big.Int).Mod(amount, big.NewInt(config.EFFECTIVE_BALANCE_INCREMENT)))
			if effectiveBalance.Cmp(big.NewInt(config.MAX_EFFECTIVE_BALANCE)) > 0 {
				effectiveBalance = big.NewInt(config.MAX_EFFECTIVE_BALANCE)
			}

			val := types.Validator{
				PubKey:                     pubkey,
				WithdrawalCredentials:      deposit.Data.WithdrawalCredentials,
				ActivationEligibilityEpoch: config.FAR_FUTURE_EPOCH,
				ActivationEpoch:            config.FAR_FUTURE_EPOCH,
				ExitEpoch:                  config.FAR_FUTURE_EPOCH,
				WithdrawalEpoch:            config.FAR_FUTURE_EPOCH,
				EffectiveBalance:           effectiveBalance,
			}
			state.AddValidator(&val, amount)
		} else {
			// Increase balance by deposit amount
			state.IncreaseBalance(index, amount)
		}
	}
	return nil
}

func processVoluntaryExits(state *types.BeaconState, exits []types.SignedVoluntaryExit) error {
	for _, exit := range exits {
		voluntaryExit := exit.Message
		validator := state.Validators[voluntaryExit.ValidatorIndex]

		if !validator.IsActive(state.Epoch()) {
			return errors.New("invalid voluntary exit, already exited")
		}
		if validator.ExitEpoch != config.FAR_FUTURE_EPOCH {
			return errors.New("invalid voluntary exit, already initiated")
		}
		if voluntaryExit.Epoch < state.Epoch() {
			return fmt.Errorf("volExit not valid before epoch %v is %v", state.Epoch(), voluntaryExit.Epoch)
		}
		if validator.ActivationEpoch+config.PERSISTENT_COMMITTEE_PERIOD < state.Epoch() {
			return fmt.Errorf("volExit, validator not active for long: needs %v", validator.ActivationEpoch+config.PERSISTENT_COMMITTEE_PERIOD)
		}
		domain := getDomainAtEpoch(state, config.DOMAIN_VOLUNTARY_EXIT, state.Epoch())
		signingRoot := computeSigningRootVoluntaryExit(voluntaryExit, domain)
		if !Verify(validator.PubKey, signingRoot, exit.Signature) {
			return errors.New("invalid signature on voluntary exit")
		}
		if err := initiateValidatorExit(state, voluntaryExit.ValidatorIndex); err != nil {
			return err
		}
	}
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

func computeDomain(domain int) types.Domain {
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

func computeSigningRootAttestationData(attData *types.AttestationData, domain types.Domain) common.Hash {
	// TODO impl
	return common.Hash{}
}

func computeSigningRootDepositMessage(msg types.DepositMessage, domain types.Domain) common.Hash {
	// TODO impl
	return common.Hash{}
}

func computeSigningRootVoluntaryExit(exit types.VoluntaryExit, domain types.Domain) common.Hash {
	// TODO impl
	return common.Hash{}
}

func initiateValidatorExit(state *types.BeaconState, index uint64) error {
	// TODO impl
	return nil
}

func SetIntersection(a, b []int) []int {
	// TODO impl
	return []int{}
}

func getCommitteCountAtSlot(state *types.BeaconState, slot types.Slot) uint64 {
	// TODO impl
	return 0
}

func computeEpochAtSlot(slot types.Slot) types.Epoch {
	// TODO impl
	return 0
}

func isValidMerkleBranch(leaf common.Hash, proof []common.Hash, depth int, index uint64, root common.Hash) bool {
	// TODO impl
	return false
}

func Verify(pk types.BLSPubKey, msg common.Hash, sig types.BLSSignature) bool {
	// TODO impl
	return false
}

func getBeaconComittee(state *types.BeaconState, slot types.Slot, index uint64) []uint64 {
	return []uint64{}
}

package core

import (
	"errors"
	"math"

	"github.com/MariusVanDerWijden/eth2-lc/config"
	"github.com/MariusVanDerWijden/eth2-lc/types"
	"github.com/google/go-cmp/cmp"
)

const (
	FINALIZED_ROOT_INDEX            = 1234
	NEXT_SYNC_COMMITTEE_INDEX       = 1234
	MIN_SYNC_COMMITTEE_PARTICIPANTS = 1234
)

func getSubtreeIndex(index uint64) uint64 {
	return uint64(index % uint64(math.Pow(2., math.Log2(float64(index)))))
}

func validateLightClientUpdate(snapshot types.LightClientSnapshot, update types.LightClientUpdate, genesisValidatorRoot types.Hash) error {
	if update.Header.Slot <= snapshot.Header.Slot {
		return errors.New("update slot leq snapshot slot")
	}

	snapshotPeriod := epochAtSlot(snapshot.Header.Slot)
	updatePeriod := epochAtSlot(update.Header.Slot)

	if updatePeriod != snapshotPeriod && updatePeriod != snapshotPeriod+1 {
		return errors.New("invalid update period")
	}

	var signedHeader types.BeaconBlockHeader
	if cmp.Equal(update.FinalityHeader, types.BeaconBlockHeader{}) {
		signedHeader = update.Header
		for i := 0; i < int(math.Log2(FINALIZED_ROOT_INDEX)); i++ {
			if update.FinalityBranch[i] != [32]byte{} {
				return errors.New("invalid finality branch")
			}
		}
	} else {
		signedHeader = update.FinalityHeader
		if !isValidMerkleBranch(
			hashTreeRoot(update.Header),
			update.FinalityBranch,
			int(math.Log2(FINALIZED_ROOT_INDEX)),
			getSubtreeIndex(FINALIZED_ROOT_INDEX),
			update.Header.StateRoot,
		) {
			return errors.New("invalid merkle branch")
		}
	}
	// Verify update next sync committee
	var syncCommittee types.SyncCommittee
	if updatePeriod == snapshotPeriod {
		syncCommittee = snapshot.CurrentSyncCommittee
		for i := 0; i < int(math.Log2(NEXT_SYNC_COMMITTEE_INDEX)); i++ {
			if update.NextSyncCommitteeBranch[i] != [32]byte{} {
				return errors.New("invalid next sync committee")
			}
		}
	} else {
		syncCommittee = snapshot.NextSyncCommittee
		if !isValidMerkleBranch(
			hashTreeRoot(update.NextSyncCommittee),
			update.NextSyncCommitteeBranch,
			int(math.Log2(NEXT_SYNC_COMMITTEE_INDEX)),
			getSubtreeIndex(NEXT_SYNC_COMMITTEE_INDEX),
			update.Header.StateRoot,
		) {
			return errors.New("invalid merkle branch")
		}
	}

	if update.SyncCommitteeBits.Count() < MIN_SYNC_COMMITTEE_PARTICIPANTS {
		return errors.New("invalid sync committee bits")
	}

	// verify sync committee aggregate signature
	var participantPubkeys []types.BLSPubKey
	for _, bit := range update.SyncCommitteeBits.BitIndices() {
		participantPubkeys = append(participantPubkeys, syncCommittee.PubKeys[bit])
	}
	domain := computeDomainFull(config.DOMAIN_SYNC_COMMITTEE, update.ForkVersion, genesisValidatorRoot)
	signingRoot := computeSigningRoot(signedHeader, domain)
	if VerifyMultiple(participantPubkeys, signingRoot, update.SyncCommitteeSignature) {
		return errors.New("bls signature verification failed")
	}
	return nil
}

func applyLightClientUpdate(snapshot types.LightClientSnapshot, update types.LightClientUpdate) {
	snapshotPeriod := epochAtSlot(snapshot.Header.Slot)
	updatePeriod := epochAtSlot(update.Header.Slot)
	if updatePeriod == snapshotPeriod+1 {
		snapshot.CurrentSyncCommittee = snapshot.NextSyncCommittee
		snapshot.NextSyncCommittee = update.NextSyncCommittee
	}
	snapshot.Header = update.Header
}

func processLightClientUpdate(store types.LightClientStore, update types.LightClientUpdate, currentSlot types.Slot, genesisValidatorsRoot types.Hash) error {
	if err := validateLightClientUpdate(store.Snapshot, update, genesisValidatorsRoot); err != nil {
		return err
	}
	store.ValidUpdates = append(store.ValidUpdates, update)
	updateTimeout := config.SLOTS_PER_EPOCH * config.EPOCHS_PER_HISTORICAL_VECTOR

	if update.SyncCommitteeBits.Count()*3 >= update.SyncCommitteeBits.Len()*2 &&
		cmp.Equal(update.FinalityHeader, types.BeaconBlockHeader{}) {
		// Apply update if (1) 2/3 quorum is reached and (2) we have a finality proof.
		applyLightClientUpdate(store.Snapshot, update)
		store.ValidUpdates = make([]types.LightClientUpdate, 0)
	} else if currentSlot > store.Snapshot.Header.Slot+types.Slot(updateTimeout) {
		// forced update if timeout has elapsed
		mostSignedUpdate := update
		for _, up := range store.ValidUpdates {
			if up.SyncCommitteeBits.Count() > mostSignedUpdate.SyncCommitteeBits.Count() {
				mostSignedUpdate = up
			}
		}
		applyLightClientUpdate(store.Snapshot, mostSignedUpdate)
		store.ValidUpdates = make([]types.LightClientUpdate, 0)
	}
	return nil
}

func epochAtSlot(slot types.Slot) types.Epoch {
	return types.Epoch(slot / config.SLOTS_PER_EPOCH)
}

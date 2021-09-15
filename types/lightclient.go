package types

import "github.com/prysmaticlabs/go-bitfield"

type LightClientSnapshot struct {
	Header               BeaconBlockHeader
	CurrentSyncCommittee SyncCommittee
	NextSyncCommittee    SyncCommittee
}

type LightClientUpdate struct {
	Header BeaconBlockHeader
	// Next sync committee
	NextSyncCommittee       SyncCommittee
	NextSyncCommitteeBranch [][32]byte
	// Finality proof
	FinalityHeader BeaconBlockHeader
	FinalityBranch [][32]byte
	// sync committee aggregate signature
	SyncCommitteeBits      bitfield.Bitvector512
	SyncCommitteeSignature BLSSignature
	// Fork version
	ForkVersion uint64
}

type LightClientStore struct {
	Snapshot     LightClientSnapshot
	ValidUpdates []LightClientUpdate
}

type SyncCommittee struct {
	PubKeys           []BLSPubKey
	AggregatedPubKeys BLSPubKey
}

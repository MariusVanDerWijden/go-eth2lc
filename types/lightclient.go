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
	NextSyncCommitteeBranch []Hash
	// Finality proof
	FinalityHeader BeaconBlockHeader
	FinalityBranch []Hash
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

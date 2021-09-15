package full

import (
	"github.com/MariusVanDerWijden/eth2-lc/core"
	"github.com/MariusVanDerWijden/eth2-lc/types"
)

func main() {
	b := types.SignedBeaconBlock{}
	state := types.BeaconState{}
	res, err := core.StateTransition(&state, b, false)
	_ = res
	_ = err
}

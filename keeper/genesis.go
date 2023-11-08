package keeper

import (
	"context"

	"github.com/sonrhq/identity"
)

// InitGenesis initializes the module state from a genesis state.
func (k *Keeper) InitGenesis(ctx context.Context, data *identity.GenesisState) error {
	if err := k.Params.Set(ctx, data.Params); err != nil {
		return err
	}

	for _, counter := range data.Counters {
		if err := k.Counter.Set(ctx, counter.Address, counter.Count); err != nil {
			return err
		}
	}

	return nil
}

// ExportGenesis exports the module state to a genesis state.
func (k *Keeper) ExportGenesis(ctx context.Context) (*identity.GenesisState, error) {
	params, err := k.Params.Get(ctx)
	if err != nil {
		return nil, err
	}

	var counters []identity.Counter
	if err := k.Counter.Walk(ctx, nil, func(address string, count uint64) (bool, error) {
		counters = append(counters, identity.Counter{
			Address: address,
			Count:   count,
		})

		return false, nil
	}); err != nil {
		return nil, err
	}

	return &identity.GenesisState{
		Params:   params,
		Counters: counters,
	}, nil
}

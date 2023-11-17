package keeper

import (
	"fmt"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	storetypes "cosmossdk.io/core/store"
	"cosmossdk.io/orm/model/ormdb"
	"github.com/cosmos/cosmos-sdk/codec"

	"github.com/sonrhq/identity"
	modulev1 "github.com/sonrhq/identity/api/module/v1"
)

type Keeper struct {
	cdc          codec.BinaryCodec
	addressCodec address.Codec
	db           modulev1.ModuleStore

	// authority is the address capable of executing a MsgUpdateParams and other authority-gated message.
	// typically, this should be the x/gov module account.
	authority string

	// state management
	Schema  collections.Schema
	Params  collections.Item[identity.Params]
	Counter collections.Map[string, uint64]
}

// NewKeeper creates a new Keeper instance
func NewKeeper(cdc codec.BinaryCodec, addressCodec address.Codec, storeService storetypes.KVStoreService, authority string) Keeper {
	if _, err := addressCodec.StringToBytes(authority); err != nil {
		panic(fmt.Errorf("invalid authority address: %w", err))
	}
	db, err := ormdb.NewModuleDB(identitySchema, ormdb.ModuleDBOptions{KVStoreService: storeService})
	if err != nil {
		panic(err)
	}

	store, err := modulev1.NewModuleStore(db)
	if err != nil {
		panic(err)
	}

	sb := collections.NewSchemaBuilder(storeService)
	k := Keeper{
		cdc:          cdc,
		addressCodec: addressCodec,
		authority:    authority,
		Params:       collections.NewItem(sb, identity.ParamsKey, "params", codec.CollValue[identity.Params](cdc)),
		Counter:      collections.NewMap(sb, identity.CounterKey, "counter", collections.StringKey, collections.Uint64Value),
		db:           store,
	}

	schema, err := sb.Build()
	if err != nil {
		panic(err)
	}

	k.Schema = schema

	return k
}

// GetAuthority returns the module's authority.
func (k Keeper) GetAuthority() string {
	return k.authority
}

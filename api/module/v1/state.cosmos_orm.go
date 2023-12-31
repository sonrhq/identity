// Code generated by protoc-gen-go-cosmos-orm. DO NOT EDIT.

package modulev1

import (
	context "context"
	ormlist "cosmossdk.io/orm/model/ormlist"
	ormtable "cosmossdk.io/orm/model/ormtable"
	ormerrors "cosmossdk.io/orm/types/ormerrors"
)

type AccountTable interface {
	Insert(ctx context.Context, account *Account) error
	InsertReturningIndex(ctx context.Context, account *Account) (uint64, error)
	LastInsertedSequence(ctx context.Context) (uint64, error)
	Update(ctx context.Context, account *Account) error
	Save(ctx context.Context, account *Account) error
	Delete(ctx context.Context, account *Account) error
	Has(ctx context.Context, index uint64) (found bool, err error)
	// Get returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	Get(ctx context.Context, index uint64) (*Account, error)
	HasByAddress(ctx context.Context, address string) (found bool, err error)
	// GetByAddress returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	GetByAddress(ctx context.Context, address string) (*Account, error)
	HasByPublicKey(ctx context.Context, public_key []byte) (found bool, err error)
	// GetByPublicKey returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	GetByPublicKey(ctx context.Context, public_key []byte) (*Account, error)
	List(ctx context.Context, prefixKey AccountIndexKey, opts ...ormlist.Option) (AccountIterator, error)
	ListRange(ctx context.Context, from, to AccountIndexKey, opts ...ormlist.Option) (AccountIterator, error)
	DeleteBy(ctx context.Context, prefixKey AccountIndexKey) error
	DeleteRange(ctx context.Context, from, to AccountIndexKey) error

	doNotImplement()
}

type AccountIterator struct {
	ormtable.Iterator
}

func (i AccountIterator) Value() (*Account, error) {
	var account Account
	err := i.UnmarshalMessage(&account)
	return &account, err
}

type AccountIndexKey interface {
	id() uint32
	values() []interface{}
	accountIndexKey()
}

// primary key starting index..
type AccountPrimaryKey = AccountIndexIndexKey

type AccountIndexIndexKey struct {
	vs []interface{}
}

func (x AccountIndexIndexKey) id() uint32            { return 0 }
func (x AccountIndexIndexKey) values() []interface{} { return x.vs }
func (x AccountIndexIndexKey) accountIndexKey()      {}

func (this AccountIndexIndexKey) WithIndex(index uint64) AccountIndexIndexKey {
	this.vs = []interface{}{index}
	return this
}

type AccountAddressIndexKey struct {
	vs []interface{}
}

func (x AccountAddressIndexKey) id() uint32            { return 1 }
func (x AccountAddressIndexKey) values() []interface{} { return x.vs }
func (x AccountAddressIndexKey) accountIndexKey()      {}

func (this AccountAddressIndexKey) WithAddress(address string) AccountAddressIndexKey {
	this.vs = []interface{}{address}
	return this
}

type AccountPublicKeyIndexKey struct {
	vs []interface{}
}

func (x AccountPublicKeyIndexKey) id() uint32            { return 2 }
func (x AccountPublicKeyIndexKey) values() []interface{} { return x.vs }
func (x AccountPublicKeyIndexKey) accountIndexKey()      {}

func (this AccountPublicKeyIndexKey) WithPublicKey(public_key []byte) AccountPublicKeyIndexKey {
	this.vs = []interface{}{public_key}
	return this
}

type accountTable struct {
	table ormtable.AutoIncrementTable
}

func (this accountTable) Insert(ctx context.Context, account *Account) error {
	return this.table.Insert(ctx, account)
}

func (this accountTable) Update(ctx context.Context, account *Account) error {
	return this.table.Update(ctx, account)
}

func (this accountTable) Save(ctx context.Context, account *Account) error {
	return this.table.Save(ctx, account)
}

func (this accountTable) Delete(ctx context.Context, account *Account) error {
	return this.table.Delete(ctx, account)
}

func (this accountTable) InsertReturningIndex(ctx context.Context, account *Account) (uint64, error) {
	return this.table.InsertReturningPKey(ctx, account)
}

func (this accountTable) LastInsertedSequence(ctx context.Context) (uint64, error) {
	return this.table.LastInsertedSequence(ctx)
}

func (this accountTable) Has(ctx context.Context, index uint64) (found bool, err error) {
	return this.table.PrimaryKey().Has(ctx, index)
}

func (this accountTable) Get(ctx context.Context, index uint64) (*Account, error) {
	var account Account
	found, err := this.table.PrimaryKey().Get(ctx, &account, index)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &account, nil
}

func (this accountTable) HasByAddress(ctx context.Context, address string) (found bool, err error) {
	return this.table.GetIndexByID(1).(ormtable.UniqueIndex).Has(ctx,
		address,
	)
}

func (this accountTable) GetByAddress(ctx context.Context, address string) (*Account, error) {
	var account Account
	found, err := this.table.GetIndexByID(1).(ormtable.UniqueIndex).Get(ctx, &account,
		address,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &account, nil
}

func (this accountTable) HasByPublicKey(ctx context.Context, public_key []byte) (found bool, err error) {
	return this.table.GetIndexByID(2).(ormtable.UniqueIndex).Has(ctx,
		public_key,
	)
}

func (this accountTable) GetByPublicKey(ctx context.Context, public_key []byte) (*Account, error) {
	var account Account
	found, err := this.table.GetIndexByID(2).(ormtable.UniqueIndex).Get(ctx, &account,
		public_key,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &account, nil
}

func (this accountTable) List(ctx context.Context, prefixKey AccountIndexKey, opts ...ormlist.Option) (AccountIterator, error) {
	it, err := this.table.GetIndexByID(prefixKey.id()).List(ctx, prefixKey.values(), opts...)
	return AccountIterator{it}, err
}

func (this accountTable) ListRange(ctx context.Context, from, to AccountIndexKey, opts ...ormlist.Option) (AccountIterator, error) {
	it, err := this.table.GetIndexByID(from.id()).ListRange(ctx, from.values(), to.values(), opts...)
	return AccountIterator{it}, err
}

func (this accountTable) DeleteBy(ctx context.Context, prefixKey AccountIndexKey) error {
	return this.table.GetIndexByID(prefixKey.id()).DeleteBy(ctx, prefixKey.values()...)
}

func (this accountTable) DeleteRange(ctx context.Context, from, to AccountIndexKey) error {
	return this.table.GetIndexByID(from.id()).DeleteRange(ctx, from.values(), to.values())
}

func (this accountTable) doNotImplement() {}

var _ AccountTable = accountTable{}

func NewAccountTable(db ormtable.Schema) (AccountTable, error) {
	table := db.GetTable(&Account{})
	if table == nil {
		return nil, ormerrors.TableNotFound.Wrap(string((&Account{}).ProtoReflect().Descriptor().FullName()))
	}
	return accountTable{table.(ormtable.AutoIncrementTable)}, nil
}

type CredentialTable interface {
	Insert(ctx context.Context, credential *Credential) error
	InsertReturningId(ctx context.Context, credential *Credential) (uint64, error)
	LastInsertedSequence(ctx context.Context) (uint64, error)
	Update(ctx context.Context, credential *Credential) error
	Save(ctx context.Context, credential *Credential) error
	Delete(ctx context.Context, credential *Credential) error
	Has(ctx context.Context, id uint64) (found bool, err error)
	// Get returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	Get(ctx context.Context, id uint64) (*Credential, error)
	HasByOriginHandle(ctx context.Context, origin string, handle string) (found bool, err error)
	// GetByOriginHandle returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	GetByOriginHandle(ctx context.Context, origin string, handle string) (*Credential, error)
	HasByCredentialId(ctx context.Context, credential_id []byte) (found bool, err error)
	// GetByCredentialId returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	GetByCredentialId(ctx context.Context, credential_id []byte) (*Credential, error)
	HasByPublicKey(ctx context.Context, public_key []byte) (found bool, err error)
	// GetByPublicKey returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	GetByPublicKey(ctx context.Context, public_key []byte) (*Credential, error)
	List(ctx context.Context, prefixKey CredentialIndexKey, opts ...ormlist.Option) (CredentialIterator, error)
	ListRange(ctx context.Context, from, to CredentialIndexKey, opts ...ormlist.Option) (CredentialIterator, error)
	DeleteBy(ctx context.Context, prefixKey CredentialIndexKey) error
	DeleteRange(ctx context.Context, from, to CredentialIndexKey) error

	doNotImplement()
}

type CredentialIterator struct {
	ormtable.Iterator
}

func (i CredentialIterator) Value() (*Credential, error) {
	var credential Credential
	err := i.UnmarshalMessage(&credential)
	return &credential, err
}

type CredentialIndexKey interface {
	id() uint32
	values() []interface{}
	credentialIndexKey()
}

// primary key starting index..
type CredentialPrimaryKey = CredentialIdIndexKey

type CredentialIdIndexKey struct {
	vs []interface{}
}

func (x CredentialIdIndexKey) id() uint32            { return 0 }
func (x CredentialIdIndexKey) values() []interface{} { return x.vs }
func (x CredentialIdIndexKey) credentialIndexKey()   {}

func (this CredentialIdIndexKey) WithId(id uint64) CredentialIdIndexKey {
	this.vs = []interface{}{id}
	return this
}

type CredentialHandleIndexKey struct {
	vs []interface{}
}

func (x CredentialHandleIndexKey) id() uint32            { return 1 }
func (x CredentialHandleIndexKey) values() []interface{} { return x.vs }
func (x CredentialHandleIndexKey) credentialIndexKey()   {}

func (this CredentialHandleIndexKey) WithHandle(handle string) CredentialHandleIndexKey {
	this.vs = []interface{}{handle}
	return this
}

type CredentialOriginHandleIndexKey struct {
	vs []interface{}
}

func (x CredentialOriginHandleIndexKey) id() uint32            { return 2 }
func (x CredentialOriginHandleIndexKey) values() []interface{} { return x.vs }
func (x CredentialOriginHandleIndexKey) credentialIndexKey()   {}

func (this CredentialOriginHandleIndexKey) WithOrigin(origin string) CredentialOriginHandleIndexKey {
	this.vs = []interface{}{origin}
	return this
}

func (this CredentialOriginHandleIndexKey) WithOriginHandle(origin string, handle string) CredentialOriginHandleIndexKey {
	this.vs = []interface{}{origin, handle}
	return this
}

type CredentialCredentialIdIndexKey struct {
	vs []interface{}
}

func (x CredentialCredentialIdIndexKey) id() uint32            { return 3 }
func (x CredentialCredentialIdIndexKey) values() []interface{} { return x.vs }
func (x CredentialCredentialIdIndexKey) credentialIndexKey()   {}

func (this CredentialCredentialIdIndexKey) WithCredentialId(credential_id []byte) CredentialCredentialIdIndexKey {
	this.vs = []interface{}{credential_id}
	return this
}

type CredentialPublicKeyIndexKey struct {
	vs []interface{}
}

func (x CredentialPublicKeyIndexKey) id() uint32            { return 4 }
func (x CredentialPublicKeyIndexKey) values() []interface{} { return x.vs }
func (x CredentialPublicKeyIndexKey) credentialIndexKey()   {}

func (this CredentialPublicKeyIndexKey) WithPublicKey(public_key []byte) CredentialPublicKeyIndexKey {
	this.vs = []interface{}{public_key}
	return this
}

type credentialTable struct {
	table ormtable.AutoIncrementTable
}

func (this credentialTable) Insert(ctx context.Context, credential *Credential) error {
	return this.table.Insert(ctx, credential)
}

func (this credentialTable) Update(ctx context.Context, credential *Credential) error {
	return this.table.Update(ctx, credential)
}

func (this credentialTable) Save(ctx context.Context, credential *Credential) error {
	return this.table.Save(ctx, credential)
}

func (this credentialTable) Delete(ctx context.Context, credential *Credential) error {
	return this.table.Delete(ctx, credential)
}

func (this credentialTable) InsertReturningId(ctx context.Context, credential *Credential) (uint64, error) {
	return this.table.InsertReturningPKey(ctx, credential)
}

func (this credentialTable) LastInsertedSequence(ctx context.Context) (uint64, error) {
	return this.table.LastInsertedSequence(ctx)
}

func (this credentialTable) Has(ctx context.Context, id uint64) (found bool, err error) {
	return this.table.PrimaryKey().Has(ctx, id)
}

func (this credentialTable) Get(ctx context.Context, id uint64) (*Credential, error) {
	var credential Credential
	found, err := this.table.PrimaryKey().Get(ctx, &credential, id)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &credential, nil
}

func (this credentialTable) HasByOriginHandle(ctx context.Context, origin string, handle string) (found bool, err error) {
	return this.table.GetIndexByID(2).(ormtable.UniqueIndex).Has(ctx,
		origin,
		handle,
	)
}

func (this credentialTable) GetByOriginHandle(ctx context.Context, origin string, handle string) (*Credential, error) {
	var credential Credential
	found, err := this.table.GetIndexByID(2).(ormtable.UniqueIndex).Get(ctx, &credential,
		origin,
		handle,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &credential, nil
}

func (this credentialTable) HasByCredentialId(ctx context.Context, credential_id []byte) (found bool, err error) {
	return this.table.GetIndexByID(3).(ormtable.UniqueIndex).Has(ctx,
		credential_id,
	)
}

func (this credentialTable) GetByCredentialId(ctx context.Context, credential_id []byte) (*Credential, error) {
	var credential Credential
	found, err := this.table.GetIndexByID(3).(ormtable.UniqueIndex).Get(ctx, &credential,
		credential_id,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &credential, nil
}

func (this credentialTable) HasByPublicKey(ctx context.Context, public_key []byte) (found bool, err error) {
	return this.table.GetIndexByID(4).(ormtable.UniqueIndex).Has(ctx,
		public_key,
	)
}

func (this credentialTable) GetByPublicKey(ctx context.Context, public_key []byte) (*Credential, error) {
	var credential Credential
	found, err := this.table.GetIndexByID(4).(ormtable.UniqueIndex).Get(ctx, &credential,
		public_key,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &credential, nil
}

func (this credentialTable) List(ctx context.Context, prefixKey CredentialIndexKey, opts ...ormlist.Option) (CredentialIterator, error) {
	it, err := this.table.GetIndexByID(prefixKey.id()).List(ctx, prefixKey.values(), opts...)
	return CredentialIterator{it}, err
}

func (this credentialTable) ListRange(ctx context.Context, from, to CredentialIndexKey, opts ...ormlist.Option) (CredentialIterator, error) {
	it, err := this.table.GetIndexByID(from.id()).ListRange(ctx, from.values(), to.values(), opts...)
	return CredentialIterator{it}, err
}

func (this credentialTable) DeleteBy(ctx context.Context, prefixKey CredentialIndexKey) error {
	return this.table.GetIndexByID(prefixKey.id()).DeleteBy(ctx, prefixKey.values()...)
}

func (this credentialTable) DeleteRange(ctx context.Context, from, to CredentialIndexKey) error {
	return this.table.GetIndexByID(from.id()).DeleteRange(ctx, from.values(), to.values())
}

func (this credentialTable) doNotImplement() {}

var _ CredentialTable = credentialTable{}

func NewCredentialTable(db ormtable.Schema) (CredentialTable, error) {
	table := db.GetTable(&Credential{})
	if table == nil {
		return nil, ormerrors.TableNotFound.Wrap(string((&Credential{}).ProtoReflect().Descriptor().FullName()))
	}
	return credentialTable{table.(ormtable.AutoIncrementTable)}, nil
}

type InterchainTable interface {
	Insert(ctx context.Context, interchain *Interchain) error
	InsertReturningIndex(ctx context.Context, interchain *Interchain) (uint64, error)
	LastInsertedSequence(ctx context.Context) (uint64, error)
	Update(ctx context.Context, interchain *Interchain) error
	Save(ctx context.Context, interchain *Interchain) error
	Delete(ctx context.Context, interchain *Interchain) error
	Has(ctx context.Context, index uint64) (found bool, err error)
	// Get returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	Get(ctx context.Context, index uint64) (*Interchain, error)
	HasByChainId(ctx context.Context, chain_id string) (found bool, err error)
	// GetByChainId returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	GetByChainId(ctx context.Context, chain_id string) (*Interchain, error)
	HasByChainCode(ctx context.Context, chain_code uint32) (found bool, err error)
	// GetByChainCode returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	GetByChainCode(ctx context.Context, chain_code uint32) (*Interchain, error)
	HasByName(ctx context.Context, name string) (found bool, err error)
	// GetByName returns nil and an error which responds true to ormerrors.IsNotFound() if the record was not found.
	GetByName(ctx context.Context, name string) (*Interchain, error)
	List(ctx context.Context, prefixKey InterchainIndexKey, opts ...ormlist.Option) (InterchainIterator, error)
	ListRange(ctx context.Context, from, to InterchainIndexKey, opts ...ormlist.Option) (InterchainIterator, error)
	DeleteBy(ctx context.Context, prefixKey InterchainIndexKey) error
	DeleteRange(ctx context.Context, from, to InterchainIndexKey) error

	doNotImplement()
}

type InterchainIterator struct {
	ormtable.Iterator
}

func (i InterchainIterator) Value() (*Interchain, error) {
	var interchain Interchain
	err := i.UnmarshalMessage(&interchain)
	return &interchain, err
}

type InterchainIndexKey interface {
	id() uint32
	values() []interface{}
	interchainIndexKey()
}

// primary key starting index..
type InterchainPrimaryKey = InterchainIndexIndexKey

type InterchainIndexIndexKey struct {
	vs []interface{}
}

func (x InterchainIndexIndexKey) id() uint32            { return 0 }
func (x InterchainIndexIndexKey) values() []interface{} { return x.vs }
func (x InterchainIndexIndexKey) interchainIndexKey()   {}

func (this InterchainIndexIndexKey) WithIndex(index uint64) InterchainIndexIndexKey {
	this.vs = []interface{}{index}
	return this
}

type InterchainChainIdIndexKey struct {
	vs []interface{}
}

func (x InterchainChainIdIndexKey) id() uint32            { return 1 }
func (x InterchainChainIdIndexKey) values() []interface{} { return x.vs }
func (x InterchainChainIdIndexKey) interchainIndexKey()   {}

func (this InterchainChainIdIndexKey) WithChainId(chain_id string) InterchainChainIdIndexKey {
	this.vs = []interface{}{chain_id}
	return this
}

type InterchainChainCodeIndexKey struct {
	vs []interface{}
}

func (x InterchainChainCodeIndexKey) id() uint32            { return 2 }
func (x InterchainChainCodeIndexKey) values() []interface{} { return x.vs }
func (x InterchainChainCodeIndexKey) interchainIndexKey()   {}

func (this InterchainChainCodeIndexKey) WithChainCode(chain_code uint32) InterchainChainCodeIndexKey {
	this.vs = []interface{}{chain_code}
	return this
}

type InterchainNameIndexKey struct {
	vs []interface{}
}

func (x InterchainNameIndexKey) id() uint32            { return 3 }
func (x InterchainNameIndexKey) values() []interface{} { return x.vs }
func (x InterchainNameIndexKey) interchainIndexKey()   {}

func (this InterchainNameIndexKey) WithName(name string) InterchainNameIndexKey {
	this.vs = []interface{}{name}
	return this
}

type interchainTable struct {
	table ormtable.AutoIncrementTable
}

func (this interchainTable) Insert(ctx context.Context, interchain *Interchain) error {
	return this.table.Insert(ctx, interchain)
}

func (this interchainTable) Update(ctx context.Context, interchain *Interchain) error {
	return this.table.Update(ctx, interchain)
}

func (this interchainTable) Save(ctx context.Context, interchain *Interchain) error {
	return this.table.Save(ctx, interchain)
}

func (this interchainTable) Delete(ctx context.Context, interchain *Interchain) error {
	return this.table.Delete(ctx, interchain)
}

func (this interchainTable) InsertReturningIndex(ctx context.Context, interchain *Interchain) (uint64, error) {
	return this.table.InsertReturningPKey(ctx, interchain)
}

func (this interchainTable) LastInsertedSequence(ctx context.Context) (uint64, error) {
	return this.table.LastInsertedSequence(ctx)
}

func (this interchainTable) Has(ctx context.Context, index uint64) (found bool, err error) {
	return this.table.PrimaryKey().Has(ctx, index)
}

func (this interchainTable) Get(ctx context.Context, index uint64) (*Interchain, error) {
	var interchain Interchain
	found, err := this.table.PrimaryKey().Get(ctx, &interchain, index)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &interchain, nil
}

func (this interchainTable) HasByChainId(ctx context.Context, chain_id string) (found bool, err error) {
	return this.table.GetIndexByID(1).(ormtable.UniqueIndex).Has(ctx,
		chain_id,
	)
}

func (this interchainTable) GetByChainId(ctx context.Context, chain_id string) (*Interchain, error) {
	var interchain Interchain
	found, err := this.table.GetIndexByID(1).(ormtable.UniqueIndex).Get(ctx, &interchain,
		chain_id,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &interchain, nil
}

func (this interchainTable) HasByChainCode(ctx context.Context, chain_code uint32) (found bool, err error) {
	return this.table.GetIndexByID(2).(ormtable.UniqueIndex).Has(ctx,
		chain_code,
	)
}

func (this interchainTable) GetByChainCode(ctx context.Context, chain_code uint32) (*Interchain, error) {
	var interchain Interchain
	found, err := this.table.GetIndexByID(2).(ormtable.UniqueIndex).Get(ctx, &interchain,
		chain_code,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &interchain, nil
}

func (this interchainTable) HasByName(ctx context.Context, name string) (found bool, err error) {
	return this.table.GetIndexByID(3).(ormtable.UniqueIndex).Has(ctx,
		name,
	)
}

func (this interchainTable) GetByName(ctx context.Context, name string) (*Interchain, error) {
	var interchain Interchain
	found, err := this.table.GetIndexByID(3).(ormtable.UniqueIndex).Get(ctx, &interchain,
		name,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ormerrors.NotFound
	}
	return &interchain, nil
}

func (this interchainTable) List(ctx context.Context, prefixKey InterchainIndexKey, opts ...ormlist.Option) (InterchainIterator, error) {
	it, err := this.table.GetIndexByID(prefixKey.id()).List(ctx, prefixKey.values(), opts...)
	return InterchainIterator{it}, err
}

func (this interchainTable) ListRange(ctx context.Context, from, to InterchainIndexKey, opts ...ormlist.Option) (InterchainIterator, error) {
	it, err := this.table.GetIndexByID(from.id()).ListRange(ctx, from.values(), to.values(), opts...)
	return InterchainIterator{it}, err
}

func (this interchainTable) DeleteBy(ctx context.Context, prefixKey InterchainIndexKey) error {
	return this.table.GetIndexByID(prefixKey.id()).DeleteBy(ctx, prefixKey.values()...)
}

func (this interchainTable) DeleteRange(ctx context.Context, from, to InterchainIndexKey) error {
	return this.table.GetIndexByID(from.id()).DeleteRange(ctx, from.values(), to.values())
}

func (this interchainTable) doNotImplement() {}

var _ InterchainTable = interchainTable{}

func NewInterchainTable(db ormtable.Schema) (InterchainTable, error) {
	table := db.GetTable(&Interchain{})
	if table == nil {
		return nil, ormerrors.TableNotFound.Wrap(string((&Interchain{}).ProtoReflect().Descriptor().FullName()))
	}
	return interchainTable{table.(ormtable.AutoIncrementTable)}, nil
}

type StateStore interface {
	AccountTable() AccountTable
	CredentialTable() CredentialTable
	InterchainTable() InterchainTable

	doNotImplement()
}

type stateStore struct {
	account    AccountTable
	credential CredentialTable
	interchain InterchainTable
}

func (x stateStore) AccountTable() AccountTable {
	return x.account
}

func (x stateStore) CredentialTable() CredentialTable {
	return x.credential
}

func (x stateStore) InterchainTable() InterchainTable {
	return x.interchain
}

func (stateStore) doNotImplement() {}

var _ StateStore = stateStore{}

func NewStateStore(db ormtable.Schema) (StateStore, error) {
	accountTable, err := NewAccountTable(db)
	if err != nil {
		return nil, err
	}

	credentialTable, err := NewCredentialTable(db)
	if err != nil {
		return nil, err
	}

	interchainTable, err := NewInterchainTable(db)
	if err != nil {
		return nil, err
	}

	return stateStore{
		accountTable,
		credentialTable,
		interchainTable,
	}, nil
}

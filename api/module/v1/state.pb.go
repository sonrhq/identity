// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: sonrhq/identity/module/v1/state.proto

package modulev1

import (
	_ "cosmossdk.io/api/cosmos/orm/v1"
	_ "cosmossdk.io/api/cosmos/orm/v1alpha1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Module is the app config object of the module.
// Learn more: https://docs.cosmos.network/main/building-modules/depinject
type State struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *State) Reset() {
	*x = State{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *State) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*State) ProtoMessage() {}

func (x *State) ProtoReflect() protoreflect.Message {
	mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use State.ProtoReflect.Descriptor instead.
func (*State) Descriptor() ([]byte, []int) {
	return file_sonrhq_identity_module_v1_state_proto_rawDescGZIP(), []int{0}
}

// Account is the root sonr account table which contains all sub-identities.
type Account struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address   string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	PublicKey string `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	Network   string `protobuf:"bytes,3,opt,name=network,proto3" json:"network,omitempty"`
}

func (x *Account) Reset() {
	*x = Account{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Account) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Account) ProtoMessage() {}

func (x *Account) ProtoReflect() protoreflect.Message {
	mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Account.ProtoReflect.Descriptor instead.
func (*Account) Descriptor() ([]byte, []int) {
	return file_sonrhq_identity_module_v1_state_proto_rawDescGZIP(), []int{1}
}

func (x *Account) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Account) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

func (x *Account) GetNetwork() string {
	if x != nil {
		return x.Network
	}
	return ""
}

// Credential is the total supply of the module.
type Credential struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Did   string `protobuf:"bytes,1,opt,name=did,proto3" json:"did,omitempty"`
	Owner string `protobuf:"bytes,2,opt,name=owner,proto3" json:"owner,omitempty"`
}

func (x *Credential) Reset() {
	*x = Credential{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Credential) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Credential) ProtoMessage() {}

func (x *Credential) ProtoReflect() protoreflect.Message {
	mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Credential.ProtoReflect.Descriptor instead.
func (*Credential) Descriptor() ([]byte, []int) {
	return file_sonrhq_identity_module_v1_state_proto_rawDescGZIP(), []int{2}
}

func (x *Credential) GetDid() string {
	if x != nil {
		return x.Did
	}
	return ""
}

func (x *Credential) GetOwner() string {
	if x != nil {
		return x.Owner
	}
	return ""
}

// Supply is the total supply of the module.
type Identity struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Did   string `protobuf:"bytes,1,opt,name=did,proto3" json:"did,omitempty"`
	Owner string `protobuf:"bytes,2,opt,name=owner,proto3" json:"owner,omitempty"`
}

func (x *Identity) Reset() {
	*x = Identity{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Identity) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Identity) ProtoMessage() {}

func (x *Identity) ProtoReflect() protoreflect.Message {
	mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Identity.ProtoReflect.Descriptor instead.
func (*Identity) Descriptor() ([]byte, []int) {
	return file_sonrhq_identity_module_v1_state_proto_rawDescGZIP(), []int{3}
}

func (x *Identity) GetDid() string {
	if x != nil {
		return x.Did
	}
	return ""
}

func (x *Identity) GetOwner() string {
	if x != nil {
		return x.Owner
	}
	return ""
}

// Keyshare is the keyshare of the identity.
type Keyshare struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Did       string `protobuf:"bytes,1,opt,name=did,proto3" json:"did,omitempty"`
	Address   string `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	Path      int32  `protobuf:"varint,3,opt,name=path,proto3" json:"path,omitempty"`
	Algorithm uint32 `protobuf:"varint,4,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
	KeyType   string `protobuf:"bytes,5,opt,name=key_type,json=keyType,proto3" json:"key_type,omitempty"`
	ChainCode uint32 `protobuf:"varint,6,opt,name=chain_code,json=chainCode,proto3" json:"chain_code,omitempty"`
	Cid       string `protobuf:"bytes,7,opt,name=cid,proto3" json:"cid,omitempty"`
	PublicKey string `protobuf:"bytes,8,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
}

func (x *Keyshare) Reset() {
	*x = Keyshare{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Keyshare) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Keyshare) ProtoMessage() {}

func (x *Keyshare) ProtoReflect() protoreflect.Message {
	mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Keyshare.ProtoReflect.Descriptor instead.
func (*Keyshare) Descriptor() ([]byte, []int) {
	return file_sonrhq_identity_module_v1_state_proto_rawDescGZIP(), []int{4}
}

func (x *Keyshare) GetDid() string {
	if x != nil {
		return x.Did
	}
	return ""
}

func (x *Keyshare) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Keyshare) GetPath() int32 {
	if x != nil {
		return x.Path
	}
	return 0
}

func (x *Keyshare) GetAlgorithm() uint32 {
	if x != nil {
		return x.Algorithm
	}
	return 0
}

func (x *Keyshare) GetKeyType() string {
	if x != nil {
		return x.KeyType
	}
	return ""
}

func (x *Keyshare) GetChainCode() uint32 {
	if x != nil {
		return x.ChainCode
	}
	return 0
}

func (x *Keyshare) GetCid() string {
	if x != nil {
		return x.Cid
	}
	return ""
}

func (x *Keyshare) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

// Owner is the owner of the identity.
type Owner struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Did       string `protobuf:"bytes,1,opt,name=did,proto3" json:"did,omitempty"`
	Address   string `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	CoinType  uint32 `protobuf:"varint,3,opt,name=coin_type,json=coinType,proto3" json:"coin_type,omitempty"`
	PublicKey string `protobuf:"bytes,4,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	Access    string `protobuf:"bytes,5,opt,name=access,proto3" json:"access,omitempty"`
}

func (x *Owner) Reset() {
	*x = Owner{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Owner) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Owner) ProtoMessage() {}

func (x *Owner) ProtoReflect() protoreflect.Message {
	mi := &file_sonrhq_identity_module_v1_state_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Owner.ProtoReflect.Descriptor instead.
func (*Owner) Descriptor() ([]byte, []int) {
	return file_sonrhq_identity_module_v1_state_proto_rawDescGZIP(), []int{5}
}

func (x *Owner) GetDid() string {
	if x != nil {
		return x.Did
	}
	return ""
}

func (x *Owner) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Owner) GetCoinType() uint32 {
	if x != nil {
		return x.CoinType
	}
	return 0
}

func (x *Owner) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

func (x *Owner) GetAccess() string {
	if x != nil {
		return x.Access
	}
	return ""
}

var File_sonrhq_identity_module_v1_state_proto protoreflect.FileDescriptor

var file_sonrhq_identity_module_v1_state_proto_rawDesc = []byte{
	0x0a, 0x25, 0x73, 0x6f, 0x6e, 0x72, 0x68, 0x71, 0x2f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x2f, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x74, 0x61, 0x74,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x19, 0x73, 0x6f, 0x6e, 0x72, 0x68, 0x71, 0x2e,
	0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x2e,
	0x76, 0x31, 0x1a, 0x17, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x6f, 0x72, 0x6d, 0x2f, 0x76,
	0x31, 0x2f, 0x6f, 0x72, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x63, 0x6f, 0x73,
	0x6d, 0x6f, 0x73, 0x2f, 0x6f, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31,
	0x2f, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x33, 0x0a,
	0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x3a, 0x2a, 0x82, 0x9f, 0xd3, 0x8e, 0x03, 0x24, 0x0a, 0x22,
	0x08, 0x01, 0x12, 0x1e, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2f, 0x6d, 0x6f, 0x64,
	0x75, 0x6c, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x71, 0x0a, 0x07, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x18, 0x0a,
	0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x3a, 0x13, 0xf2, 0x9e, 0xd3, 0x8e, 0x03, 0x0d, 0x0a, 0x09, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x18, 0x01, 0x22, 0x45, 0x0a, 0x0a, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x61, 0x6c, 0x12, 0x10, 0x0a, 0x03, 0x64, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x64, 0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x3a, 0x0f, 0xf2, 0x9e, 0xd3,
	0x8e, 0x03, 0x09, 0x0a, 0x05, 0x0a, 0x03, 0x64, 0x69, 0x64, 0x18, 0x02, 0x22, 0x43, 0x0a, 0x08,
	0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x64, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x64, 0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6f, 0x77,
	0x6e, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72,
	0x3a, 0x0f, 0xf2, 0x9e, 0xd3, 0x8e, 0x03, 0x09, 0x0a, 0x05, 0x0a, 0x03, 0x64, 0x69, 0x64, 0x18,
	0x03, 0x22, 0xe4, 0x01, 0x0a, 0x08, 0x4b, 0x65, 0x79, 0x73, 0x68, 0x61, 0x72, 0x65, 0x12, 0x10,
	0x0a, 0x03, 0x64, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x64, 0x69, 0x64,
	0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61,
	0x74, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x1c,
	0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x12, 0x19, 0x0a, 0x08,
	0x6b, 0x65, 0x79, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x6b, 0x65, 0x79, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x68, 0x61, 0x69, 0x6e,
	0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x63, 0x68, 0x61,
	0x69, 0x6e, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x63, 0x69, 0x64, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x63, 0x69, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x3a, 0x0f, 0xf2, 0x9e, 0xd3, 0x8e, 0x03, 0x09, 0x0a,
	0x05, 0x0a, 0x03, 0x64, 0x69, 0x64, 0x18, 0x04, 0x22, 0x98, 0x01, 0x0a, 0x05, 0x4f, 0x77, 0x6e,
	0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x64, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x64, 0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1b,
	0x0a, 0x09, 0x63, 0x6f, 0x69, 0x6e, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x08, 0x63, 0x6f, 0x69, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x3a, 0x0f, 0xf2, 0x9e, 0xd3, 0x8e, 0x03, 0x09, 0x0a, 0x05, 0x0a, 0x03, 0x64, 0x69,
	0x64, 0x18, 0x05, 0x42, 0xf5, 0x01, 0x0a, 0x1d, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x6f, 0x6e, 0x72,
	0x68, 0x71, 0x2e, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x6d, 0x6f, 0x64, 0x75,
	0x6c, 0x65, 0x2e, 0x76, 0x31, 0x42, 0x0a, 0x53, 0x74, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x74,
	0x6f, 0x50, 0x01, 0x5a, 0x41, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x73, 0x6f, 0x6e, 0x72, 0x68, 0x71, 0x2f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x73, 0x6f, 0x6e, 0x72, 0x68, 0x71, 0x2f, 0x69, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x2f, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x6d, 0x6f,
	0x64, 0x75, 0x6c, 0x65, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x53, 0x49, 0x4d, 0xaa, 0x02, 0x19, 0x53,
	0x6f, 0x6e, 0x72, 0x68, 0x71, 0x2e, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x4d,
	0x6f, 0x64, 0x75, 0x6c, 0x65, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x19, 0x53, 0x6f, 0x6e, 0x72, 0x68,
	0x71, 0x5c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5c, 0x4d, 0x6f, 0x64, 0x75, 0x6c,
	0x65, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x25, 0x53, 0x6f, 0x6e, 0x72, 0x68, 0x71, 0x5c, 0x49, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5c, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x5c, 0x56, 0x31,
	0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x1c, 0x53,
	0x6f, 0x6e, 0x72, 0x68, 0x71, 0x3a, 0x3a, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x3a,
	0x3a, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_sonrhq_identity_module_v1_state_proto_rawDescOnce sync.Once
	file_sonrhq_identity_module_v1_state_proto_rawDescData = file_sonrhq_identity_module_v1_state_proto_rawDesc
)

func file_sonrhq_identity_module_v1_state_proto_rawDescGZIP() []byte {
	file_sonrhq_identity_module_v1_state_proto_rawDescOnce.Do(func() {
		file_sonrhq_identity_module_v1_state_proto_rawDescData = protoimpl.X.CompressGZIP(file_sonrhq_identity_module_v1_state_proto_rawDescData)
	})
	return file_sonrhq_identity_module_v1_state_proto_rawDescData
}

var file_sonrhq_identity_module_v1_state_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_sonrhq_identity_module_v1_state_proto_goTypes = []interface{}{
	(*State)(nil),      // 0: sonrhq.identity.module.v1.State
	(*Account)(nil),    // 1: sonrhq.identity.module.v1.Account
	(*Credential)(nil), // 2: sonrhq.identity.module.v1.Credential
	(*Identity)(nil),   // 3: sonrhq.identity.module.v1.Identity
	(*Keyshare)(nil),   // 4: sonrhq.identity.module.v1.Keyshare
	(*Owner)(nil),      // 5: sonrhq.identity.module.v1.Owner
}
var file_sonrhq_identity_module_v1_state_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_sonrhq_identity_module_v1_state_proto_init() }
func file_sonrhq_identity_module_v1_state_proto_init() {
	if File_sonrhq_identity_module_v1_state_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_sonrhq_identity_module_v1_state_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*State); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_sonrhq_identity_module_v1_state_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Account); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_sonrhq_identity_module_v1_state_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Credential); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_sonrhq_identity_module_v1_state_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Identity); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_sonrhq_identity_module_v1_state_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Keyshare); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_sonrhq_identity_module_v1_state_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Owner); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_sonrhq_identity_module_v1_state_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_sonrhq_identity_module_v1_state_proto_goTypes,
		DependencyIndexes: file_sonrhq_identity_module_v1_state_proto_depIdxs,
		MessageInfos:      file_sonrhq_identity_module_v1_state_proto_msgTypes,
	}.Build()
	File_sonrhq_identity_module_v1_state_proto = out.File
	file_sonrhq_identity_module_v1_state_proto_rawDesc = nil
	file_sonrhq_identity_module_v1_state_proto_goTypes = nil
	file_sonrhq_identity_module_v1_state_proto_depIdxs = nil
}

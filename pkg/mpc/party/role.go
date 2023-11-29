package party

// PartyRole is a role in the DKG protocol
type PartyRole string

const (
	// PartyRolePrivate is the default role for the alice dkg
	PartyRolePrivate PartyRole = "alice"

	// KeyshareRolePublic is the role for an encrypted keyshare for a user
	PartyRolePublic PartyRole = "bob"
)

// IsAlice returns true if the keyshare role is alice
func (ksr PartyRole) IsAlice() bool {
	return ksr == PartyRolePrivate
}

// IsBob returns true if the keyshare role is bob
func (ksr PartyRole) IsBob() bool {
	return ksr == PartyRolePublic
}

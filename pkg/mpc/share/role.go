package share

// ShareRole is a role in the DKG protocol
type ShareRole string

const (
	// PartyRolePrivate is the default role for the alice dkg
	ShareRolePrivate ShareRole = "alice"

	// KeyshareRolePublic is the role for an encrypted keyshare for a user
	ShareRolePublic ShareRole = "bob"
)

// IsAlice returns true if the keyshare role is alice
func (ksr ShareRole) IsAlice() bool {
	return ksr == ShareRolePrivate
}

// IsBob returns true if the keyshare role is bob
func (ksr ShareRole) IsBob() bool {
	return ksr == ShareRolePublic
}

package setting

type LDAPUserInfo struct {
	Username  string
	PublicKey []string
}

type LDAPPublicKey struct {
	Fingerprint string
	PublicKey   string
	Title       string
}

package setting

type LDAPUserInfo struct {
	UIDNumber int64
	Username  string
	PublicKey []string
}

type LDAPPublicKey struct {
	Fingerprint string
	PublicKey   string
	Title       string
}

package setting

type UpdateSettingRequest struct {
	Username      string `json:"username" validate:"required"`
	LinuxUsername string `json:"linux_username"`
}

type PublicKeyResponse struct {
	PublicKeys []struct {
		KeyName   string `json:"key_name"`
		PublicKey string `json:"public_key"`
	}
}

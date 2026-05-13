package user

type ListUsersRowWithLinuxUsername struct {
	ListUsersRow
	LinuxUsername string
}

type PresetUserInfo struct {
	Role string `yaml:"role"`
}

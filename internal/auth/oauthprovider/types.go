package oauthprovider

type UserInfoStore interface {
	GetUserInfo() UserInfo
	SetUserInfo(userInfo UserInfo)
}

type UserInfo struct {
	ID    string
	Email string
	Name  string
}

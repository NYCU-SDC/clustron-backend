package role

type GlobalRole string

var (
	Admin     GlobalRole = "admin"
	Organizer GlobalRole = "organizer"
	User      GlobalRole = "user"
)

var GlobalRoles = map[GlobalRole]bool{
	Admin:     true,
	Organizer: true,
	User:      true,
}

func (g *GlobalRole) String() string {
	return string(*g)
}

func IsValidGlobalRole(role string) bool {
	_, ok := GlobalRoles[GlobalRole(role)]
	return ok
}

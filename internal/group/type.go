package group

import "clustron-backend/internal/grouprole"

type WithLinks struct {
	grouprole.UserScope
	Links []Link
}

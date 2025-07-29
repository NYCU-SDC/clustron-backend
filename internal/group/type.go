package group

import "clustron-backend/internal/grouprole"

type ResponseWithLinks struct {
	grouprole.UserScope
	Links []Link
}

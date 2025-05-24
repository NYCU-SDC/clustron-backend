package group

func CanAssignRole(myLevel string, targetLevel string) bool {
	return accessLevelRank[myLevel] > accessLevelRank[targetLevel]
}

func HasGroupControlAccess(accessLevel string) bool {
	return accessLevel == string(AccessLevelOwner) || accessLevel == string(AccessLevelAdmin)
}

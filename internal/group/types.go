package group

type DefaultRole string

const (
	RoleOwner   DefaultRole = "e02311a8-5a17-444a-b5bb-5c04afa8fa88" // Access Level: GROUP_OWNER
	RoleTA      DefaultRole = "524db082-9d0d-4515-b70c-af3766414bd7" // Access Level: GROUP_ADMIN
	RoleStudent DefaultRole = "de2ed988-a34f-40d3-af70-7e54fa266b37" // Access Level: USER
	RoleAuditor DefaultRole = "c5e8a9c9-0b71-434a-ae61-b66983736217" // Access Level: USER
)

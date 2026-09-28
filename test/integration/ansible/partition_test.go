package ansible

import (
	"testing"

	"clustron-backend/internal/ansible"
	"clustron-backend/internal/group/ldapgroup"
	"clustron-backend/test/integration"
	dbtestdata "clustron-backend/test/testdata/database"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertLdapGroup adds an ldap_groups row directly; the test data builders have no ldap
// group factory.
func insertLdapGroup(t *testing.T, db pgx.Tx, groupID uuid.UUID, cn *string, groupType string, gidNumber int64) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(t.Context(),
		`INSERT INTO ldap_groups (group_id, ldap_cn, type, gid_number) VALUES ($1, $2, $3, $4) RETURNING id`,
		groupID, cn, groupType, gidNumber).Scan(&id)
	require.NoError(t, err)
	return id
}

func ptr(s string) *string { return &s }

func TestPartitionAllowedGroupQueries(t *testing.T) {
	resourceManager, _, err := integration.GetOrInitResource()
	require.NoError(t, err)
	defer resourceManager.Cleanup(t.Context())

	t.Run("lists allowed groups with BASE cn", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		q := ansible.New(db)
		grp := dbtestdata.NewBuilder(t, db).Group().Create(dbtestdata.GroupWithTitle("CS Lab"))
		baseID := insertLdapGroup(t, db, grp.ID, ptr("cslab"), "BASE", 90001)
		insertLdapGroup(t, db, grp.ID, ptr("cslab-admin"), "ADMIN", 90002)

		require.NoError(t, q.AddPartitionAllowedGroup(t.Context(), ansible.AddPartitionAllowedGroupParams{PartitionName: "gpu", LdapGroupID: baseID}))

		groups, err := q.ListPartitionAllowedGroups(t.Context(), "gpu")
		require.NoError(t, err)
		assert.Equal(t, []ansible.ListPartitionAllowedGroupsRow{
			{GroupID: grp.ID, Title: "CS Lab", LdapCn: pgtype.Text{String: "cslab", Valid: true}},
		}, groups)

		accounts, err := q.ListAllPartitionAllowedAccounts(t.Context())
		require.NoError(t, err)
		assert.Equal(t, []ansible.ListAllPartitionAllowedAccountsRow{
			{PartitionName: "gpu", LdapCn: pgtype.Text{String: "cslab", Valid: true}},
		}, accounts)
	})

	t.Run("cascades when the ldap group is deleted", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		q := ansible.New(db)
		grp := dbtestdata.NewBuilder(t, db).Group().Create()
		baseID := insertLdapGroup(t, db, grp.ID, ptr("gone"), "BASE", 90011)
		require.NoError(t, q.AddPartitionAllowedGroup(t.Context(), ansible.AddPartitionAllowedGroupParams{PartitionName: "gpu", LdapGroupID: baseID}))

		_, err := db.Exec(t.Context(), `DELETE FROM ldap_groups WHERE id = $1`, baseID)
		require.NoError(t, err)

		accounts, err := q.ListAllPartitionAllowedAccounts(t.Context())
		require.NoError(t, err)
		assert.Empty(t, accounts)
	})

	t.Run("rejects unknown ldap group with named FK", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		q := ansible.New(db)

		err := q.AddPartitionAllowedGroup(t.Context(), ansible.AddPartitionAllowedGroupParams{PartitionName: "gpu", LdapGroupID: uuid.New()})

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "partition_allowed_groups_ldap_group_id_fkey", pgErr.ConstraintName)
	})

	t.Run("BASE lookup skips groups without a cn", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		grp := dbtestdata.NewBuilder(t, db).Group().Create()
		insertLdapGroup(t, db, grp.ID, nil, "BASE", 90021)

		_, err := ldapgroup.New(db).GetLDAPGroupIDByGroupIDAndType(t.Context(), ldapgroup.GetLDAPGroupIDByGroupIDAndTypeParams{
			GroupID: grp.ID,
			Type:    ldapgroup.GroupTypeBASE,
		})
		assert.ErrorIs(t, err, pgx.ErrNoRows)
	})
}

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

	t.Run("lists allowed groups with their type and cn", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		q := ansible.New(db)
		grp := dbtestdata.NewBuilder(t, db).Group().Create(dbtestdata.GroupWithTitle("CS Lab"))
		baseID := insertLdapGroup(t, db, grp.ID, ptr("cslab"), "BASE", 90001)
		adminID := insertLdapGroup(t, db, grp.ID, ptr("cslab-admin"), "ADMIN", 90002)
		require.NoError(t, q.UpsertPartition(t.Context(), "gpu"))
		require.NoError(t, q.UpsertPartition(t.Context(), "debug"))

		require.NoError(t, q.AddPartitionAllowedGroup(t.Context(), ansible.AddPartitionAllowedGroupParams{PartitionName: "gpu", LdapGroupID: baseID}))
		require.NoError(t, q.AddPartitionAllowedGroup(t.Context(), ansible.AddPartitionAllowedGroupParams{PartitionName: "debug", LdapGroupID: adminID}))

		groups, err := q.ListPartitionAllowedGroups(t.Context(), "gpu")
		require.NoError(t, err)
		assert.Equal(t, []ansible.ListPartitionAllowedGroupsRow{
			{GroupID: grp.ID, Type: ansible.GroupTypeBASE, Title: "CS Lab", LdapCn: pgtype.Text{String: "cslab", Valid: true}},
		}, groups)

		accounts, err := q.ListAllPartitionAllowedAccounts(t.Context())
		require.NoError(t, err)
		assert.Equal(t, []ansible.ListAllPartitionAllowedAccountsRow{
			{PartitionName: "debug", LdapCn: pgtype.Text{String: "cslab-admin", Valid: true}},
			{PartitionName: "gpu", LdapCn: pgtype.Text{String: "cslab", Valid: true}},
		}, accounts)
	})

	t.Run("cascades when the ldap group is deleted", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		q := ansible.New(db)
		grp := dbtestdata.NewBuilder(t, db).Group().Create()
		baseID := insertLdapGroup(t, db, grp.ID, ptr("gone"), "BASE", 90011)
		require.NoError(t, q.UpsertPartition(t.Context(), "gpu"))
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
		require.NoError(t, q.UpsertPartition(t.Context(), "gpu"))

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

func TestPartitionQueries(t *testing.T) {
	resourceManager, _, err := integration.GetOrInitResource()
	require.NoError(t, err)
	defer resourceManager.Cleanup(t.Context())

	// computeNode satisfies the servers check constraints: a connection (ssh_config_host) and
	// a cluster address (private_ip).
	computeNode := func(name, privateIP, partition string) ansible.CreateParams {
		return ansible.CreateParams{
			AnsibleName:    name,
			SshConfigHost:  pgtype.Text{String: name, Valid: true},
			PrivateIp:      pgtype.Text{String: privateIP, Valid: true},
			AnsibleRole:    "compute_nodes",
			SlurmPartition: pgtype.Text{String: partition, Valid: partition != ""},
			Status:         "unset",
		}
	}

	t.Run("seeds the normal partition", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)

		exists, err := ansible.New(db).ExistPartition(t.Context(), "normal")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("server with unknown partition violates FK", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)

		_, err := ansible.New(db).Create(t.Context(), computeNode("cpu1", "10.0.0.1", "ghost"))

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "servers_slurm_partition_fkey", pgErr.ConstraintName)
	})

	t.Run("upsert then create server", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		q := ansible.New(db)

		require.NoError(t, q.UpsertPartition(t.Context(), "gpu"))
		require.NoError(t, q.UpsertPartition(t.Context(), "gpu"))

		_, err := q.Create(t.Context(), computeNode("gpu1", "10.0.0.2", "gpu"))
		require.NoError(t, err)
		_, err = q.Create(t.Context(), computeNode("cpu1", "10.0.0.3", ""))
		require.NoError(t, err)
	})

	t.Run("allowed group needs an existing partition", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		q := ansible.New(db)
		grp := dbtestdata.NewBuilder(t, db).Group().Create()
		baseID := insertLdapGroup(t, db, grp.ID, ptr("lab"), "BASE", 90031)

		err := q.AddPartitionAllowedGroup(t.Context(), ansible.AddPartitionAllowedGroupParams{PartitionName: "ghost", LdapGroupID: baseID})

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "partition_allowed_groups_partition_name_fkey", pgErr.ConstraintName)
	})
}

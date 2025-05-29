package group

import (
	"clustron-backend/test/integration"
	"clustron-backend/test/testdata/database"
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDemo(t *testing.T) {
	resourceManager, _, err := integration.GetOrInitResource()
	if err != nil {
		t.Fatalf("failed to get resource manager: %v", err)
	}
	defer resourceManager.Cleanup()

	t.Run("test", func(t *testing.T) {
		t.Logf("test")

		db, rollback, err := resourceManager.SetupPostgres()
		if err != nil {
			t.Fatalf("failed to setup postgres: %v", err)
		}
		defer rollback()

		builder := dbtestdata.NewBuilder(t, db)
		user := builder.User().Create()
		fmt.Println(user)
	})
}

func TestGroupService_CountAll(t *testing.T) {
	testCases := []struct {
		name        string
		setup       func(t *testing.T, db dbtestdata.DBTX)
		expect      int64
		expectError bool
	}{
		{
			name: "count all groups",
			setup: func(t *testing.T, db dbtestdata.DBTX) {
				builder := dbtestdata.NewBuilder(t, db)
				for i := 0; i < 3; i++ {
					builder.Group().Create(
						dbtestdata.WithTitle(fmt.Sprintf("Group %d", i+1)),
						dbtestdata.WithDescription(fmt.Sprintf("Description for Group %d", i+1)),
					)
				}
			},
			expect:      3,
			expectError: false,
		},
		{
			name:        "count with no groups",
			expect:      0,
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resourceManager, _, err := integration.GetOrInitResource()
			if err != nil {
				t.Fatalf("failed to get resource manager: %v", err)
			}
			defer resourceManager.Cleanup()

			db, rollback, err := resourceManager.SetupPostgres()
			if err != nil {
				t.Fatalf("failed to setup postgres: %v", err)
			}
			defer rollback()

			builder := dbtestdata.NewBuilder(t, db)
			if tc.setup != nil {
				tc.setup(t, db)
			}

			groupQueries := builder.Group().GetGroupQueries()
			count, err := groupQueries.CountAll(context.Background())

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expect, count)
			}
		})
	}
}

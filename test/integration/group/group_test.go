package group

import (
	"clustron-backend/test/integration"
	"clustron-backend/test/testdata/database"
	"fmt"
	"testing"
)

func TestName(t *testing.T) {
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
		user := builder.User().CreateUser()
		fmt.Println(user)
	})
}

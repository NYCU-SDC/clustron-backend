package slurm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccountNameHelpers(t *testing.T) {
	testCases := []struct {
		name          string
		groupCN       string
		expectedBase  string
		expectedAdmin string
	}{
		{name: "simple name", groupCN: "proj101", expectedBase: "proj101-base", expectedAdmin: "proj101-admin"},
		{name: "name with hyphens", groupCN: "nycu-hpc", expectedBase: "nycu-hpc-base", expectedAdmin: "nycu-hpc-admin"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedBase, BaseAccountName(tc.groupCN))
			assert.Equal(t, tc.expectedAdmin, AdminAccountName(tc.groupCN))
		})
	}
}

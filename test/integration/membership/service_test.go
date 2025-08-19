package membership

//import (
//	"clustron-backend/internal/config"
//	"clustron-backend/internal/grouprole"
//	"clustron-backend/internal/jwt"
//	"clustron-backend/internal/membership"
//	"clustron-backend/internal/setting"
//	"clustron-backend/internal/user"
//	"clustron-backend/internal/user/role"
//	"clustron-backend/test/integration"
//	dbtestdata "clustron-backend/test/testdata/database"
//	"context"
//	"github.com/google/uuid"
//	"github.com/stretchr/testify/assert"
//	"github.com/stretchr/testify/require"
//	"testing"
//)
//
//func TestMembershipService_Add(t *testing.T) {
//	type params struct {
//		userId           uuid.UUID
//		groupId          uuid.UUID
//		memberIdentifier string
//		role             uuid.UUID
//	}
//	testCases := []struct {
//		name      string
//		params    params
//		setup     func(t *testing.T, params params, db dbtestdata.DBTX) context.Context
//		validate  func(t *testing.T, params params, db dbtestdata.DBTX, result membership.JoinResult)
//		expectErr bool
//	}{
//		{
//			name: "Should add membership with existing user",
//			params: params{
//				userId:           uuid.MustParse("9bdb2632-ec77-4c7a-b9e1-340576c7c3ed"),
//				groupId:          uuid.MustParse("320b8f5d-9290-40d3-bdfd-0d0e55bc9afd"),
//				memberIdentifier: "user@example.com",
//				role:             uuid.MustParse(grouprole.RoleStudent.String()),
//			},
//			setup: func(t *testing.T, params params, db dbtestdata.DBTX) context.Context {
//				builder := dbtestdata.NewBuilder(t, db)
//				userBuilder := builder.User()
//				builder.Group().CreateInfo(dbtestdata.GroupWithID(params.groupId))
//
//				operatorID := uuid.MustParse("bcdc86ec-4e09-4239-b73b-389e2909138c")
//				operator := userBuilder.CreateInfo(dbtestdata.UserWithID(operatorID),
//					dbtestdata.UserWithRole(role.Organizer))
//
//				_, err := builder.Membership().CreateInfo(params.groupId, operatorID, uuid.MustParse(grouprole.RoleOwner.String()))
//				require.NoError(t, err, "failed to create membership for operator")
//
//				userBuilder.CreateInfo(dbtestdata.UserWithID(params.userId),
//					dbtestdata.UserWithEmail("user@example.com"))
//
//				contextUser := jwt.User{
//					ID:        operator.ID,
//					Email:     operator.Email,
//					Role:      operator.Role,
//					StudentID: operator.StudentID,
//					CreatedAt: operator.CreatedAt,
//					UpdatedAt: operator.UpdatedAt,
//				}
//
//				return jwt.SetUserToContext(context.Background(), contextUser)
//			},
//			validate: func(t *testing.T, params params, db dbtestdata.DBTX, result membership.JoinResult) {
//				builder := dbtestdata.NewBuilder(t, db)
//				membershipQueries := builder.Membership().Queries()
//
//				// Check if the membership was created
//				args := membership.GetMembershipByUserParams{
//					UserID:  params.userId,
//					GroupID: params.groupId,
//				}
//				m, err := membershipQueries.GetMembershipByUser(context.Background(), args)
//				assert.NoError(t, err, "failed to get membership by user")
//				assert.Equal(t, params.userId, m.UserID, "user ID should match")
//				assert.Equal(t, params.groupId, m.GroupID, "group ID should match")
//
//				require.Equal(t, result.JoinType(), membership.JoinMemberResponseTypeMember, "join type should be ExistingUser")
//				if memberResp, ok := result.(membership.MemberResponse); ok {
//					assert.Equal(t, "9bdb2632-ec77-4c7a-b9e1-340576c7c3ed", memberResp.ID.String(), "member ID should match")
//					assert.Equal(t, "user@example.com", memberResp.Email, "member email should match")
//				}
//			},
//		},
//	}
//
//	resourceManager, logger, err := integration.GetOrInitResource()
//	if err != nil {
//		t.Fatalf("failed to get resource manager: %v", err)
//	}
//	defer resourceManager.Cleanup()
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			db, rollback, err := resourceManager.SetupPostgres()
//			if err != nil {
//				t.Fatalf("failed to setup postgres: %v", err)
//			}
//			defer rollback()
//
//			ctx := context.Background()
//			if tc.setup != nil {
//				ctx = tc.setup(t, tc.params, db)
//			}
//
//			userService := user.NewService(logger, make(map[string]config.PresetUserInfo), db)
//			settingService := setting.NewService(logger, db)
//			groupRoleService := grouprole.NewService(logger, db, settingService)
//			membershipService := membership.NewService(logger, db, userService, groupRoleService, settingService)
//
//			result, err := membershipService.Add(ctx, tc.params.userId, tc.params.groupId, tc.params.memberIdentifier, tc.params.role)
//			require.Equal(t, tc.expectErr, err != nil, "expected error: %v, got: %v", tc.expectErr, err)
//
//			if tc.validate != nil {
//				tc.validate(t, tc.params, db, result)
//			}
//		})
//	}
//}

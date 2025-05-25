package group

import (
	"context"

	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func CanAssignRole(s *Service, ctx context.Context, userId uuid.UUID, groupId uuid.UUID, roleId uuid.UUID) bool {
	traceCtx, span := s.tracer.Start(ctx, "CanAssignRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	accessLevel, err := s.GetUserGroupAccessLevel(traceCtx, userId, groupId)
	if err != nil {
		logger.Error("failed to get user group access level", zap.Error(err))
		return false
	}
	targetRole, err := s.GetGroupRoleByID(traceCtx, roleId)
	if err != nil {
		logger.Error("failed to get member role by id", zap.Error(err))
		return false
	}
	return accessLevelRank[accessLevel] > accessLevelRank[targetRole.AccessLevel]
}

func HasGroupControlAccess(s *Service, ctx context.Context, userId uuid.UUID, groupId uuid.UUID) bool {
	traceCtx, span := s.tracer.Start(ctx, "HasGroupControlAccess")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	accessLevel, err := s.GetUserGroupAccessLevel(ctx, userId, groupId)
	if err != nil {
		logger.Error("failed to get user group access level", zap.Error(err))
		return false
	}

	return accessLevel == string(AccessLevelOwner) || accessLevel == string(AccessLevelAdmin)
}

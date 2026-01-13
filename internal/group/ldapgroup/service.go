package ldapgroup

import (
	"context"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	logger *zap.Logger
	tracer trace.Tracer

	queries *Queries
}

func NewService(logger *zap.Logger, db DBTX) *Service {
	return &Service{
		logger:  logger,
		tracer:  otel.Tracer("ldapgroup/service"),
		queries: New(db),
	}
}

func (s *Service) GetLDAPBaseGroupCNByGroupID(ctx context.Context, groupID uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetLDAPBaseGroupCNByGroupID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	cn, err := s.queries.GetLDAPBaseGroupCNByGroupID(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_group", "group_id", groupID.String(), logger, "get LDAP base group CN by group ID")
		logger.Error("failed to get LDAP base group CN by group ID", zap.String("group_id", groupID.String()), zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	return cn.String, nil
}

func (s *Service) GetLDAPAdminGroupCNByGroupID(ctx context.Context, groupID uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetLDAPAdminGroupCNByGroupID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	cn, err := s.queries.GetLDAPAdminGroupCNByGroupID(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_group", "group_id", groupID.String(), logger, "get LDAP admin group CN by group ID")
		logger.Error("failed to get LDAP admin group CN by group ID", zap.String("group_id", groupID.String()), zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	return cn.String, nil
}

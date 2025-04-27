package setting

import (
	"context"
	"github.com/NYCU-SDC/summer/pkg/database"
	"github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	logger *zap.Logger
	tracer trace.Tracer
	query  *Queries
}

func NewService(logger *zap.Logger, db DBTX) *Service {
	return &Service{
		logger: logger,
		tracer: otel.Tracer("setting/service"),
		query:  New(db),
	}
}

func (s *Service) GetSettingByUserId(ctx context.Context, userId uuid.UUID) (Setting, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetSettingByUserId")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	setting, err := s.query.GetSetting(ctx, userId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", userId.String(), logger, "get setting by user id")
		span.RecordError(err)
		return Setting{}, err
	}

	return setting, nil
}

func (s *Service) UpdateSetting(ctx context.Context, userId uuid.UUID, setting Setting) (Setting, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateSetting")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	updatedSetting, err := s.query.UpdateSetting(ctx, UpdateSettingParams(setting))

	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", userId.String(), logger, "update setting")
		span.RecordError(err)
		return Setting{}, err
	}

	return updatedSetting, nil
}

func (s *Service) GetPublicKeysByUserId(ctx context.Context, userId uuid.UUID) ([]PublicKey, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetPublicKeysByUserId")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	publicKeys, err := s.query.GetPublicKeys(ctx, userId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "public_keys", "id", userId.String(), logger, "get public keys by user id")
		span.RecordError(err)
		return nil, err
	}

	return publicKeys, err
}

func (s *Service) GetPublicKeyById(ctx context.Context, id uuid.UUID) (PublicKey, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetPublicKeyById")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	publicKey, err := s.query.GetPublicKey(ctx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "public_keys", "id", id.String(), logger, "get public key by id")
		span.RecordError(err)
		return PublicKey{}, err
	}

	return publicKey, nil
}

func (s *Service) AddPublicKey(ctx context.Context, publicKey AddPublicKeyParams) (PublicKey, error) {
	traceCtx, span := s.tracer.Start(ctx, "AddPublicKey")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	addedPublicKey, err := s.query.AddPublicKey(ctx, publicKey)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "public_keys", "id", publicKey.UserID.String(), logger, "add public key")
		span.RecordError(err)
		return PublicKey{}, err
	}

	return addedPublicKey, nil
}

func (s *Service) DeletePublicKey(ctx context.Context, id uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "DeletePublicKey")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	err := s.query.DeletePublicKey(ctx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", id.String(), logger, "delete public key")
		span.RecordError(err)
		return err
	}

	return nil
}

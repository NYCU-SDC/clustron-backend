package module

import (
	"context"

	// 專案共用工具
	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype" // 根據你的 sqlc 設定，可能需要這個
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service 定義模組服務的結構
// 參考 PDF
type Service struct {
	logger  *zap.Logger
	tracer  trace.Tracer
	queries *Queries
}

// NewService 初始化 Service
// 參考 PDF
func NewService(logger *zap.Logger, dbConn db.DBTX) *Service {
	return &Service{
		logger: logger,
		// 使用 module/service 作為 tracer 名稱，區隔 group/service
		tracer:  otel.Tracer("module/service"),
		queries: New(dbConn),
	}
}

// Create 建立新模組
// 參考 PDF CreateLink 的寫法
func (s *Service) Create(ctx context.Context, title string, description string, environment []byte) (Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "Create")
	defer span.End()

	logger := logutil.WithContext(traceCtx, s.logger)

	// 呼叫 SQLC 生成的 CreateModule
	// 注意：environment 參數類型取決於你的 models.go，通常是 []byte 或 json.RawMessage
	module, err := s.queries.CreateModule(traceCtx, CreateModuleParams{
		Title:       title,
		Description: pgtype.Text{String: description, Valid: description != ""}, // 處理 Nullable Text
		Environment: environment,
	})

	if err != nil {
		// 參考 PDF 使用 WrapDBError
		err = databaseutil.WrapDBError(err, logger, "failed to create module")
		span.RecordError(err)
		return Module{}, err
	}

	return module, nil
}

// Get 讀取單一模組
// 參考 PDF Get 方法
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "Get")
	defer span.End()

	logger := logutil.WithContext(traceCtx, s.logger)

	module, err := s.queries.GetModule(traceCtx, id)
	if err != nil {
		// 參考 PDF 使用 WrapDBErrorWithKeyValue 加上 ID 資訊方便除錯
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to get module by id")
		span.RecordError(err)
		return Module{}, err
	}

	return module, nil
}

// ListPaged 分頁讀取模組列表
// 參考 PDF ListPaged 方法
func (s *Service) ListPaged(ctx context.Context, page int, size int) ([]Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListPaged")
	defer span.End()

	logger := logutil.WithContext(traceCtx, s.logger)

	// 計算 Offset (Skip)
	// 參考 PDF Skip: int32(page) * int32(size)
	limit := int32(size)
	offset := int32(page) * int32(size)

	params := ListModulesParams{
		Size: limit,
		Skip: offset,
	}

	modules, err := s.queries.ListModules(traceCtx, params)
	if err != nil {
		// 參考 PDF
		err = databaseutil.WrapDBError(err, logger, "failed to list modules")
		span.RecordError(err)
		return nil, err
	}

	return modules, nil
}

// Update 更新模組
// 參考 PDF UpdateLink 的寫法
func (s *Service) Update(ctx context.Context, id uuid.UUID, title string, description string, environment []byte) (db.Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "Update")
	defer span.End()

	logger := logutil.WithContext(traceCtx, s.logger)

	updatedModule, err := s.queries.UpdateModule(traceCtx, UpdateModuleParams{
		ID:          id,
		Title:       title,
		Description: pgtype.Text{String: description, Valid: description != ""},
		Environment: environment,
	})

	if err != nil {
		// 參考 PDF
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to update module")
		span.RecordError(err)
		return Module{}, err
	}

	return updatedModule, nil
}

// Delete 刪除模組
// 參考 PDF DeleteLink 的寫法
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "Delete")
	defer span.End()

	logger := logutil.WithContext(traceCtx, s.logger)

	err := s.queries.DeleteModule(traceCtx, id)
	if err != nil {
		// 參考 PDF
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to delete module")
		span.RecordError(err)
		return err
	}

	return nil
}

package group

import (
	"context"
	"github.com/NYCU-SDC/summer/pkg/pagination"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Store interface {
	GetAllGroupCount(ctx context.Context) (int, error)
	GetUserGroupsCount(ctx context.Context, userId uuid.UUID) (int, error)
	GetAll(ctx context.Context, page int, size int, sort string, sortBy string) ([]Group, error)
	GetByUserId(ctx context.Context, userId uuid.UUID, page int, size int, sort string, sortBy string) ([]Group, error)
	GetById(ctx context.Context, groupId uuid.UUID) (Group, error)
	CreateGroup(ctx context.Context, group CreateParams) (Group, error)
	ArchiveGroup(ctx context.Context, groupId uuid.UUID) (Group, error)
	UnarchiveGroup(ctx context.Context, groupId uuid.UUID) (Group, error)
}

type Response struct {
	Id          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	IsArchived  bool   `json:"isArchived"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type CreateRequest struct {
	Title       string `json:"title" validate:"required"`
	Description string `json:"description" validate:"required"`
}

type Handler struct {
	Validator         *validator.Validate
	Logger            *zap.Logger
	Tracer            trace.Tracer
	Store             Store
	PaginationFactory pagination.Factory[Response]
}

func NewHandler(validator *validator.Validate, logger *zap.Logger, store Store) *Handler {
	return &Handler{
		Validator:         validator,
		Logger:            logger,
		Tracer:            otel.Tracer("group/handler"),
		Store:             store,
		PaginationFactory: pagination.NewFactory[Response](200, []string{"created_at"}),
	}
}

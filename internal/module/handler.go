package module

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	// 專案共用工具
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// -------------------------------------------------------------------
// 1. DTO (Data Transfer Objects) 定義
// -------------------------------------------------------------------

// CreateRequest 定義建立模組的請求格式
type CreateRequest struct {
	Title       string          `json:"title" validate:"required,max=100"`
	Description string          `json:"description"` // 前端傳字串，我們轉成 pgtype.Text
	Environment json.RawMessage `json:"environment"` // 接收任意 JSON 格式
}

// UpdateRequest 定義更新模組的請求格式
type UpdateRequest struct {
	Title       string          `json:"title" validate:"required,max=100"`
	Description string          `json:"description"`
	Environment json.RawMessage `json:"environment"`
}

// Response 定義回傳給前端的格式 (這就是 API 文件會看到的樣子)
// 參考 PDF Page 27: TransferOwner 回傳的格式
type Response struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Environment json.RawMessage `json:"environment"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// -------------------------------------------------------------------
// 2. 介面與結構定義
// -------------------------------------------------------------------

// Store 定義 Handler 需要的商業邏輯介面
// 這樣做是為了可以 Mock Service 進行單元測試
// 參考 PDF Page 1: MemberStore 介面定義
type Store interface {
	Create(ctx context.Context, title string, description string, environment []byte) (Module, error)
	Get(ctx context.Context, id uuid.UUID) (Module, error)
	ListPaged(ctx context.Context, page int, size int) ([]Module, error)
	Update(ctx context.Context, id uuid.UUID, title string, description string, environment []byte) (Module, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// Handler 處理 HTTP 請求
// 參考 PDF Page 4: Handler 結構
type Handler struct {
	store         Store
	validator     *validator.Validate
	logger        *zap.Logger
	tracer        trace.Tracer
	problemWriter *problem.ProblemWriter // 專案統一的錯誤回應工具
}

// NewHandler 初始化 Handler
func NewHandler(store Store, validator *validator.Validate, logger *zap.Logger, problemWriter *problem.ProblemWriter) *Handler {
	return &Handler{
		store:         store,
		validator:     validator,
		logger:        logger,
		tracer:        otel.Tracer("module/handler"),
		problemWriter: problemWriter,
	}
}

// -------------------------------------------------------------------
// 3. HTTP Methods 實作
// -------------------------------------------------------------------

// Create 處理 POST /modules
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Create")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	// 解析並驗證 Request Body
	// 參考 PDF Page 27
	var req CreateRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		// ParseAndValidateRequestBody 內部通常會處理 400 Bad Request
		// 但如果有錯誤回傳，我們用 problemWriter 寫出
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// 呼叫 Service
	module, err := h.store.Create(traceCtx, req.Title, req.Description, req.Environment)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// 回傳 JSON
	handlerutil.WriteJSONResponse(w, http.StatusCreated, toResponse(module))
}

// Get 處理 GET /modules/{id}
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Get")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	// 解析 URL 參數 (Go 1.22+ style)
	// 參考 PDF Page 26
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		// 這裡假設 problem package 有定義 ErrInvalidRequest 或類似的
		// 如果沒有，可以直接用 http.Error 或自定義錯誤
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	module, err := h.store.Get(traceCtx, id)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, toResponse(module))
}

// List 處理 GET /modules?page=0&size=10
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "List")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	// 解析分頁參數 (簡單實作)
	page, _ := strconv.Atoi(r.URL.Query().Get("page")) // 預設 0
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	if size == 0 {
		size = 10 // 預設大小
	}

	modules, err := h.store.ListPaged(traceCtx, page, size)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// 轉換成 Response Slice
	responses := make([]Response, len(modules))
	for i, m := range modules {
		responses[i] = toResponse(m)
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, responses)
}

// Update 處理 PUT /modules/{id}
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Update")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var req UpdateRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	module, err := h.store.Update(traceCtx, id, req.Title, req.Description, req.Environment)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, toResponse(module))
}

// Delete 處理 DELETE /modules/{id}
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Delete")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if err := h.store.Delete(traceCtx, id); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// 刪除成功通常回傳 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

// -------------------------------------------------------------------
// 4. Helper Methods
// -------------------------------------------------------------------

// toResponse 將 DB 模型轉換為 API 回應格式
// 這是 "Mapping" 的過程，把內部髒髒的結構轉成外部乾淨的 JSON
func toResponse(m Module) Response {
	return Response{
		ID:          m.ID.String(),
		Title:       m.Title,
		Description: m.Description.String, // 自動處理: 如果是 NULL 這裡會是空字串
		Environment: m.Environment,        // []byte 會自動被 Marshal 成 JSON Object
		CreatedAt:   m.CreatedAt.Time,
		UpdatedAt:   m.UpdatedAt.Time,
	}
}

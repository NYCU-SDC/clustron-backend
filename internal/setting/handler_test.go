package setting_test

import (
	"bytes"
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/setting/mocks"
	"clustron-backend/internal/user/role"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

var exampleValidKey = "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQB/nAmOjTmezNUDKYvEeIRf2YnwM9/uUG1d0BYsc8/tRtx+RGi7N2lUbp728MXGwdnL9od4cItzky/zVdLZE2cycOa18xBK9cOWmcKS0A8FYBxEQWJ/q9YVUgZbFKfYGaGQxsER+A0w/fX8ALuk78ktP31K69LcQgxIsl7rNzxsoOQKJ/CIxOGMMxczYTiEoLvQhapFQMs3FL96didKr/QbrfB1WT6s3838SEaXfgZvLef1YB2xmfhbT9OXFE3FXvh2UPBfN+ffE7iiayQf/2XR+8j4N4bW30DiPtOQLGUrH1y5X/rpNZNlWW2+jGIxqZtgWg7lTy3mXy5x836Sj/6L"

func TestHandler_AddUserPublicKeyHandler(t *testing.T) {
	testCase := []struct {
		name           string
		body           setting.AddPublicKeyRequest
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Should add public key",
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: exampleValidKey,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when public key is invalid",
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: "MFswDQYJKoZIhvcNAQEBBQADSgAwR/",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when title is empty",
			body: setting.AddPublicKeyRequest{
				PublicKey: exampleValidKey,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when public key is empty",
			body: setting.AddPublicKeyRequest{
				Title: "Test Title",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	// Mock the dependencies
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	store := mocks.NewStore(t)
	store.On("AddPublicKey", mock.Anything, setting.CreatePublicKeyParams{
		UserID:    uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
		Title:     "Test Title",
		PublicKey: exampleValidKey,
	}).Return(setting.PublicKey{
		ID:        uuid.MustParse("33a40641-45bb-4b47-aa33-113c7c562328"),
		UserID:    uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
		Title:     "Test Title",
		PublicKey: exampleValidKey,
	}, nil)

	h := setting.NewHandler(logger, validator.New(), problem.New(), store)

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			requestBody, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/setting/publicKey", bytes.NewReader(requestBody))
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, jwt.User{
				ID:   uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
				Role: role.User.String(),
			}))

			w := httptest.NewRecorder()

			h.AddUserPublicKeyHandler(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_DeletePublicKeyHandler(t *testing.T) {
	publicKey := setting.PublicKey{
		ID:        uuid.MustParse("33a40641-45bb-4b47-aa33-113c7c562328"),
		UserID:    uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
		Title:     "Test Title",
		PublicKey: exampleValidKey,
	}

	testCase := []struct {
		name           string
		user           jwt.User
		body           setting.DeletePublicKeyRequest
		expectedStatus int
	}{
		{
			name: "Should delete public key",
			user: jwt.User{
				ID:   publicKey.UserID,
				Role: role.User.String(),
			},
			body: setting.DeletePublicKeyRequest{
				ID: publicKey.ID.String(),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return permission denied when user is not the owner of the public key",
			user: jwt.User{
				ID:   uuid.MustParse("8814749c-49db-451d-9c78-5118138a7612"),
				Role: role.User.String(),
			},
			body: setting.DeletePublicKeyRequest{
				ID: publicKey.ID.String(),
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	// Mock the dependencies
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	store := mocks.NewStore(t)
	store.On("GetPublicKeyByID", mock.Anything, publicKey.ID).Return(publicKey, nil)
	store.On("DeletePublicKey", mock.Anything, publicKey.ID).Return(nil)

	h := setting.NewHandler(logger, validator.New(), problem.New(), store)

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			requestBody, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			r := httptest.NewRequest(http.MethodDelete, "/api/setting/publicKey", bytes.NewReader(requestBody))
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
			w := httptest.NewRecorder()

			h.DeletePublicKeyHandler(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_UpdateUserSettingHandler(t *testing.T) {
	testCases := []struct {
		name           string
		body           setting.UpdateSettingRequest
		expectedStatus int
	}{
		{
			name: "Should update user setting",
			body: setting.UpdateSettingRequest{
				FullName:      "testuser",
				LinuxUsername: "testuser",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should update user setting without linux username",
			body: setting.UpdateSettingRequest{
				FullName: "testuser",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when fullName is empty",
			body: setting.UpdateSettingRequest{
				LinuxUsername: "testuser",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when linux username contain space",
			body: setting.UpdateSettingRequest{
				FullName:      "testuser",
				LinuxUsername: "test user",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	// Mock the dependencies
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	store := mocks.NewStore(t)
	store.On("UpdateSetting", mock.Anything, mock.Anything, mock.Anything).Return(setting.Setting{
		UserID:   uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
		FullName: pgtype.Text{String: "testuser", Valid: true},
	}, nil)
	store.On("GetSettingByUserID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(setting.Setting{
		UserID:        uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
		FullName:      pgtype.Text{String: "testuser", Valid: true},
		LinuxUsername: pgtype.Text{String: "testuser", Valid: true},
	}, nil)

	h := setting.NewHandler(logger, validator.New(), problem.New(), store)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestBody, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			r := httptest.NewRequest(http.MethodPut, "/api/setting", bytes.NewReader(requestBody))
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, jwt.User{
				ID:   uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
				Role: role.User.String(),
			}))
			w := httptest.NewRecorder()

			h.UpdateUserSettingHandler(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_OnboardingHandler(t *testing.T) {
	testCases := []struct {
		name           string
		body           setting.OnboardingRequest
		setupMock      func(store *mocks.Store)
		expectedStatus int
	}{
		{
			name: "Should complete onboarding",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "testuser",
			},
			setupMock: func(store *mocks.Store) {
				store.On("OnboardUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				store.On("IsLinuxUsernameExists", mock.Anything, "testuser").Return(false, nil).Once()
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should block linux username with reserved word",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "root",
			},
			setupMock: func(store *mocks.Store) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block linux username with over 32 characters",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "12345678901234567890123456789012345678901234567890",
			},
			setupMock: func(store *mocks.Store) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block linux username with space",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "test user",
			},
			setupMock: func(store *mocks.Store) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block linux username start with number",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "1testuser",
			},
			setupMock: func(store *mocks.Store) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block linux username start with hyphen",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "-testuser",
			},
			setupMock: func(store *mocks.Store) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block linux username contain ':'",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "test:user",
			},
			setupMock: func(store *mocks.Store) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block linux username contain '/'",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "test/user",
			},
			setupMock: func(store *mocks.Store) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block linux username contain uppercase letters",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "TestUser",
			},
			setupMock: func(store *mocks.Store) {
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock the dependencies
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)
			tc.setupMock(store)

			h := setting.NewHandler(logger, validator.New(), problem.NewWithMapping(internal.ErrorHandler), store)

			requestBody, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/setting/onboarding", bytes.NewReader(requestBody))
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, jwt.User{
				ID:   uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
				Role: role.User.String(),
			}))
			w := httptest.NewRecorder()

			h.OnboardingHandler(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

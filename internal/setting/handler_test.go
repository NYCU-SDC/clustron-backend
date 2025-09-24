package setting_test

import (
	"bytes"
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/setting/mocks"
	"clustron-backend/internal/user"
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
	testCases := []struct {
		name           string
		body           setting.AddPublicKeyRequest
		setupMock      func(store *mocks.Store)
		userInContext  *jwt.User
		customBody     []byte // for raw body (e.g. invalid JSON)
		expectedStatus int
	}{
		{
			name: "Should add public key",
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: exampleValidKey,
			},
			setupMock: func(store *mocks.Store) {
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
			},
			userInContext: &jwt.User{
				ID:   uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
				Role: role.User.String(),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when public key is invalid",
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: "MFswDQYJKoZIhvcNAQEBBQADSgAwR/",
			},
			setupMock:      func(store *mocks.Store) {},
			userInContext:  &jwt.User{ID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"), Role: role.User.String()},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when title is empty",
			body: setting.AddPublicKeyRequest{
				PublicKey: exampleValidKey,
			},
			setupMock:      func(store *mocks.Store) {},
			userInContext:  &jwt.User{ID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"), Role: role.User.String()},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when public key is empty",
			body: setting.AddPublicKeyRequest{
				Title: "Test Title",
			},
			setupMock:      func(store *mocks.Store) {},
			userInContext:  &jwt.User{ID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"), Role: role.User.String()},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when DB fails",
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: exampleValidKey,
			},
			setupMock: func(store *mocks.Store) {
				store.On("AddPublicKey", mock.Anything, mock.Anything).Return(setting.PublicKey{}, assert.AnError)
			},
			userInContext:  &jwt.User{ID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"), Role: role.User.String()},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Should return error when user is missing in context",
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: exampleValidKey,
			},
			setupMock:      func(store *mocks.Store) {},
			userInContext:  nil,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Should return error when request body is invalid JSON",
			customBody:     []byte(`{"title": "test", "publicKey": "abc",}`),
			setupMock:      func(store *mocks.Store) {},
			userInContext:  &jwt.User{ID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"), Role: role.User.String()},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)
			userStore := mocks.NewUserStore(t)
			if tc.setupMock != nil {
				tc.setupMock(store)
			}
			h := setting.NewHandler(logger, validator.New(), problem.NewWithMapping(internal.ErrorHandler), store, userStore)
			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("failed to marshal request body: %v", err)
				}
			}
			r := httptest.NewRequest(http.MethodPost, "/api/setting/publicKey", bytes.NewReader(requestBody))
			w := httptest.NewRecorder()
			if tc.userInContext != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.userInContext))
			}
			if tc.name == "Should return error when user is missing in context" {
				assert.Panics(t, func() {
					h.AddUserPublicKeyHandler(w, r)
				}, tc.name)
			} else {
				h.AddUserPublicKeyHandler(w, r)
				assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
			}
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

	testCases := []struct {
		name           string
		user           jwt.User
		body           setting.DeletePublicKeyRequest
		setupMock      func(store *mocks.Store)
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
			setupMock: func(store *mocks.Store) {
				store.On("GetPublicKeyByID", mock.Anything, publicKey.ID).Return(publicKey, nil)
				store.On("DeletePublicKey", mock.Anything, publicKey.ID).Return(nil)
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
			setupMock: func(store *mocks.Store) {
				store.On("GetPublicKeyByID", mock.Anything, publicKey.ID).Return(publicKey, nil)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "Should return error when DB fails on GetPublicKeyByID",
			user: jwt.User{
				ID:   publicKey.UserID,
				Role: role.User.String(),
			},
			body: setting.DeletePublicKeyRequest{
				ID: publicKey.ID.String(),
			},
			setupMock: func(store *mocks.Store) {
				store.On("GetPublicKeyByID", mock.Anything, publicKey.ID).Return(setting.PublicKey{}, assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Should return error when ID is not a valid UUID",
			user: jwt.User{
				ID:   publicKey.UserID,
				Role: role.User.String(),
			},
			body: setting.DeletePublicKeyRequest{
				ID: "not-a-uuid",
			},
			setupMock:      func(store *mocks.Store) {},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)
			userStore := mocks.NewUserStore(t)
			if tc.setupMock != nil {
				tc.setupMock(store)
			}
			h := setting.NewHandler(logger, validator.New(), problem.New(), store, userStore)
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
		setupMock      func(store *mocks.Store)
		expectedStatus int
	}{
		{
			name: "Should update user setting",
			body: setting.UpdateSettingRequest{
				FullName:      "testuser",
				LinuxUsername: "testuser",
			},
			setupMock: func(store *mocks.Store) {
				store.On("UpdateSetting", mock.Anything, mock.Anything, mock.Anything).Return(setting.Setting{
					UserID:   uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
					FullName: pgtype.Text{String: "testuser", Valid: true},
				}, nil)
				store.On("GetSettingByUserID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(setting.Setting{
					UserID:        uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
					FullName:      pgtype.Text{String: "testuser", Valid: true},
					LinuxUsername: pgtype.Text{String: "testuser", Valid: true},
				}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should update user setting without linux username",
			body: setting.UpdateSettingRequest{
				FullName: "testuser",
			},
			setupMock: func(store *mocks.Store) {
				store.On("UpdateSetting", mock.Anything, mock.Anything, mock.Anything).Return(setting.Setting{
					UserID:   uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
					FullName: pgtype.Text{String: "testuser", Valid: true},
				}, nil)
				store.On("GetSettingByUserID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(setting.Setting{
					UserID:        uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
					FullName:      pgtype.Text{String: "testuser", Valid: true},
					LinuxUsername: pgtype.Text{String: "testuser", Valid: true},
				}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when fullName is empty",
			body: setting.UpdateSettingRequest{
				LinuxUsername: "testuser",
			},
			setupMock: func(store *mocks.Store) {
				store.On("GetSettingByUserID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(setting.Setting{}, nil)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when linux username contain space",
			body: setting.UpdateSettingRequest{
				FullName:      "testuser",
				LinuxUsername: "test user",
			},
			setupMock: func(store *mocks.Store) {
				store.On("GetSettingByUserID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(setting.Setting{}, nil)
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)
			userStore := mocks.NewUserStore(t)
			if tc.setupMock != nil {
				tc.setupMock(store)
			}
			h := setting.NewHandler(logger, validator.New(), problem.New(), store, userStore)
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
		{
			name: "Should block empty linux username",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "",
			},
			setupMock:      func(store *mocks.Store) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block empty full name",
			body: setting.OnboardingRequest{
				FullName:      "",
				LinuxUsername: "testuser",
			},
			setupMock:      func(store *mocks.Store) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block linux username with only spaces",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "   ",
			},
			setupMock:      func(store *mocks.Store) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block full name with only spaces",
			body: setting.OnboardingRequest{
				FullName:      "   ",
				LinuxUsername: "testuser",
			},
			setupMock: func(store *mocks.Store) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should block if linux username already exists",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "existuser",
			},
			setupMock: func(store *mocks.Store) {
				store.On("IsLinuxUsernameExists", mock.Anything, "existuser").Return(true, nil).Once()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error if checking username existence fails",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "erroruser",
			},
			setupMock: func(store *mocks.Store) {
				store.On("IsLinuxUsernameExists", mock.Anything, "erroruser").Return(false, assert.AnError).Once()
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Should return error if onboarding fails",
			body: setting.OnboardingRequest{
				FullName:      "testuser",
				LinuxUsername: "failuser",
			},
			setupMock: func(store *mocks.Store) {
				store.On("IsLinuxUsernameExists", mock.Anything, "failuser").Return(false, nil).Once()
				store.On("OnboardUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
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

			userStore := mocks.NewUserStore(t)

			h := setting.NewHandler(logger, validator.New(), problem.NewWithMapping(internal.ErrorHandler), store, userStore)

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

func TestHandler_GetUserSettingHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, userStore *mocks.UserStore)
		userInContext  *jwt.User
		expectedStatus int
	}{
		{
			name: "Should return user setting",
			setupMock: func(store *mocks.Store, userStore *mocks.UserStore) {
				store.On("GetSettingByUserID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(setting.Setting{
					UserID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
				}, nil)
				userStore.On("ListLoginMethodsByID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return([]user.ListLoginMethodsRow{}, nil)
			},
			userInContext:  &jwt.User{ID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"), Role: role.User.String()},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when DB fails",
			setupMock: func(store *mocks.Store, userStore *mocks.UserStore) {
				store.On("GetSettingByUserID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(setting.Setting{}, assert.AnError)
			},
			userInContext:  &jwt.User{ID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"), Role: role.User.String()},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Should return error when user is missing in context",
			setupMock:      func(store *mocks.Store, userStore *mocks.UserStore) {},
			userInContext:  nil,
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := zap.NewDevelopment()
			store := mocks.NewStore(t)
			userStore := mocks.NewUserStore(t)
			if tc.setupMock != nil {
				tc.setupMock(store, userStore)
			}
			h := setting.NewHandler(logger, validator.New(), problem.New(), store, userStore)
			r := httptest.NewRequest(http.MethodGet, "/api/setting", nil)
			w := httptest.NewRecorder()
			if tc.userInContext != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.userInContext))
			}
			if tc.userInContext == nil {
				assert.Panics(t, func() {
					h.GetUserSettingHandler(w, r)
				}, tc.name)
			} else {
				h.GetUserSettingHandler(w, r)
				assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
			}
		})
	}
}

func TestHandler_GetUserPublicKeysHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store)
		userInContext  *jwt.User
		expectedStatus int
	}{
		{
			name: "Should return user public keys",
			setupMock: func(store *mocks.Store) {
				store.On("GetPublicKeysByUserID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return([]setting.PublicKey{}, nil)
			},
			userInContext:  &jwt.User{ID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"), Role: role.User.String()},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when DB fails",
			setupMock: func(store *mocks.Store) {
				store.On("GetPublicKeysByUserID", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(nil, assert.AnError)
			},
			userInContext:  &jwt.User{ID: uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"), Role: role.User.String()},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Should return error when user is missing in context",
			setupMock:      func(store *mocks.Store) {},
			userInContext:  nil,
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := zap.NewDevelopment()
			store := mocks.NewStore(t)
			userStore := mocks.NewUserStore(t)
			if tc.setupMock != nil {
				tc.setupMock(store)
			}
			h := setting.NewHandler(logger, validator.New(), problem.New(), store, userStore)
			r := httptest.NewRequest(http.MethodGet, "/api/setting/publicKey", nil)
			w := httptest.NewRecorder()
			if tc.userInContext != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.userInContext))
			}
			if tc.userInContext == nil {
				assert.Panics(t, func() {
					h.GetUserPublicKeysHandler(w, r)
				}, tc.name)
			} else {
				h.GetUserPublicKeysHandler(w, r)
				assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
			}
		})
	}
}

//func TestHandler_UpdateUserSettingHandler_DBErrorOnIsLinuxUsernameValid(t *testing.T) {
//	testCases := []struct {
//		name           string
//		setupMock      func(store *mocks.Store)
//		body           setting.UpdateSettingRequest
//		expectedStatus int
//	}{
//		{
//			name: "Should return 500 when IsLinuxUsernameValid returns DB error",
//			setupMock: func(store *mocks.Store) {
//				store.On("GetSettingByUserID", mock.Anything, mock.Anything).Return(setting.Setting{}, nil)
//				store.On("UpdateSetting", mock.Anything, mock.Anything, mock.Anything).Return(setting.Setting{}, nil)
//				store.On("IsLinuxUsernameExists", mock.Anything, "testuser").Return(false, assert.AnError)
//			},
//			body: setting.UpdateSettingRequest{
//				FullName:      "testuser",
//				LinuxUsername: "testuser",
//			},
//			expectedStatus: http.StatusInternalServerError,
//		},
//	}
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			logger, _ := zap.NewDevelopment()
//			store := mocks.NewStore(t)
//			userStore := mocks.NewUserStore(t)
//			if tc.setupMock != nil {
//				tc.setupMock(store)
//			}
//			h := setting.NewHandler(logger, validator.New(), problem.New(), store, userStore)
//			requestBody, _ := json.Marshal(tc.body)
//			r := httptest.NewRequest(http.MethodPut, "/api/setting", bytes.NewReader(requestBody))
//			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, jwt.User{
//				ID:   uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
//				Role: role.User.String(),
//			}))
//			w := httptest.NewRecorder()
//			h.UpdateUserSettingHandler(w, r)
//			assert.Equal(t, tc.expectedStatus, w.Code)
//		}
//	}
//}

package setting_test

import (
	"bytes"
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	ldaputil "clustron-backend/internal/ldap"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/setting/mocks"
	"clustron-backend/internal/user"
	"clustron-backend/internal/user/role"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

var exampleValidKey = "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQB/nAmOjTmezNUDKYvEeIRf2YnwM9/uUG1d0BYsc8/tRtx+RGi7N2lUbp728MXGwdnL9od4cItzky/zVdLZE2cycOa18xBK9cOWmcKS0A8FYBxEQWJ/q9YVUgZbFKfYGaGQxsER+A0w/fX8ALuk78ktP31K69LcQgxIsl7rNzxsoOQKJ/CIxOGMMxczYTiEoLvQhapFQMs3FL96didKr/QbrfB1WT6s3838SEaXfgZvLef1YB2xmfhbT9OXFE3FXvh2UPBfN+ffE7iiayQf/2XR+8j4N4bW30DiPtOQLGUrH1y5X/rpNZNlWW2+jGIxqZtgWg7lTy3mXy5x836Sj/6L title"

func TestHandler_AddUserPublicKeyHandler(t *testing.T) {
	testCases := []struct {
		name           string
		body           setting.AddPublicKeyRequest
		user           *jwt.User
		setupMock      func(store *mocks.Store, user *jwt.User)
		customBody     []byte // for raw body (e.g. invalid JSON)
		expectedStatus int
	}{
		{
			name: "Should add public key",
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: exampleValidKey,
			},
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock: func(store *mocks.Store, user *jwt.User) {
				store.On("AddPublicKey", mock.Anything,
					user.ID,
					exampleValidKey,
					"Test Title",
				).Return(setting.LDAPPublicKey{
					Fingerprint: "mock-fingerprint",
					Title:       "Test Title",
					PublicKey:   exampleValidKey,
				}, nil)
			},

			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when public key is invalid",
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: "MFswDQYJKoZIhvcNAQEBBQADSgAwR/",
			},
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock:      func(store *mocks.Store, user *jwt.User) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when title is empty",
			body: setting.AddPublicKeyRequest{
				PublicKey: exampleValidKey,
			},
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock:      func(store *mocks.Store, user *jwt.User) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when public key is empty",
			body: setting.AddPublicKeyRequest{
				Title: "Test Title",
			},
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock:      func(store *mocks.Store, user *jwt.User) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return error when public key already exists",
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: exampleValidKey,
			},
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock: func(store *mocks.Store, user *jwt.User) {
				store.On("AddPublicKey", mock.Anything,
					user.ID,
					exampleValidKey,
					"Test Title",
				).Return(setting.LDAPPublicKey{}, ldaputil.ErrPublicKeyExists)
			},
			expectedStatus: http.StatusConflict,
		},
		{
			name: "Should return error when user is missing in context",
			user: nil,
			body: setting.AddPublicKeyRequest{
				Title:     "Test Title",
				PublicKey: exampleValidKey,
			},
			setupMock:      func(store *mocks.Store, user *jwt.User) {},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:       "Should return error when request body is invalid JSON",
			customBody: []byte(`{"title": "test", "publicKey": "abc",}`),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock:      func(store *mocks.Store, user *jwt.User) {},
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
				tc.setupMock(store, tc.user)
			}
			h := setting.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, userStore)
			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("failed to marshal request body: %v", err)
				}
			}
			r := httptest.NewRequest(http.MethodPost, "/api/publickey", bytes.NewReader(requestBody))
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
				h.AddUserPublicKeyHandler(w, r)
				assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
			} else {
				assert.Panics(t, func() {
					h.AddUserPublicKeyHandler(w, r)
				}, tc.name)
			}
		})
	}
}

func TestHandler_DeletePublicKeyHandler(t *testing.T) {
	publicKey := setting.LDAPPublicKey{
		Fingerprint: "mock-fingerprint",
		Title:       "Test Title",
		PublicKey:   exampleValidKey,
	}

	testCases := []struct {
		name           string
		user           *jwt.User
		fingerprint    string
		setupMock      func(store *mocks.Store, user *jwt.User)
		expectedStatus int
	}{
		{
			name: "Should delete public key",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			fingerprint: "mock-fingerprint",
			setupMock: func(store *mocks.Store, user *jwt.User) {
				store.On("DeletePublicKey", mock.Anything, user.ID, publicKey.Fingerprint).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when fingerprint is empty",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			fingerprint:    "",
			setupMock:      func(store *mocks.Store, user *jwt.User) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Should return not found when LDAP user not found",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			fingerprint: "mock-fingerprint",
			setupMock: func(store *mocks.Store, user *jwt.User) {
				store.On("DeletePublicKey", mock.Anything,
					user.ID,
					publicKey.Fingerprint,
				).Return(ldaputil.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "Should return not found when fingerprint not found",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			fingerprint: "non-existing-fingerprint",
			setupMock: func(store *mocks.Store, user *jwt.User) {
				store.On("DeletePublicKey", mock.Anything, user.ID, mock.Anything).Return(ldaputil.ErrPublicKeyNotFound)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Should return error when user is missing in context",
			fingerprint:    "mock-fingerprint",
			user:           nil,
			setupMock:      func(store *mocks.Store, user *jwt.User) {},
			expectedStatus: http.StatusInternalServerError,
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
				tc.setupMock(store, tc.user)
			}
			h := setting.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, userStore)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			r := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/publickey/%s", tc.fingerprint), nil)
			r.SetPathValue("fingerprint", tc.fingerprint)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
				h.DeletePublicKeyHandler(w, r)
				assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
			} else {
				assert.Panics(t, func() {
					h.DeletePublicKeyHandler(w, r)
				}, tc.name)
			}
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
		user           *jwt.User
		setupMock      func(store *mocks.Store, userStore *mocks.UserStore, user *jwt.User)
		expectedStatus int
	}{
		{
			name: "Should return user setting",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock: func(store *mocks.Store, userStore *mocks.UserStore, jwtUser *jwt.User) {
				store.On("GetLDAPUserInfoByUserID", mock.Anything, jwtUser.ID).Return(setting.LDAPUserInfo{
					Username: "testuser",
					PublicKey: []string{
						"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..",
						"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB..",
					},
				}, nil)
				userStore.On("GetByID", mock.Anything, jwtUser.ID).Return(user.User{
					ID:       jwtUser.ID,
					Role:     role.User.String(),
					FullName: pgtype.Text{String: "Test User", Valid: true},
				}, nil)
				userStore.On("ListLoginMethodsByID", mock.Anything, jwtUser.ID).Return([]user.ListLoginMethodsRow{}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when DB fails",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock: func(store *mocks.Store, userStore *mocks.UserStore, jwtUser *jwt.User) {
				store.On("GetLDAPUserInfoByUserID", mock.Anything, jwtUser.ID).Return(setting.LDAPUserInfo{}, assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Should return error when user is missing in context",
			user:           nil,
			setupMock:      func(store *mocks.Store, userStore *mocks.UserStore, jwtUser *jwt.User) {},
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := zap.NewDevelopment()
			store := mocks.NewStore(t)
			userStore := mocks.NewUserStore(t)
			if tc.setupMock != nil {
				tc.setupMock(store, userStore, tc.user)
			}
			h := setting.NewHandler(logger, validator.New(), problem.New(), store, userStore)
			r := httptest.NewRequest(http.MethodGet, "/api/setting", nil)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
				h.GetUserSettingHandler(w, r)
				assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
			} else {
				assert.Panics(t, func() {
					h.GetUserSettingHandler(w, r)
				}, tc.name)
			}
		})
	}
}

func TestHandler_GetUserPublicKeysHandler(t *testing.T) {
	testCases := []struct {
		name           string
		user           *jwt.User
		setupMock      func(store *mocks.Store, user *jwt.User)
		expectedStatus int
	}{
		{
			name: "Should return user public keys",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock: func(store *mocks.Store, user *jwt.User) {
				store.On("GetPublicKeysByUserID", mock.Anything, user.ID).Return([]setting.LDAPPublicKey{}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Should return error when DB fails",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			setupMock: func(store *mocks.Store, user *jwt.User) {
				store.On("GetPublicKeysByUserID", mock.Anything, user.ID).Return(nil, assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Should return error when user is missing in context",
			user:           nil,
			setupMock:      func(store *mocks.Store, user *jwt.User) {},
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := zap.NewDevelopment()
			store := mocks.NewStore(t)
			userStore := mocks.NewUserStore(t)
			if tc.setupMock != nil {
				tc.setupMock(store, tc.user)
			}
			h := setting.NewHandler(logger, validator.New(), problem.New(), store, userStore)
			r := httptest.NewRequest(http.MethodGet, "/api/publickey", nil)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
				h.GetUserPublicKeysHandler(w, r)
				assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
			} else {
				assert.Panics(t, func() {
					h.GetUserPublicKeysHandler(w, r)
				}, tc.name)
			}
		})
	}
}

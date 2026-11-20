package slurm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"clustron-backend/internal"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSlurmHTTPClientWrapsUnavailableResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	_, err = (slurmHTTPClient{client: server.Client()}).Do(request)
	require.Error(t, err)
	require.True(t, errors.Is(err, internal.ErrSlurmUnavailable))
	require.EqualError(t, err, fmt.Sprintf("%s: slurm returned HTTP 503", internal.ErrSlurmUnavailable))
}

func TestSlurmHTTPClientPassesThroughClientErrors(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusUnprocessableEntity,
		http.StatusTooManyRequests,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			const body = `{"error":"request rejected"}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			require.NoError(t, err)

			response, err := (slurmHTTPClient{client: server.Client()}).Do(request)
			require.NoError(t, err)
			require.NotNil(t, response)
			defer func() {
				require.NoError(t, response.Body.Close())
			}()

			require.Equal(t, status, response.StatusCode)
			gotBody, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Equal(t, body, string(gotBody))
		})
	}
}

func TestProbe(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{name: "available", statusCode: http.StatusOK},
		{name: "unauthorized but available", statusCode: http.StatusUnauthorized},
		{name: "forbidden but available", statusCode: http.StatusForbidden},
		{name: "unavailable", statusCode: http.StatusServiceUnavailable, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/openapi/v3", r.URL.Path)
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			service := NewService(nil, Config{
				SlurmRestfulBaseURL: server.URL,
				SlurmRestfulVersion: "v0.0.44",
			}, nil, nil)

			err := service.Probe(t.Context())
			if tt.wantErr {
				require.ErrorIs(t, err, internal.ErrSlurmUnavailable)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (f httpDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestProbeUsesSharedClientWithTimeout(t *testing.T) {
	for _, shorterParentDeadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("shorter parent deadline=%t", shorterParentDeadline), func(t *testing.T) {
			ctx := t.Context()
			parentDeadline := time.Now().Add(time.Second)
			if shorterParentDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, parentDeadline)
				defer cancel()
			}

			service := NewService(zap.NewNop(), Config{SlurmRestfulBaseURL: "http://slurm.test"}, nil, nil)
			started := time.Now()
			var requestContext context.Context
			clientErr := internal.WrapSlurmUnavailable(errors.New("test client failure"))
			service.httpClient = httpDoerFunc(func(request *http.Request) (*http.Response, error) {
				requestContext = request.Context()
				deadline, ok := requestContext.Deadline()
				require.True(t, ok)
				if shorterParentDeadline {
					require.Equal(t, parentDeadline, deadline)
				} else {
					require.False(t, deadline.Before(started.Add(3*time.Second)))
					require.False(t, deadline.After(time.Now().Add(3*time.Second)))
				}
				return nil, clientErr
			})

			err := service.Probe(ctx)
			require.ErrorIs(t, err, clientErr)
			require.ErrorIs(t, err, internal.ErrSlurmUnavailable)
			require.NotNil(t, requestContext)
			require.ErrorIs(t, requestContext.Err(), context.Canceled)
		})
	}
}

type contextRoundTripper func(*http.Request) (*http.Response, error)

func (f contextRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestServiceRequestsPropagateContext(t *testing.T) {
	for _, operation := range []string{"probe", "delete user"} {
		for _, cancellation := range []string{"cancel", "deadline"} {
			t.Run(operation+"/"+cancellation, func(t *testing.T) {
				type contextKey struct{}
				parentDeadline := time.Now().Add(time.Minute)
				if cancellation == "deadline" {
					parentDeadline = time.Now().Add(20 * time.Millisecond)
				}
				ctx, cancel := context.WithDeadline(context.WithValue(t.Context(), contextKey{}, "request value"), parentDeadline)
				defer cancel()
				service := NewService(zap.NewNop(), Config{
					SlurmRestfulBaseURL: "http://slurm.test",
				}, nil, nil)
				called := false
				service.httpClient = slurmHTTPClient{client: &http.Client{
					Transport: contextRoundTripper(func(request *http.Request) (*http.Response, error) {
						called = true
						require.Equal(t, "request value", request.Context().Value(contextKey{}))
						deadline, ok := request.Context().Deadline()
						require.True(t, ok)
						if operation == "delete user" || cancellation == "deadline" {
							require.Equal(t, parentDeadline, deadline)
						}
						if cancellation == "cancel" {
							cancel()
						}
						select {
						case <-request.Context().Done():
						case <-time.After(time.Second):
							t.Fatal("request context did not receive parent cancellation")
						}
						return nil, request.Context().Err()
					}),
				}}

				var err error
				if operation == "probe" {
					err = service.Probe(ctx)
				} else {
					err = service.DeleteUser(ctx, "test-user")
				}
				require.True(t, called)
				require.ErrorIs(t, err, internal.ErrSlurmUnavailable)
				if cancellation == "cancel" {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
			})
		}
	}
}

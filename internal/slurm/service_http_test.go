package slurm

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"clustron-backend/internal"

	"github.com/stretchr/testify/require"
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

func TestProbe(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{name: "available", statusCode: http.StatusOK},
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

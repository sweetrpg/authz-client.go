package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sweetrpg/common.go/logging"
)

func TestMain(m *testing.M) {
	logging.Init()
	os.Exit(m.Run())
}

func TestClientCheck_allowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/authz/check" {
			t.Errorf("path = %s, want /authz/check", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer good-token" {
			t.Errorf("authorization = %q, want %q", got, "Bearer good-token")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":true,"roles":["editor","admin"],"sub":"auth0|abc123"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	resp, err := client.Check(context.Background(), "good-token", "catalog-api")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !resp.Allowed {
		t.Errorf("Allowed = false, want true")
	}
	if len(resp.Roles) != 2 || resp.Roles[0] != "editor" || resp.Roles[1] != "admin" {
		t.Errorf("Roles = %v, want [editor admin]", resp.Roles)
	}
	if resp.Sub != "auth0|abc123" {
		t.Errorf("Sub = %q, want auth0|abc123", resp.Sub)
	}
}

func TestClientCheck_denied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":false,"sub":"auth0|abc123","reason":"not_in_role"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	resp, err := client.Check(context.Background(), "good-token", "catalog-api")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if resp.Allowed {
		t.Errorf("Allowed = true, want false")
	}
	if resp.Reason != "not_in_role" {
		t.Errorf("Reason = %q, want not_in_role", resp.Reason)
	}
}

func TestClientCheck_invalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	_, err := client.Check(context.Background(), "bad-token", "catalog-api")
	if !errors.Is(err, InvalidTokenError{}) {
		t.Errorf("Check() error = %v, want InvalidTokenError", err)
	}
}

func TestClientCheck_transportError(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "")
	_, err := client.Check(context.Background(), "good-token", "catalog-api")
	if err == nil {
		t.Errorf("Check() error = nil, want transport error")
	}
	if errors.Is(err, InvalidTokenError{}) {
		t.Errorf("Check() error = %v, want non-InvalidTokenError", err)
	}
}

func TestClientCheck_non200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	_, err := client.Check(context.Background(), "good-token", "catalog-api")
	if err == nil {
		t.Errorf("Check() error = nil, want status error")
	}
}

func TestClientResolveUserID_happy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/profile" {
			t.Errorf("path = %s, want /profile", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer good-token" {
			t.Errorf("authorization = %q, want %q", got, "Bearer good-token")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user_id":"64b2d9f1c4a3e2d1a5b6c7d8"}`))
	}))
	defer server.Close()

	client := NewClient("", server.URL)
	got := client.ResolveUserID(context.Background(), "good-token")
	if got != "64b2d9f1c4a3e2d1a5b6c7d8" {
		t.Errorf("ResolveUserID() = %q, want canonical user id", got)
	}
}

func TestClientResolveUserID_noProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient("", server.URL)
	if got := client.ResolveUserID(context.Background(), "good-token"); got != "" {
		t.Errorf("ResolveUserID() = %q, want empty on 404", got)
	}
}

func TestClientResolveUserID_invalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("", server.URL)
	if got := client.ResolveUserID(context.Background(), "bad-token"); got != "" {
		t.Errorf("ResolveUserID() = %q, want empty on 401", got)
	}
}

func TestClientResolveUserID_backendError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient("", server.URL)
	if got := client.ResolveUserID(context.Background(), "good-token"); got != "" {
		t.Errorf("ResolveUserID() = %q, want empty on 500", got)
	}
}

func TestClientResolveUserID_transportError(t *testing.T) {
	client := NewClient("", "http://127.0.0.1:1")
	if got := client.ResolveUserID(context.Background(), "good-token"); got != "" {
		t.Errorf("ResolveUserID() = %q, want empty on transport error", got)
	}
}

func TestClientResolveUserID_emptyToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("request sent with empty token")
	}))
	defer server.Close()

	client := NewClient("", server.URL)
	if got := client.ResolveUserID(context.Background(), ""); got != "" {
		t.Errorf("ResolveUserID() = %q, want empty for empty token", got)
	}
}

func TestClientResolveUserID_noUsersURL(t *testing.T) {
	client := NewClient("", "")
	if got := client.ResolveUserID(context.Background(), "good-token"); got != "" {
		t.Errorf("ResolveUserID() = %q, want empty when users URL unset", got)
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient("http://auth.example", "http://users.example")
	if client.baseURL != "http://auth.example" {
		t.Errorf("baseURL = %q, want http://auth.example", client.baseURL)
	}
	if client.usersBaseURL != "http://users.example" {
		t.Errorf("usersBaseURL = %q, want http://users.example", client.usersBaseURL)
	}
	if client.http == nil {
		t.Errorf("http client not initialized")
	}
	if client.http.Timeout == 0 {
		t.Errorf("http client timeout not set")
	}
}

func TestHasRole(t *testing.T) {
	roles := []string{"user", "editor"}
	if !HasRole(roles, "editor") {
		t.Errorf("HasRole([user editor], editor) = false, want true")
	}
	if HasRole(roles, "admin") {
		t.Errorf("HasRole([user editor], admin) = true, want false")
	}
	if HasRole(nil, "user") {
		t.Errorf("HasRole(nil, user) = true, want false")
	}
}

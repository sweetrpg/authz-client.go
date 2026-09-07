package authz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	apiv "github.com/sweetrpg/api-core.go/vo"
)

func newTestRouter(client *Client, middlewares ...gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/test")
	for _, mw := range middlewares {
		rg.Use(mw)
	}
	rg.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func performRequest(r *gin.Engine, authHeader string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	r.ServeHTTP(w, req)
	return w
}

func TestRequireAnyRole_missingToken(t *testing.T) {
	client := NewClient("", "")
	r := newTestRouter(client, RequireAnyRole(client, "catalog-api", RoleEditor))

	w := performRequest(r, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	var body apiv.ErrorVO
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != "invalid_token" {
		t.Errorf("error = %q, want invalid_token", body.Error)
	}
}

func TestRequireAnyRole_invalidToken(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer auth.Close()
	client := NewClient(auth.URL, "")
	r := newTestRouter(client, RequireAnyRole(client, "catalog-api", RoleEditor))

	w := performRequest(r, "Bearer bad-token")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAnyRole_authUnavailable(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "")
	r := newTestRouter(client, RequireAnyRole(client, "catalog-api", RoleEditor))

	w := performRequest(r, "Bearer good-token")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	var body apiv.ErrorVO
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != "authz_unavailable" {
		t.Errorf("error = %q, want authz_unavailable", body.Error)
	}
}

func TestRequireAnyRole_denied(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":false,"sub":"auth0|abc","reason":"not_in_role"}`))
	}))
	defer auth.Close()
	client := NewClient(auth.URL, "")
	r := newTestRouter(client, RequireAnyRole(client, "catalog-api", RoleEditor))

	w := performRequest(r, "Bearer good-token")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireAnyRole_wrongRole(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":true,"roles":["user"],"sub":"auth0|abc"}`))
	}))
	defer auth.Close()
	client := NewClient(auth.URL, "")
	r := newTestRouter(client, RequireAnyRole(client, "catalog-api", RoleEditor))

	w := performRequest(r, "Bearer good-token")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// newRequireAnyRoleStub serves both /authz/check (role verification) and /profile (canonical
// user resolution) from one server so RequireAnyRole tests can exercise the full middleware.
func newRequireAnyRoleStub(t *testing.T, checkBody, userID string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/authz/check":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(checkBody))
		case r.Method == http.MethodGet && r.URL.Path == "/profile":
			if userID == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"user_id":%q}`, userID)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRequireAnyRole_allowed(t *testing.T) {
	auth := newRequireAnyRoleStub(t, `{"allowed":true,"roles":["editor","admin"],"sub":"auth0|editor-1"}`, "64b2d9f1c4a3e2d1a5b6c7d8")
	defer auth.Close()
	client := NewClient(auth.URL, auth.URL)

	var gotRoles []string
	var gotSub string
	var gotToken string
	var gotViewer string

	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/test")
	rg.Use(RequireAnyRole(client, "catalog-api", RoleEditor, RoleAdmin))
	rg.GET("/", func(c *gin.Context) {
		gotRoles = Roles(c)
		gotSub = Subject(c)
		gotToken = Token(c)
		gotViewer = Viewer(c)
		c.String(http.StatusOK, "ok")
	})

	w := performRequest(r, "Bearer good-token")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if len(gotRoles) != 2 || gotRoles[0] != "editor" || gotRoles[1] != "admin" {
		t.Errorf("Roles(c) = %v, want [editor admin]", gotRoles)
	}
	if gotSub != "auth0|editor-1" {
		t.Errorf("Subject(c) = %q, want auth0|editor-1", gotSub)
	}
	if gotToken != "good-token" {
		t.Errorf("Token(c) = %q, want good-token", gotToken)
	}
	if gotViewer != "64b2d9f1c4a3e2d1a5b6c7d8" {
		t.Errorf("Viewer(c) = %q, want resolved canonical user id", gotViewer)
	}
}

func TestRequireAnyRole_multipleRoles(t *testing.T) {
	auth := newRequireAnyRoleStub(t, `{"allowed":true,"roles":["submitter"],"sub":"auth0|sub"}`, "64b2d9f1c4a3e2d1a5b6c7d8")
	defer auth.Close()
	client := NewClient(auth.URL, auth.URL)
	r := newTestRouter(client, RequireAnyRole(client, "catalog-api", RoleModerator, RoleSubmitter))

	w := performRequest(r, "Bearer good-token")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for submitter among [moderator submitter]", w.Code)
	}
}

func TestRequireAnyRole_viewerUnresolvable(t *testing.T) {
	auth := newRequireAnyRoleStub(t, `{"allowed":true,"roles":["editor"],"sub":"auth0|editor-1"}`, "")
	defer auth.Close()
	client := NewClient(auth.URL, auth.URL)
	r := newTestRouter(client, RequireAnyRole(client, "catalog-api", RoleEditor))

	w := performRequest(r, "Bearer good-token")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when subject has no profile", w.Code)
	}
	var body apiv.ErrorVO
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != "user_resolution_unavailable" {
		t.Errorf("error = %q, want user_resolution_unavailable", body.Error)
	}
}

func TestRequireAnyRole_usersURLUnset(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authz/check" {
			t.Errorf("path = %s, want /authz/check", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":true,"roles":["editor"],"sub":"auth0|editor-1"}`))
	}))
	defer auth.Close()
	client := NewClient(auth.URL, "")
	r := newTestRouter(client, RequireAnyRole(client, "catalog-api", RoleEditor))

	w := performRequest(r, "Bearer good-token")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when users-api URL is unset", w.Code)
	}
}

func TestResolveViewer_missingToken(t *testing.T) {
	client := NewClient("", "")
	r := newTestRouter(client, ResolveViewer(client, "game-room-api"))

	w := performRequest(r, "")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestResolveViewer_validToken(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":true,"roles":["user"],"sub":"auth0|abc123"}`))
	}))
	defer auth.Close()
	users := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile" {
			t.Errorf("path = %s, want /profile", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user_id":"64b2d9f1c4a3e2d1a5b6c7d8"}`))
	}))
	defer users.Close()
	client := NewClient(auth.URL, users.URL)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/test")
	rg.Use(ResolveViewer(client, "game-room-api"))
	rg.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, Viewer(c))
	})

	w := performRequest(r, "Bearer good-token")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "64b2d9f1c4a3e2d1a5b6c7d8" {
		t.Errorf("Viewer(c) = %q, want canonical user id", w.Body.String())
	}
}

func TestResolveViewer_noProfile(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":true,"roles":["user"],"sub":"auth0|abc123"}`))
	}))
	defer auth.Close()
	users := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer users.Close()
	client := NewClient(auth.URL, users.URL)

	r := newTestRouter(client, ResolveViewer(client, "game-room-api"))
	w := performRequest(r, "Bearer good-token")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (anonymous viewer)", w.Code)
	}
}

func TestResolveViewer_invalidToken(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer auth.Close()
	client := NewClient(auth.URL, "")
	r := newTestRouter(client, ResolveViewer(client, "game-room-api"))

	w := performRequest(r, "Bearer bad-token")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (anonymous viewer on invalid token)", w.Code)
	}
}

func TestRequireOwner_ownsResource(t *testing.T) {
	userId := "64b2d9f1c4a3e2d1a5b6c7d8"
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/users/:user_id/rooms")
	rg.Use(
		func(c *gin.Context) { c.Set(viewerContextKey, userId) },
		RequireOwner(),
	)
	rg.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "owned")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/users/"+userId+"/rooms/", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRequireOwner_mismatchedViewer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/users/:user_id/rooms")
	rg.Use(
		func(c *gin.Context) { c.Set(viewerContextKey, "someone-else") },
		RequireOwner(),
	)
	rg.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "owned")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/users/64b2d9f1c4a3e2d1a5b6c7d8/rooms/", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for mismatched owner", w.Code)
	}
}

func TestRequireOwner_anonymousViewer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/users/:user_id/rooms")
	rg.Use(
		func(c *gin.Context) { c.Set(viewerContextKey, "") },
		RequireOwner(),
	)
	rg.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "owned")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/users/64b2d9f1c4a3e2d1a5b6c7d8/rooms/", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for anonymous viewer", w.Code)
	}
}

func TestViewer_absent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := Viewer(c); got != "" {
		t.Errorf("Viewer(c) = %q, want empty when unset", got)
	}
}

func TestRoles_absent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := Roles(c); got != nil {
		t.Errorf("Roles(c) = %v, want nil when unset", got)
	}
}

func TestSubject_absent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := Subject(c); got != "" {
		t.Errorf("Subject(c) = %q, want empty when unset", got)
	}
}

func TestToken_absent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := Token(c); got != "" {
		t.Errorf("Token(c) = %q, want empty when unset", got)
	}
}

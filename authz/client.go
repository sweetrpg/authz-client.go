// Package authz is the shared identity-resolution and authorization client for SweetRPG's Go
// APIs. It verifies a caller's bearer token against auth-api's POST /authz/check (returning
// their roles, subject, and allow/deny decision), resolves the subject to the caller's
// canonical users._id via users-api's GET /profile, and provides gin middleware that stashes
// the resolved identity in the request context.
//
// The package merges what were previously the local authz packages in game-room-api (identity
// resolution for owner-scoped, anonymous-friendly reads) and catalog-api (fail-closed role
// gating for admin/moderation routes).
package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sweetrpg/common.go/logging"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Platform role names, matching auth-api's fixed role model exactly (see
// openspec/specs/user-authorization/spec.md's "Role model" requirement).
const (
	RoleUser      = "user"
	RoleSubmitter = "submitter"
	RoleEditor    = "editor"
	RoleModerator = "moderator"
	RoleApprover  = "approver"
	RoleAdmin     = "admin"
)

// CheckResponse is the union of auth-api's allowed/denied /authz/check response shapes.
type CheckResponse struct {
	Allowed bool     `json:"allowed"`
	Roles   []string `json:"roles"`
	Sub     string   `json:"sub"`
	Reason  string   `json:"reason"`
}

// InvalidTokenError means auth-api rejected the bearer token itself (missing, expired,
// unverifiable) - distinct from a service-level deny (Allowed: false with a Reason) or a
// transport/backend failure.
type InvalidTokenError struct{}

func (InvalidTokenError) Error() string { return "authz: invalid or missing token" }

// Client calls auth-api's /authz/check endpoint and users-api's /profile endpoint.
type Client struct {
	baseURL      string
	usersBaseURL string
	http         *http.Client
}

// NewClient builds a Client against auth-api's base URL and users-api's base URL. authBaseURL
// drives identity verification (roles + subject); usersBaseURL resolves that subject to the
// canonical users._id user ID. Either may be empty so the service can still start when the
// corresponding URL env var isn't configured - a missing URL makes the relevant call fail,
// which ResolveViewer treats as anonymous and RequireAnyRole surfaces as a 503.
func NewClient(authBaseURL, usersBaseURL string) *Client {
	return &Client{
		baseURL:      authBaseURL,
		usersBaseURL: usersBaseURL,
		http: &http.Client{
			Timeout:   5 * time.Second,
			Transport: otelhttp.NewTransport(http.DefaultTransport),
		},
	}
}

// Check verifies token against auth-api and returns the caller's allowed/roles/subject for the
// given service name. Returns InvalidTokenError if auth-api rejects the token itself.
func (c *Client) Check(ctx context.Context, token, service string) (*CheckResponse, error) {
	body, err := json.Marshal(map[string]string{"service": service})
	if err != nil {
		return nil, fmt.Errorf("authz: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/authz/check", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("authz: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authz: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, InvalidTokenError{}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authz: unexpected status %d from auth-api", resp.StatusCode)
	}

	var out CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("authz: decode response: %w", err)
	}

	logging.Logger.Debug("authz check", "service", service, "allowed", out.Allowed, "sub", out.Sub)
	return &out, nil
}

// profileResponse is the slice of users-api's /profile response the client reads.
type profileResponse struct {
	UserID string `json:"user_id"`
}

// ResolveUserID exchanges a verified bearer token for the caller's canonical users._id user ID
// by calling users-api's /profile. It returns "" when the token is missing, the user has no
// provisioned profile (HTTP 404), auth-api rejects the token (HTTP 401), or users-api is
// unavailable - all of which ResolveViewer treats as an unprovisioned/anonymous viewer.
func (c *Client) ResolveUserID(ctx context.Context, token string) string {
	if c.usersBaseURL == "" || token == "" {
		return ""
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.usersBaseURL+"/profile", nil)
	if err != nil {
		logging.Logger.Debug("users-api resolve: build request", "error", err.Error())
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		logging.Logger.Debug("users-api resolve: request failed", "error", err.Error())
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
		return ""
	}
	if resp.StatusCode != http.StatusOK {
		logging.Logger.Debug("users-api resolve: unexpected status", "status", resp.StatusCode)
		return ""
	}

	var out profileResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		logging.Logger.Debug("users-api resolve: decode response", "error", err.Error())
		return ""
	}
	return out.UserID
}

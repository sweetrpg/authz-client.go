package authz

import (
	"net/http"

	"github.com/gin-gonic/gin"
	apiv "github.com/sweetrpg/api-core.go/vo"
	"github.com/sweetrpg/common.go/logging"
)

// Gin context keys set by RequireAnyRole / ResolveViewer; read via Roles/Subject/Token/Viewer.
const (
	rolesContextKey   = "authz.roles"
	subjectContextKey = "authz.subject"
	tokenContextKey   = "authz.token"
	viewerContextKey  = "authz.viewer"
)

// RequireAnyRole returns gin middleware that verifies the caller's bearer token against
// auth-api's /authz/check for the given service name, then requires the caller hold at least
// one of allowedRoles. On success, the verified roles and subject are stashed in the gin
// context (read via Roles(c) / Subject(c)) for the handler to use.
func RequireAnyRole(client *Client, service string, allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c)
		if token == "" {
			unauthorized(c)
			return
		}

		result, err := client.Check(c.Request.Context(), token, service)
		if err != nil {
			if _, ok := err.(InvalidTokenError); ok {
				unauthorized(c)
				return
			}
			logging.Logger.Error("authz check failed", "error", err.Error())
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, apiv.ErrorVO{
				Error:   "authz_unavailable",
				Message: "Unable to verify authorization",
			})
			return
		}

		if !result.Allowed {
			forbidden(c)
			return
		}

		if !hasAnyRole(result.Roles, allowedRoles) {
			forbidden(c)
			return
		}

		c.Set(rolesContextKey, result.Roles)
		c.Set(subjectContextKey, result.Sub)
		c.Set(tokenContextKey, token)
		c.Next()
	}
}

// ResolveViewer returns gin middleware that resolves the caller's identity from a bearer token,
// when present, and stashes it in the gin context (read via Viewer(c)) for handlers to use in
// visibility filtering and ownership checks. A missing token, one auth-api rejects, or a subject
// with no provisioned user profile resolves to an anonymous viewer ("") rather than aborting the
// request - reads must stay accessible to anonymous callers for anything public.
//
// The viewer identity stored in the context is the caller's canonical users._id user ID.
// Resolving it requires a users-api round trip for authenticated callers; an unresolvable
// subject yields "" so owner-scoped writes are rejected.
func ResolveViewer(client *Client, service string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c)
		if token == "" {
			c.Set(viewerContextKey, "")
			c.Next()
			return
		}

		result, err := client.Check(c.Request.Context(), token, service)
		if err != nil {
			logging.Logger.Debug("authz check failed, treating caller as anonymous", "error", err.Error())
			c.Set(viewerContextKey, "")
			c.Next()
			return
		}

		userID := client.ResolveUserID(c.Request.Context(), token)
		if userID == "" {
			logging.Logger.Debug("subject has no provisioned user, treating caller as anonymous", "sub", result.Sub)
		}
		c.Set(viewerContextKey, userID)
		c.Next()
	}
}

// Viewer returns the caller's canonical users._id user ID, or "" for an anonymous viewer.
func Viewer(c *gin.Context) string {
	if v, ok := c.Get(viewerContextKey); ok {
		if sub, ok := v.(string); ok {
			return sub
		}
	}
	return ""
}

// RequireOwner aborts with 403 unless the resolved viewer matches the :user_id path param -
// every Game Room write endpoint is scoped to the caller's own collection.
func RequireOwner() gin.HandlerFunc {
	return func(c *gin.Context) {
		viewer := Viewer(c)
		if viewer == "" || viewer != c.Param("user_id") {
			c.AbortWithStatusJSON(http.StatusForbidden, apiv.ErrorVO{
				Error:   "forbidden",
				Message: "Caller does not own this resource",
			})
			return
		}
		c.Next()
	}
}

// Roles returns the verified roles stashed in the gin context by RequireAnyRole.
func Roles(c *gin.Context) []string {
	if v, ok := c.Get(rolesContextKey); ok {
		if roles, ok := v.([]string); ok {
			return roles
		}
	}
	return nil
}

// Subject returns the verified Auth0 subject stashed in the gin context by RequireAnyRole.
func Subject(c *gin.Context) string {
	if v, ok := c.Get(subjectContextKey); ok {
		if sub, ok := v.(string); ok {
			return sub
		}
	}
	return ""
}

// Token returns the caller's verified bearer token stashed in the gin context by
// RequireAnyRole - forwarded onward when this service calls another one on the user's behalf
// (e.g. assets-web's asset store), so downstream services authorize the same user.
func Token(c *gin.Context) string {
	if v, ok := c.Get(tokenContextKey); ok {
		if token, ok := v.(string); ok {
			return token
		}
	}
	return ""
}

// HasRole reports whether roles contains want.
func HasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func hasAnyRole(have []string, want []string) bool {
	for _, w := range want {
		if HasRole(have, w) {
			return true
		}
	}
	return false
}

func bearerToken(c *gin.Context) string {
	const prefix = "Bearer "
	auth := c.GetHeader("Authorization")
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		return ""
	}
	return auth[len(prefix):]
}

func unauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, apiv.ErrorVO{
		Error:   "invalid_token",
		Message: "Missing or invalid bearer token",
	})
}

func forbidden(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, apiv.ErrorVO{
		Error:   "forbidden",
		Message: "Caller does not have a qualifying role",
	})
}

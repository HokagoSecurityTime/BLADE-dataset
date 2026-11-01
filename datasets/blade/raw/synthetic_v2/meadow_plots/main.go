package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type Principal struct{ ID, TenantID, Role string }
type Record struct{ ID, OwnerID, TenantID, GroupID, Value string }
type memberKey struct{ UserID, GroupID string }

var principals = map[string]Principal{"alice": {"alice", "north", "user"}, "bob": {"bob", "south", "user"}, "admin": {"root", "north", "admin"}}
var objects = map[string]Record{"1": {"1", "alice", "north", "g_north_hikers", "fixture secret"}, "2": {"2", "bob", "south", "g_south_riders", "other secret"}}
var memberships = map[memberKey]bool{{"alice", "g_north_hikers"}: true, {"bob", "g_south_riders"}: true}

// authRequired: authentication only (401). It performs no authorization.
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := principals[strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")]
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("principal", p)
		c.Next()
	}
}

// requireRole: role check as route middleware (403).
func requireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.MustGet("principal").(Principal).Role != role {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// Intentionally anonymous reference catalogue.
func meadow_plots_catalogue_0(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// Intentionally anonymous reference catalogue.
func meadow_plots_catalogue_1(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// Only the record owner may read it.
func meadow_plots_drafts_0(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	p := c.MustGet("principal").(Principal)
	if p.ID != obj.OwnerID {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// Only the record owner may read it.
func meadow_plots_drafts_1(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// Deliberate fixture: object authorization check omitted.
	c.JSON(http.StatusOK, obj)
}

// The record owner or an administrator may read it.
func meadow_plots_shared_0(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	p := c.MustGet("principal").(Principal)
	if p.ID != obj.OwnerID && p.Role != "admin" {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// The record owner or an administrator may read it.
func meadow_plots_shared_1(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// Deliberate fixture: object authorization check omitted.
	c.JSON(http.StatusOK, obj)
}

// The record owner or an administrator may read it.
func meadow_plots_moderation_0(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	p := c.MustGet("principal").(Principal)
	if p.ID != obj.OwnerID && p.Role != "admin" {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// The record owner or an administrator may read it.
func meadow_plots_moderation_1(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// Deliberate fixture: object authorization check omitted.
	c.JSON(http.StatusOK, obj)
}

// Caller and record must share a tenant.
func meadow_plots_workspace_0(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	p := c.MustGet("principal").(Principal)
	if p.TenantID != obj.TenantID {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// Caller and record must share a tenant.
func meadow_plots_workspace_1(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// Deliberate fixture: object authorization check omitted.
	c.JSON(http.StatusOK, obj)
}

// Only administrators may read this operational resource.
func meadow_plots_audit_0(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// Only administrators may read this operational resource.
func meadow_plots_audit_1(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// Deliberate fixture: object authorization check omitted.
	c.JSON(http.StatusOK, obj)
}

// Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.
func meadow_plots_roster_0(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	p := c.MustGet("principal").(Principal)
	if !memberships[memberKey{p.ID, obj.GroupID}] {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.
func meadow_plots_roster_1(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// Deliberate fixture: object authorization check omitted.
	c.JSON(http.StatusOK, obj)
}

// Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.
func meadow_plots_pins_0(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	p := c.MustGet("principal").(Principal)
	if !memberships[memberKey{p.ID, obj.GroupID}] {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.
func meadow_plots_pins_1(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// Deliberate fixture: object authorization check omitted.
	c.JSON(http.StatusOK, obj)
}

// Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review.
func meadow_plots_council_0(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	p := c.MustGet("principal").(Principal)
	if p.TenantID != obj.TenantID || !memberships[memberKey{p.ID, obj.GroupID}] {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, obj)
}

// Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review.
func meadow_plots_council_1(c *gin.Context) {
	obj, ok := objects[c.Param("item_id")]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	p := c.MustGet("principal").(Principal)
	if p.TenantID != obj.TenantID || !memberships[memberKey{p.ID, obj.GroupID}] {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, obj)
}

func main() {
	r := gin.Default()
	authed := r.Group("/", authRequired())
	r.GET("/fixtures/meadow_plots/plots/catalogue/current/:item_id", meadow_plots_catalogue_0)
	r.GET("/fixtures/meadow_plots/plots/catalogue/archive/:item_id", meadow_plots_catalogue_1)
	authed.GET("/fixtures/meadow_plots/plots/drafts/current/:item_id", meadow_plots_drafts_0)
	authed.GET("/fixtures/meadow_plots/plots/drafts/archive/:item_id", meadow_plots_drafts_1)
	authed.GET("/fixtures/meadow_plots/plots/shared/current/:item_id", meadow_plots_shared_0)
	authed.GET("/fixtures/meadow_plots/plots/shared/archive/:item_id", meadow_plots_shared_1)
	authed.GET("/fixtures/meadow_plots/plots/moderation/current/:item_id", meadow_plots_moderation_0)
	authed.GET("/fixtures/meadow_plots/plots/moderation/archive/:item_id", meadow_plots_moderation_1)
	authed.GET("/fixtures/meadow_plots/plots/workspace/current/:item_id", meadow_plots_workspace_0)
	authed.GET("/fixtures/meadow_plots/plots/workspace/archive/:item_id", meadow_plots_workspace_1)
	authed.GET("/fixtures/meadow_plots/plots/audit/current/:item_id", requireRole("admin"), meadow_plots_audit_0)
	authed.GET("/fixtures/meadow_plots/plots/audit/archive/:item_id", meadow_plots_audit_1)
	authed.GET("/fixtures/meadow_plots/plots/roster/current/:item_id", meadow_plots_roster_0)
	authed.GET("/fixtures/meadow_plots/plots/roster/archive/:item_id", meadow_plots_roster_1)
	authed.GET("/fixtures/meadow_plots/plots/pins/current/:item_id", meadow_plots_pins_0)
	authed.GET("/fixtures/meadow_plots/plots/pins/archive/:item_id", meadow_plots_pins_1)
	authed.GET("/fixtures/meadow_plots/plots/council/current/:item_id", meadow_plots_council_0)
	authed.GET("/fixtures/meadow_plots/plots/council/archive/:item_id", meadow_plots_council_1)
	r.Run(":8080")
}

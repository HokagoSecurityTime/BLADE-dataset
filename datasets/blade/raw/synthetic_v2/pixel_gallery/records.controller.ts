import { Controller, Get, Param, Req, UseGuards, NotFoundException, ForbiddenException } from "@nestjs/common";
import { AuthGuard, RolesGuard, Roles } from "./guards";
const OBJECTS: Record<string, any> = { "1": { id: "1", ownerId: "alice", tenantId: "north", groupId: "g_north_hikers", value: "fixture secret" }, "2": { id: "2", ownerId: "bob", tenantId: "south", groupId: "g_south_riders", value: "other secret" } };
const MEMBERSHIPS = new Set(["alice:g_north_hikers", "bob:g_south_riders"]);
const isMember = (userId: string, groupId: string) => MEMBERSHIPS.has(`${userId}:${groupId}`);

@Controller()
export class RecordsController {
  /** Intentionally anonymous reference catalogue. */
  @Get("/fixtures/pixel_gallery/artworks/catalogue/current/:itemId")
  pixel_gallery_catalogue_0(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    return obj;
  }

  /** Intentionally anonymous reference catalogue. */
  @Get("/fixtures/pixel_gallery/artworks/catalogue/archive/:itemId")
  pixel_gallery_catalogue_1(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    return obj;
  }

  /** Only the record owner may read it. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/drafts/current/:itemId")
  pixel_gallery_drafts_0(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    if (principal.id !== obj.ownerId) throw new ForbiddenException();
    return obj;
  }

  /** Only the record owner may read it. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/drafts/archive/:itemId")
  pixel_gallery_drafts_1(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    // Deliberate fixture: object authorization check omitted.
    return obj;
  }

  /** The record owner or an administrator may read it. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/shared/current/:itemId")
  pixel_gallery_shared_0(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    if (principal.id !== obj.ownerId && principal.role !== "admin") throw new ForbiddenException();
    return obj;
  }

  /** The record owner or an administrator may read it. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/shared/archive/:itemId")
  pixel_gallery_shared_1(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    // Deliberate fixture: object authorization check omitted.
    return obj;
  }

  /** The record owner or an administrator may read it. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/moderation/current/:itemId")
  pixel_gallery_moderation_0(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    if (principal.id !== obj.ownerId && principal.role !== "admin") throw new ForbiddenException();
    return obj;
  }

  /** The record owner or an administrator may read it. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/moderation/archive/:itemId")
  pixel_gallery_moderation_1(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    // Deliberate fixture: object authorization check omitted.
    return obj;
  }

  /** Caller and record must share a tenant. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/workspace/current/:itemId")
  pixel_gallery_workspace_0(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    if (principal.tenantId !== obj.tenantId) throw new ForbiddenException();
    return obj;
  }

  /** Caller and record must share a tenant. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/workspace/archive/:itemId")
  pixel_gallery_workspace_1(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    // Deliberate fixture: object authorization check omitted.
    return obj;
  }

  /** Only administrators may read this operational resource. */
  @UseGuards(AuthGuard, RolesGuard)
  @Roles("admin")
  @Get("/fixtures/pixel_gallery/artworks/audit/current/:itemId")
  pixel_gallery_audit_0(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    return obj;
  }

  /** Only administrators may read this operational resource. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/audit/archive/:itemId")
  pixel_gallery_audit_1(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    // Deliberate fixture: object authorization check omitted.
    return obj;
  }

  /** Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/roster/current/:itemId")
  pixel_gallery_roster_0(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    if (!isMember(principal.id, obj.groupId)) throw new ForbiddenException();
    return obj;
  }

  /** Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/roster/archive/:itemId")
  pixel_gallery_roster_1(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    // Deliberate fixture: object authorization check omitted.
    return obj;
  }

  /** Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/pins/current/:itemId")
  pixel_gallery_pins_0(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    if (!isMember(principal.id, obj.groupId)) throw new ForbiddenException();
    return obj;
  }

  /** Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/pins/archive/:itemId")
  pixel_gallery_pins_1(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    // Deliberate fixture: object authorization check omitted.
    return obj;
  }

  /** Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/council/current/:itemId")
  pixel_gallery_council_0(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    if (principal.tenantId !== obj.tenantId || !isMember(principal.id, obj.groupId)) throw new ForbiddenException();
    return obj;
  }

  /** Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review. */
  @UseGuards(AuthGuard)
  @Get("/fixtures/pixel_gallery/artworks/council/archive/:itemId")
  pixel_gallery_council_1(@Param("itemId") itemId: string, @Req() req: any) {
    const obj = OBJECTS[itemId];
    if (!obj) throw new NotFoundException();
    const principal = req.principal;
    if (principal.tenantId !== obj.tenantId || !isMember(principal.id, obj.groupId)) throw new ForbiddenException();
    return obj;
  }

}

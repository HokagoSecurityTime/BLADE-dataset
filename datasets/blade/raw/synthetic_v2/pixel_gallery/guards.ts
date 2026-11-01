import { CanActivate, ExecutionContext, Injectable, SetMetadata, UnauthorizedException, ForbiddenException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
const PRINCIPALS: Record<string, any> = { alice: { id: "alice", tenantId: "north", role: "user" }, bob: { id: "bob", tenantId: "south", role: "user" }, admin: { id: "root", tenantId: "north", role: "admin" } };
@Injectable()
export class AuthGuard implements CanActivate {
  // Authentication only: resolves the Bearer token to a principal or throws 401. No authorization.
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const principal = PRINCIPALS[(req.headers.authorization || "").replace(/^Bearer /, "")];
    if (!principal) throw new UnauthorizedException();
    req.principal = principal;
    return true;
  }
}
export const Roles = (...roles: string[]) => SetMetadata("roles", roles);
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(ctx: ExecutionContext): boolean {
    const roles = this.reflector.get<string[]>("roles", ctx.getHandler()) || [];
    const principal = ctx.switchToHttp().getRequest().principal;
    if (roles.length && !roles.includes(principal.role)) throw new ForbiddenException();
    return true;
  }
}

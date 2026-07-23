const tenantIds = new WeakMap<Request, string>();

export interface TenantContext {
  tenantId?: string;
}

export function setRequestTenant(request: Request, tenantId: string): void {
  tenantIds.set(request, tenantId);
}

export function readRequestTenant(request: Request): string | undefined {
  return tenantIds.get(request);
}

export function createTenantContext(request: Request): TenantContext {
  const tenantId = readRequestTenant(request);
  return tenantId ? { tenantId } : {};
}

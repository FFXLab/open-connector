import type { RuntimeGrant } from "../storage/runtime-token-service.ts";

export type RuntimeConnectionDecision =
  | { allowed: true; connectionName?: string }
  | { allowed: false; code: "connection_not_allowed"; message: string };

/**
 * Stored runtime tokens with a non-empty connection map are confined to that
 * exact service/alias pair. An empty map preserves the existing unrestricted
 * token behavior for manually created local tokens.
 */
export function evaluateRuntimeConnection(
  grant: RuntimeGrant | undefined,
  service: string,
  requestedConnectionName: string | undefined,
): RuntimeConnectionDecision {
  const allowedConnections = grant?.allowedConnections ?? {};
  if (!grant || Object.keys(allowedConnections).length === 0) {
    return { allowed: true, connectionName: requestedConnectionName };
  }
  if (!(service in allowedConnections)) {
    return {
      allowed: false,
      code: "connection_not_allowed",
      message: `${service} is not included in the runtime token connection allowlist.`,
    };
  }
  const allowedConnection = allowedConnections[service];
  if (allowedConnection === null) {
    return { allowed: true };
  }
  if (requestedConnectionName && requestedConnectionName !== allowedConnection) {
    return {
      allowed: false,
      code: "connection_not_allowed",
      message: `${service} connection is not included in the runtime token connection allowlist.`,
    };
  }
  return { allowed: true, connectionName: allowedConnection };
}

export function runtimeGrantAllowsService(grant: RuntimeGrant | undefined, service: string): boolean {
  const allowedConnections = grant?.allowedConnections ?? {};
  return !grant || Object.keys(allowedConnections).length === 0 || service in allowedConnections;
}

export function runtimeGrantAllowsProxy(grant: RuntimeGrant | undefined): boolean {
  return !grant || Object.keys(grant.allowedConnections ?? {}).length === 0;
}

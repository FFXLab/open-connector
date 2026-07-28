import type { RuntimeGrant } from "../storage/runtime-token-service.ts";

import { describe, expect, it } from "vitest";
import { evaluateRuntimeConnection, runtimeGrantAllowsService } from "./runtime-connection-grant.ts";

function grant(allowedConnections: Record<string, string | null>): RuntimeGrant {
  return {
    tokenId: "token-1",
    allowedActions: ["*"],
    blockedActions: [],
    allowedConnections,
  };
}

describe("runtime connection grants", () => {
  it("only grants explicitly stored service names", () => {
    const allowedConnections = Object.create({
      github: "inherited-alias",
    }) as Record<string, string | null>;
    allowedConnections.notion = "j_user1";
    const runtimeGrant = grant(allowedConnections);

    expect(runtimeGrantAllowsService(runtimeGrant, "github")).toBe(false);
    expect(evaluateRuntimeConnection(runtimeGrant, "github", undefined)).toMatchObject({
      allowed: false,
      code: "connection_not_allowed",
    });
    expect(runtimeGrantAllowsService(runtimeGrant, "notion")).toBe(true);
    expect(evaluateRuntimeConnection(runtimeGrant, "notion", undefined)).toEqual({
      allowed: true,
      connectionName: "j_user1",
    });
  });
});

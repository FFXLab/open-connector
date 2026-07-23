import { describe, expect, it } from "vitest";
import { resolveJennyRuntimeToken } from "./jenny-runtime-token.ts";

const secret = "jenny-runtime-token-test-secret-long-enough";

describe("resolveJennyRuntimeToken", () => {
  it("derives tenant, action, and proxy scope from a valid token", async () => {
    const token = await createToken({ services: ["github", "notion"] });
    await expect(resolveJennyRuntimeToken(token, secret)).resolves.toMatchObject({
      tenantId: "workspace-1",
      allowedActions: ["github.*", "notion.*"],
      allowedProxies: ["github", "notion"],
    });
  });

  it("rejects tampered and expired tokens", async () => {
    const token = await createToken({ services: ["github"] });
    await expect(resolveJennyRuntimeToken(`${token}x`, secret)).resolves.toBeUndefined();
    await expect(
      resolveJennyRuntimeToken(await createToken({ services: [], expired: true }), secret),
    ).resolves.toBeUndefined();
  });

  it("uses explicit Jenny action and proxy policy", async () => {
    const token = await createToken({
      services: ["github"],
      claims: {
        allowedActions: ["github.get_issue"],
        blockedActions: ["github.delete_repository"],
        allowedProxies: [],
        blockedProxies: ["github"],
      },
    });
    await expect(resolveJennyRuntimeToken(token, secret)).resolves.toMatchObject({
      allowedActions: ["github.get_issue"],
      blockedActions: ["github.delete_repository"],
      allowedProxies: [],
      blockedProxies: ["github"],
    });
  });
});

async function createToken(input: {
  services: string[];
  expired?: boolean;
  claims?: Record<string, unknown>;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({
      aud: "jenny-open-connector",
      iss: "jenny-gateway",
      jti: "token-1",
      workspaceId: "workspace-1",
      services: input.services,
      ...input.claims,
      iat: now - 60,
      exp: input.expired ? now - 1 : now + 600,
    }),
  ).toString("base64url");
  const value = `jct_v1.${payload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))).toString(
    "base64url",
  );
  return `${value}.${signature}`;
}

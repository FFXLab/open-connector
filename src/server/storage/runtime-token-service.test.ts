import type { IRuntimeTokenStore } from "./runtime-token-service.ts";

import { describe, expect, it, vi } from "vitest";
import { hashRuntimeToken, RuntimeTokenService } from "./runtime-token-service.ts";

describe("RuntimeTokenService", () => {
  it("rejects non-runtime-token values without reading the store", async () => {
    const store: IRuntimeTokenStore = {
      add: vi.fn(),
      list: vi.fn(async () => []),
      findByHash: vi.fn(),
      updatePolicy: vi.fn(),
      revoke: vi.fn(async () => false),
      markUsed: vi.fn(),
    };
    const service = new RuntimeTokenService(store);

    await expect(service.verifyToken("jwt.access.token")).resolves.toBe(false);
    expect(store.findByHash).not.toHaveBeenCalled();
    expect(store.markUsed).not.toHaveBeenCalled();
  });

  it("resolves stored tokens by hash into a scoped grant", async () => {
    const token = "oct_secret";
    const record = {
      id: "token-1",
      name: "Issue bot",
      tokenHash: hashRuntimeToken(token),
      allowedActions: ["github.*"],
      blockedActions: ["github.delete_repository"],
      allowedConnections: { github: "j_p_project1_agent1", hackernews: null },
      actionInputConstraints: { "github.*": { owner: "FFXLab", repo: "Jenny" } },
      createdAt: "2026-07-20T00:00:00.000Z",
    };
    const store: IRuntimeTokenStore = {
      add: vi.fn(),
      list: vi.fn(async () => [record]),
      findByHash: vi.fn(async () => record),
      updatePolicy: vi.fn(),
      revoke: vi.fn(async () => false),
      markUsed: vi.fn(),
    };

    await expect(new RuntimeTokenService(store).resolveToken(token)).resolves.toEqual({
      tokenId: "token-1",
      allowedActions: ["github.*"],
      blockedActions: ["github.delete_repository"],
      allowedConnections: { github: "j_p_project1_agent1", hackernews: null },
      actionInputConstraints: { "github.*": { owner: "FFXLab", repo: "Jenny" } },
    });
    expect(store.findByHash).toHaveBeenCalledWith(record.tokenHash);
    expect(store.list).not.toHaveBeenCalled();
    expect(store.markUsed).toHaveBeenCalledWith("token-1", expect.any(String));
  });

  it("rejects expired stored tokens without marking them as used", async () => {
    const token = "oct_expired";
    const record = {
      id: "token-expired",
      name: "Expired lease",
      tokenHash: hashRuntimeToken(token),
      allowedActions: ["github.*"],
      blockedActions: [],
      allowedConnections: { github: "project" },
      createdAt: "2026-07-20T00:00:00.000Z",
      expiresAt: "2026-07-20T01:00:00.000Z",
    };
    const store: IRuntimeTokenStore = {
      add: vi.fn(),
      list: vi.fn(async () => [record]),
      findByHash: vi.fn(async () => record),
      updatePolicy: vi.fn(),
      revoke: vi.fn(async () => false),
      markUsed: vi.fn(),
    };

    await expect(new RuntimeTokenService(store).resolveToken(token)).resolves.toBeUndefined();
    expect(store.markUsed).not.toHaveBeenCalled();
  });

  it("persists a normalized future expiry on newly created tokens", async () => {
    const store: IRuntimeTokenStore = {
      add: vi.fn(),
      list: vi.fn(async () => []),
      findByHash: vi.fn(),
      updatePolicy: vi.fn(),
      revoke: vi.fn(async () => false),
      markUsed: vi.fn(),
    };
    const future = new Date(Date.now() + 60_000).toISOString();

    const created = await new RuntimeTokenService(store).createToken("Lease", undefined, future);

    expect(created.record.expiresAt).toBe(future);
    expect(store.add).toHaveBeenCalledWith(expect.objectContaining({ expiresAt: future }));
  });
});

import type { IConnectionStore, StoredConnection } from "../../connection-service.ts";
import type { ResolvedCredential } from "../../core/types.ts";

import { describe, expect, it } from "vitest";
import { TenantConnectionStore } from "./tenant-connection-store.ts";

describe("TenantConnectionStore", () => {
  it("isolates aliases without exposing its storage prefix", async () => {
    const base = new MemoryConnectionStore();
    const first = new TenantConnectionStore(base, { tenantId: "first" });
    const second = new TenantConnectionStore(base, { tenantId: "second" });
    await first.set("github", "default", { authType: "no_auth" });

    await expect(first.get("github", "default")).resolves.toMatchObject({ connectionName: "default" });
    await expect(second.get("github", "default")).resolves.toBeUndefined();
    await expect(first.list()).resolves.toHaveLength(1);
    await expect(second.list()).resolves.toEqual([]);
  });
});

class MemoryConnectionStore implements IConnectionStore {
  private readonly values = new Map<string, StoredConnection>();

  async get(service: string, name: string): Promise<StoredConnection | undefined> {
    return this.values.get(`${service}:${name}`);
  }
  async set(service: string, connectionName: string, credential: ResolvedCredential): Promise<StoredConnection> {
    const value = { id: crypto.randomUUID(), service, connectionName, credential };
    this.values.set(`${service}:${connectionName}`, value);
    return value;
  }
  async updateCredential(input: StoredConnection): Promise<boolean> {
    this.values.set(`${input.service}:${input.connectionName}`, input);
    return true;
  }
  async delete(service: string, name: string): Promise<void> {
    this.values.delete(`${service}:${name}`);
  }
  async list(): Promise<StoredConnection[]> {
    return [...this.values.values()];
  }
}

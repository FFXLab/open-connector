import type { IConnectionStore, StoredConnection } from "../../connection-service.ts";
import type { ResolvedCredential } from "../../core/types.ts";
import type { TenantContext } from "./tenant-context.ts";

const separator = "~";

export class TenantConnectionStore implements IConnectionStore {
  private readonly store: IConnectionStore;
  private readonly context: TenantContext;

  constructor(store: IConnectionStore, context: TenantContext) {
    this.store = store;
    this.context = context;
  }

  async get(service: string, connectionName: string): Promise<StoredConnection | undefined> {
    const stored = await this.store.get(service, this.storageName(connectionName));
    return stored ? this.external(stored) : undefined;
  }

  async set(service: string, connectionName: string, credential: ResolvedCredential): Promise<StoredConnection> {
    return this.external(await this.store.set(service, this.storageName(connectionName), credential));
  }

  async updateCredential(input: StoredConnection): Promise<boolean> {
    return await this.store.updateCredential({
      ...input,
      connectionName: this.storageName(input.connectionName),
    });
  }

  async delete(service: string, connectionName: string): Promise<void> {
    await this.store.delete(service, this.storageName(connectionName));
  }

  async list(): Promise<StoredConnection[]> {
    const prefix = this.prefix();
    if (!prefix) {
      return await this.store.list();
    }
    return (await this.store.list())
      .filter((connection) => connection.connectionName.startsWith(prefix))
      .map((connection) => this.external(connection));
  }

  private storageName(connectionName: string): string {
    const prefix = this.prefix();
    return prefix ? `${prefix}${connectionName}` : connectionName;
  }

  private external(connection: StoredConnection): StoredConnection {
    const prefix = this.prefix();
    return prefix ? { ...connection, connectionName: connection.connectionName.slice(prefix.length) } : connection;
  }

  private prefix(): string {
    return this.context.tenantId ? `${this.context.tenantId}${separator}` : "";
  }
}

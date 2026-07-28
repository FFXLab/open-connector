import type { TokenActionPolicy } from "../../core/action-policy.ts";

import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

export interface RuntimeTokenRecord {
  id: string;
  name: string;
  tokenHash: string;
  allowedActions: string[];
  blockedActions: string[];
  allowedConnections?: Record<string, string | null>;
  actionInputConstraints?: Record<string, Record<string, string | number | boolean | null>>;
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
}

export interface RuntimeTokenSummary {
  id: string;
  name: string;
  allowedActions: string[];
  blockedActions: string[];
  allowedConnections?: Record<string, string | null>;
  actionInputConstraints?: Record<string, Record<string, string | number | boolean | null>>;
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
}

export interface RuntimeTokenCreation {
  token: string;
  record: RuntimeTokenRecord;
}

export interface IRuntimeTokenStore {
  add(record: RuntimeTokenRecord): Promise<void>;
  list(): Promise<RuntimeTokenRecord[]>;
  findByHash(tokenHash: string): Promise<RuntimeTokenRecord | undefined>;
  updatePolicy(id: string, policy: TokenActionPolicy): Promise<RuntimeTokenRecord | undefined>;
  revoke(id: string): Promise<boolean>;
  markUsed(id: string, usedAt: string): Promise<void>;
}

const tokenPrefix = "oct_";

export interface RuntimeGrant extends TokenActionPolicy {
  tokenId: string;
}

export class RuntimeTokenService {
  private readonly store: IRuntimeTokenStore;

  constructor(store: IRuntimeTokenStore) {
    this.store = store;
  }

  async createToken(
    name: string,
    policy: TokenActionPolicy = {
      allowedActions: [],
      blockedActions: [],
      allowedConnections: {},
      actionInputConstraints: {},
    },
    expiresAt?: string,
  ): Promise<RuntimeTokenCreation> {
    const token = `${tokenPrefix}${randomBytes(32).toString("base64url")}`;
    const now = new Date().toISOString();
    const record: RuntimeTokenRecord = {
      id: randomUUID(),
      name: name.trim(),
      tokenHash: hashRuntimeToken(token),
      allowedActions: policy.allowedActions,
      blockedActions: policy.blockedActions,
      allowedConnections: policy.allowedConnections ?? {},
      actionInputConstraints: policy.actionInputConstraints ?? {},
      createdAt: now,
      expiresAt: normalizeFutureExpiry(expiresAt, now),
    };
    await this.store.add(record);
    return { token, record };
  }

  async listTokens(): Promise<RuntimeTokenSummary[]> {
    return (await this.store.list()).map(summarizeRuntimeToken);
  }

  async revokeToken(id: string): Promise<boolean> {
    return this.store.revoke(id);
  }

  async updateTokenPolicy(id: string, policy: TokenActionPolicy): Promise<RuntimeTokenSummary | undefined> {
    const record = await this.store.updatePolicy(id, policy);
    return record ? summarizeRuntimeToken(record) : undefined;
  }

  async resolveToken(token: string): Promise<RuntimeGrant | undefined> {
    if (!token.startsWith(tokenPrefix)) {
      return undefined;
    }
    const tokenHash = hashRuntimeToken(token);
    const matched = await this.store.findByHash(tokenHash);
    if (!matched || !equalHashes(matched.tokenHash, tokenHash)) {
      return undefined;
    }
    if (matched.expiresAt && Date.parse(matched.expiresAt) <= Date.now()) {
      return undefined;
    }

    await this.store.markUsed(matched.id, new Date().toISOString());
    return {
      tokenId: matched.id,
      allowedActions: matched.allowedActions,
      blockedActions: matched.blockedActions,
      allowedConnections: matched.allowedConnections ?? {},
      actionInputConstraints: matched.actionInputConstraints ?? {},
    };
  }

  async verifyToken(token: string): Promise<boolean> {
    return Boolean(await this.resolveToken(token));
  }
}

export function hashRuntimeToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

export function summarizeRuntimeToken(record: RuntimeTokenRecord): RuntimeTokenSummary {
  return {
    id: record.id,
    name: record.name,
    allowedActions: record.allowedActions,
    blockedActions: record.blockedActions,
    allowedConnections: record.allowedConnections ?? {},
    actionInputConstraints: record.actionInputConstraints ?? {},
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    lastUsedAt: record.lastUsedAt,
  };
}

function normalizeFutureExpiry(expiresAt: string | undefined, now: string): string | undefined {
  if (expiresAt === undefined) return undefined;
  const timestamp = Date.parse(expiresAt);
  if (!Number.isFinite(timestamp) || timestamp <= Date.parse(now)) {
    throw new Error("expiresAt must be a valid future timestamp.");
  }
  return new Date(timestamp).toISOString();
}

function equalHashes(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

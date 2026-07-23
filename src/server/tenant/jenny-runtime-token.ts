import type { RuntimeGrant } from "../storage/runtime-token-service.ts";

const tokenPrefix = "jct_v1";
const tokenAudience = "jenny-open-connector";

interface JennyRuntimeClaims {
  aud: string;
  iss: string;
  jti: string;
  workspaceId: string;
  projectId?: string;
  agentId?: string;
  services: string[];
  allowedActions?: string[];
  blockedActions?: string[];
  allowedProxies?: string[];
  blockedProxies?: string[];
  resources?: Record<string, { defaults: Record<string, string>; locked: string[] }>;
  credentialEnvelope?: string;
  iat: number;
  exp: number;
}

export async function resolveJennyRuntimeToken(
  token: string,
  secret: string | undefined,
): Promise<RuntimeGrant | undefined> {
  if (!secret) {
    return undefined;
  }
  const [prefix, payload, signature, ...extra] = token.split(".");
  if (prefix !== tokenPrefix || !payload || !signature || extra.length > 0) {
    return undefined;
  }
  const expected = await sign(`${tokenPrefix}.${payload}`, secret);
  if (!constantTimeEqual(signature, expected)) {
    return undefined;
  }

  let claims: JennyRuntimeClaims;
  try {
    claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as JennyRuntimeClaims;
  } catch {
    return undefined;
  }
  const now = Math.floor(Date.now() / 1000);
  if (
    claims.aud !== tokenAudience ||
    claims.iss !== "jenny-gateway" ||
    typeof claims.jti !== "string" ||
    typeof claims.workspaceId !== "string" ||
    !Array.isArray(claims.services) ||
    claims.services.some((service) => typeof service !== "string" || service.length === 0) ||
    typeof claims.iat !== "number" ||
    typeof claims.exp !== "number" ||
    claims.iat > now + 30 ||
    claims.exp <= now
  ) {
    return undefined;
  }

  const services = [...new Set(claims.services)];
  const credentials = claims.credentialEnvelope
    ? await openCredentialEnvelope(claims.credentialEnvelope, secret, claims.projectId, claims.agentId)
    : undefined;
  if (claims.credentialEnvelope && !credentials) {
    return undefined;
  }
  return {
    tokenId: claims.jti,
    tenantId: claims.workspaceId,
    allowedActions: claims.allowedActions ?? services.map((service) => `${service}.*`),
    blockedActions: claims.blockedActions ?? [],
    allowedProxies: claims.allowedProxies ?? services,
    blockedProxies: claims.blockedProxies ?? [],
    resources: claims.resources,
    credentials,
  };
}

async function openCredentialEnvelope(
  envelope: string,
  secret: string,
  projectId: string | undefined,
  agentId: string | undefined,
): Promise<RuntimeGrant["credentials"] | undefined> {
  if (!projectId || !agentId) {
    return undefined;
  }
  const [ivPart, tagPart, ciphertextPart, ...extra] = envelope.split(".");
  if (!ivPart || !tagPart || !ciphertextPart || extra.length > 0) {
    return undefined;
  }
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret)),
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    const ciphertext = Buffer.concat([Buffer.from(ciphertextPart, "base64url"), Buffer.from(tagPart, "base64url")]);
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: Buffer.from(ivPart, "base64url"),
        additionalData: new TextEncoder().encode(`${projectId}:${agentId}`),
        tagLength: 128,
      },
      key,
      ciphertext,
    );
    const value = JSON.parse(new TextDecoder().decode(plaintext)) as RuntimeGrant["credentials"];
    return value && typeof value === "object" ? value : undefined;
  } catch {
    return undefined;
  }
}

async function sign(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))).toString("base64url");
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

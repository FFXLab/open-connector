import type { PolicyRules, TokenActionPolicy } from "../../core/action-policy.ts";
import type { JsonRequestBody } from "./http-utils.ts";

import { Buffer } from "node:buffer";
import { requiredStringArray } from "../../core/cast.ts";
import { HttpRequestError } from "./http-utils.ts";

export const policyRequestMaxBytes: number = 256 * 1024;
export const policyRuleMaxBytes: number = 256;
export const policyRuleListMaxItems: number = 128;

export function readRuntimePolicyRules(body: JsonRequestBody): PolicyRules {
  return {
    allowedActions: readRules(body.allowedActions, "allowedActions", "action"),
    blockedActions: readRules(body.blockedActions, "blockedActions", "action"),
    allowedProxies: readRules(body.allowedProxies, "allowedProxies", "proxy"),
    blockedProxies: readRules(body.blockedProxies, "blockedProxies", "proxy"),
  };
}

export function readTokenActionPolicy(body: JsonRequestBody, allowOmitted = false): TokenActionPolicy {
  if (body.allowedProxies !== undefined || body.blockedProxies !== undefined) {
    throw invalidInput("Token policy does not support proxy rules.");
  }
  return {
    allowedActions: readRules(body.allowedActions, "allowedActions", "action", allowOmitted),
    blockedActions: readRules(body.blockedActions, "blockedActions", "action", allowOmitted),
    allowedConnections: readAllowedConnections(body.allowedConnections, allowOmitted),
  };
}

function readAllowedConnections(value: unknown, allowOmitted: boolean): Record<string, string | null> | undefined {
  if (value === undefined) return allowOmitted ? {} : undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalidInput("allowedConnections must be an object keyed by service.");
  }
  const entries = Object.entries(value);
  if (entries.length > policyRuleListMaxItems) {
    throw invalidInput(`allowedConnections must not contain more than ${policyRuleListMaxItems} entries.`);
  }
  return Object.fromEntries(
    entries.map(([service, connectionName]) => {
      const normalizedService = service.trim();
      if (!normalizedService || /\s/.test(normalizedService) || normalizedService.includes("*")) {
        throw invalidInput(`allowedConnections contains an invalid service: ${service}.`);
      }
      if (connectionName !== null && typeof connectionName !== "string") {
        throw invalidInput(`allowedConnections.${normalizedService} must be a connection name or null.`);
      }
      const normalizedConnection = typeof connectionName === "string" ? connectionName.trim() : null;
      if (typeof connectionName === "string" && !normalizedConnection) {
        throw invalidInput(`allowedConnections.${normalizedService} must not be empty.`);
      }
      if (normalizedConnection && Buffer.byteLength(normalizedConnection, "utf8") > policyRuleMaxBytes) {
        throw invalidInput(
          `allowedConnections.${normalizedService} must not exceed ${policyRuleMaxBytes} UTF-8 bytes.`,
        );
      }
      return [normalizedService, normalizedConnection];
    }),
  );
}

function readRules(value: unknown, fieldName: string, kind: "action" | "proxy", allowOmitted = false): string[] {
  if (value === undefined && allowOmitted) {
    return [];
  }
  const values = requiredStringArray(value, fieldName, invalidInput);
  const rules: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const rule = value.trim();
    if (!rule) {
      throw invalidInput(`${fieldName} must not contain empty rules.`);
    }
    if (Buffer.byteLength(rule, "utf8") > policyRuleMaxBytes) {
      throw invalidInput(`${fieldName} rules must not exceed ${policyRuleMaxBytes} UTF-8 bytes.`);
    }
    assertRuleSyntax(rule, fieldName, kind);
    if (!seen.has(rule)) {
      seen.add(rule);
      rules.push(rule);
    }
  }
  if (rules.length > policyRuleListMaxItems) {
    throw invalidInput(`${fieldName} must not contain more than ${policyRuleListMaxItems} rules.`);
  }
  return rules;
}

function assertRuleSyntax(rule: string, fieldName: string, kind: "action" | "proxy"): void {
  if (rule === "*") {
    return;
  }
  if (kind === "proxy") {
    if (rule.includes("*") || /\s/.test(rule)) {
      throw invalidInput(`${fieldName} contains an invalid proxy rule: ${rule}.`);
    }
    return;
  }
  if (/^[^\s.*]+\.\*$/.test(rule)) {
    return;
  }
  const separator = rule.indexOf(".");
  if (rule.includes("*") || /\s/.test(rule) || separator <= 0 || separator === rule.length - 1) {
    throw invalidInput(`${fieldName} contains an invalid action rule: ${rule}.`);
  }
}

function invalidInput(message: string): HttpRequestError {
  return new HttpRequestError("invalid_input", message);
}

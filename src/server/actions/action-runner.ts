import type { CatalogStore } from "../../catalog-store.ts";
import type { ConnectionService, ConnectionSummary, ExecutionConnection } from "../../connection-service.ts";
import type { ActionPolicyDecision, ActionPolicyService, ActionPolicySnapshot } from "../../core/action-policy.ts";
import type { ExecutionContext, ExecutionResult, ResolvedCredential, TransitFileWriter } from "../../core/types.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { Logger } from "../logger.ts";
import type { IRunLogStore, RunLog, RunLogCaller, RunLogListInput, RunLogPage } from "../storage/runtime-store.ts";
import type { RuntimeResourceScope } from "../storage/runtime-token-service.ts";

import { ConnectionError } from "../../connection-service.ts";
import { executeAction as executeProviderAction } from "../../core/execution.ts";
import { safeRunLogError, summarizeForRunLog } from "./run-log-summary.ts";

export interface ActionRunnerOptions {
  catalog: CatalogStore;
  providerLoader: IProviderLoader;
  connections: ConnectionService;
  runs: IRunLogStore;
  transitFiles?: TransitFileWriter;
  actionPolicy?: ActionPolicyService;
  logger?: Logger;
}

export interface RunActionInput {
  actionId: string;
  input: unknown;
  caller: RunLogCaller;
  connectionName?: string;
  policy?: ActionPolicySnapshot;
  runtimeTokenId?: string;
  runtimeCredentials?: Record<string, ResolvedCredential>;
  resourceScopes?: Record<string, RuntimeResourceScope>;
}

export interface ActionRunResult {
  executionId: string;
  auditPersisted: boolean;
  result: ExecutionResult;
  connection?: ConnectionSummary;
}

/**
 * Shared execution boundary for HTTP, MCP, and future local callers.
 */
export class ActionRunner {
  private readonly options: ActionRunnerOptions;

  constructor(options: ActionRunnerOptions) {
    this.options = options;
  }

  async run(input: RunActionInput): Promise<ActionRunResult | undefined> {
    const action = this.options.catalog.actionsById.get(input.actionId);
    if (!action) {
      this.options.logger?.warn(
        {
          actionId: input.actionId,
          caller: input.caller,
          errorCode: "invalid_input",
        },
        "action run rejected",
      );
      return undefined;
    }

    const executionId = crypto.randomUUID();
    const logContext = {
      actionId: action.id,
      service: action.service,
      caller: input.caller,
      executionId,
    };
    this.options.logger?.info(logContext, "action run started");
    const startedAtMs = Date.now();
    const startedAt = new Date(startedAtMs).toISOString();
    const policy: ActionPolicyDecision = (input.policy ?? this.options.actionPolicy?.createSnapshot())?.evaluate(
      action,
    ) ?? { allowed: true, checks: [] };
    let actionInput = input.input;
    let connection: ExecutionConnection | undefined;
    let result: ExecutionResult;
    if (!policy.allowed) {
      result = { ok: false, error: { code: policy.code, message: policy.message } };
    } else {
      try {
        const runtimeCredential = input.runtimeCredentials?.[action.service];
        connection = runtimeCredential
          ? {
              getCredential: async (service) => (service === action.service ? runtimeCredential : undefined),
            }
          : await this.options.connections.resolveForExecution(action.service, input.connectionName);
        actionInput = applyResourceScope(input.input, input.resourceScopes?.[action.service]);
        const executor = action.execution.locallyExecutable
          ? await this.options.providerLoader.loadActionExecutor(
              action.service,
              action.id,
              this.options.catalog.providers.find((provider) => provider.service === action.service)?.displayName,
            )
          : undefined;
        result = await executeProviderAction(
          action,
          executor,
          actionInput,
          this.createExecutionContext(connection.getCredential),
        );
      } catch (error) {
        result =
          error instanceof ConnectionError
            ? { ok: false, error: { code: error.code, message: error.message } }
            : {
                ok: false,
                error: { code: "internal_error", message: "Action execution failed unexpectedly." },
              };
      }
    }
    const completedAtMs = Date.now();
    const durationMs = completedAtMs - startedAtMs;
    const auditError = safeRunLogError(result.error);
    const runLog: RunLog = {
      id: executionId,
      service: action.service,
      actionId: input.actionId,
      caller: input.caller,
      startedAt,
      completedAt: new Date(completedAtMs).toISOString(),
      durationMs,
      ok: result.ok,
      connectionId: connection?.summary?.id,
      connectionProfile: connection?.summary?.profile,
      runtimeTokenId: input.runtimeTokenId,
      policy,
      inputSummary: this.summarizeAuditValue(actionInput, logContext),
      outputSummary: result.ok ? this.summarizeAuditValue(result.output, logContext) : undefined,
      ...auditError,
    };

    let auditPersisted = false;
    try {
      const write = await this.options.runs.add(runLog);
      auditPersisted = true;
      if (!write.retentionApplied) {
        this.options.logger?.warn({ ...logContext, auditPersisted }, "run audit retention failed");
      }
    } catch {
      this.options.logger?.warn({ ...logContext, auditPersisted }, "run audit persistence failed");
    }

    const completedLogContext = {
      ...logContext,
      connectionId: connection?.summary?.id,
      durationMs,
      ok: result.ok,
      errorCode: result.error?.code,
      auditPersisted,
    };
    if (result.ok) {
      this.options.logger?.info(completedLogContext, "action run completed");
    } else {
      this.options.logger?.warn(completedLogContext, "action run failed");
    }

    return { executionId, auditPersisted, result, connection: connection?.summary };
  }

  listRuns(input?: RunLogListInput): Promise<RunLogPage> {
    return this.options.runs.list(input);
  }

  getRun(id: string): Promise<RunLog | undefined> {
    return this.options.runs.get(id);
  }

  private createExecutionContext(getCredential: ExecutionConnection["getCredential"]): ExecutionContext {
    const context: ExecutionContext = {
      getCredential,
    };
    if (this.options.transitFiles) {
      context.transitFiles = this.options.transitFiles;
    }
    return context;
  }

  private summarizeAuditValue(value: unknown, logContext: Record<string, unknown>): unknown {
    try {
      return summarizeForRunLog(value);
    } catch {
      this.options.logger?.warn(logContext, "run audit summary unavailable");
      return "[unavailable]";
    }
  }
}

function applyResourceScope(input: unknown, scope: RuntimeResourceScope | undefined): unknown {
  if (!scope) {
    return input;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new ConnectionError("connection_invalid", "Scoped action input must be an object.");
  }
  const scoped = { ...(input as Record<string, unknown>) };
  for (const key of scope.locked) {
    const expected = scope.defaults[key];
    const provided = scoped[key];
    if (provided !== undefined && String(provided).toLowerCase() !== expected?.toLowerCase()) {
      throw new ConnectionError("connection_invalid", `Action access is limited to the current project ${key}.`);
    }
    if (expected !== undefined) {
      scoped[key] = expected;
    }
  }
  return scoped;
}

import type { CredentialValidators, ProviderExecutors } from "../../core/types.ts";
import type { GitHubActionContext } from "./runtime-shared.ts";

import { defineProviderExecutors, requireBearerCredential } from "../provider-runtime.ts";
import { activityActionHandlers } from "./runtime-activity.ts";
import { issueActionHandlers } from "./runtime-issue.ts";
import { pullRequestActionHandlers } from "./runtime-pull-request.ts";
import { releaseActionHandlers } from "./runtime-release.ts";
import { repositoryActionHandlers } from "./runtime-repository.ts";
import { searchActionHandlers } from "./runtime-search.ts";
import { githubRequestJson } from "./runtime-shared.ts";

const service = "github";

export const executors: ProviderExecutors = defineProviderExecutors<GitHubActionContext>({
  service,
  handlers: Object.assign(
    {},
    activityActionHandlers,
    repositoryActionHandlers,
    issueActionHandlers,
    pullRequestActionHandlers,
    releaseActionHandlers,
    searchActionHandlers,
  ),
  async createContext(context, fetcher): Promise<GitHubActionContext> {
    const credential = await requireBearerCredential(context, service);
    return {
      accessToken: credential.accessToken,
      fetcher,
    };
  },
});

export const credentialValidators: CredentialValidators = {
  async apiKey(input, { fetcher }) {
    return input.apiKey.startsWith("ghs_")
      ? validateGitHubInstallationToken(input.apiKey, fetcher)
      : validateGitHubUserToken(input.apiKey, fetcher);
  },
  async oauth2(input, { fetcher }) {
    return validateGitHubUserToken(input.accessToken, fetcher);
  },
};

async function validateGitHubUserToken(accessToken: string, fetcher: typeof fetch) {
  const user = await githubRequestJson<Record<string, unknown>>({
    path: "/user",
    accessToken,
    fetcher,
  });

  const login = typeof user.login === "string" ? user.login : undefined;
  const id = user.id === undefined ? undefined : String(user.id);
  const name = typeof user.name === "string" && user.name.trim() ? user.name.trim() : undefined;

  return {
    profile: {
      accountId: login ?? id ?? "github:user",
      displayName: name ?? login ?? id ?? "GitHub User",
    },
    metadata: {
      currentUser: user,
    },
  };
}

async function validateGitHubInstallationToken(accessToken: string, fetcher: typeof fetch) {
  const installation = await githubRequestJson<{
    total_count?: number;
    repositories?: Array<{ owner?: { id?: number; login?: string } }>;
  }>({
    path: "/installation/repositories",
    query: { per_page: 1 },
    accessToken,
    fetcher,
  });
  const owner = installation.repositories?.[0]?.owner;
  const ownerId = owner?.id === undefined ? undefined : String(owner.id);
  const ownerLogin = typeof owner?.login === "string" ? owner.login : undefined;

  return {
    profile: {
      accountId: ownerId ?? ownerLogin ?? "github:installation",
      displayName: ownerLogin ? `${ownerLogin} GitHub App` : "GitHub App installation",
    },
    metadata: {
      installation: {
        repositoryCount: installation.total_count ?? 0,
        owner: owner ?? null,
      },
    },
  };
}

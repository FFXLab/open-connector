import { describe, expect, it, vi } from "vitest";
import { credentialValidators } from "./executors.ts";

describe("GitHub credential validators", () => {
  it("validates GitHub App installation tokens against installation repositories", async () => {
    const fetcher = vi.fn(async (url: string | URL | Request) => {
      expect(String(url)).toBe("https://api.github.com/installation/repositories?per_page=1");
      return Response.json({
        total_count: 1,
        repositories: [{ owner: { id: 271475861, login: "FFX-bot" } }],
      });
    }) as unknown as typeof fetch;

    const result = await credentialValidators.apiKey?.(
      { apiKey: "ghs_installation-token", values: { apiKey: "ghs_installation-token" } },
      { fetcher },
    );

    expect(result).toMatchObject({
      profile: { accountId: "271475861", displayName: "FFX-bot GitHub App" },
      metadata: { installation: { repositoryCount: 1 } },
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("continues to validate personal and OAuth tokens against the current user", async () => {
    const fetcher = vi.fn(async (url: string | URL | Request) => {
      expect(String(url)).toBe("https://api.github.com/user");
      return Response.json({ id: 1, login: "octocat", name: "The Octocat" });
    }) as unknown as typeof fetch;

    await credentialValidators.apiKey?.(
      { apiKey: "github_pat_token", values: { apiKey: "github_pat_token" } },
      { fetcher },
    );
    await credentialValidators.oauth2?.(
      {
        authType: "oauth2",
        accessToken: "oauth-token",
        tokenType: "bearer",
        profile: { accountId: "octocat", displayName: "The Octocat", grantedScopes: [] },
        metadata: {},
      },
      { fetcher },
    );

    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});

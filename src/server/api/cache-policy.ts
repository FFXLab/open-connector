export interface ResponseCachePolicy {
  cacheControl: string;
  cloudflareCdnCacheControl?: string;
  vary?: string;
}

const catalogBrowserCacheControl = "public, max-age=0, must-revalidate";
const catalogEdgeCacheControl = "public, max-age=31536000, stale-while-revalidate=86400";

export function getResponseCachePolicy(method: string, path: string, status: number): ResponseCachePolicy | undefined {
  // Runtime endpoints are filtered by the caller's token policy and exact
  // connection grants. They must never enter a shared browser/CDN cache,
  // even when the payload happens to look like catalog metadata.
  if (path === "/v1" || path.startsWith("/v1/") || path === "/mcp" || path.startsWith("/mcp/")) {
    return { cacheControl: "no-store", cloudflareCdnCacheControl: "no-store" };
  }

  if (isCatalogResponse(method, path) && status >= 200 && status < 300) {
    return {
      cacheControl: catalogBrowserCacheControl,
      cloudflareCdnCacheControl: catalogEdgeCacheControl,
      vary: "Authorization, Cookie",
    };
  }

  if (isRuntimeResponsePath(path)) {
    return { cacheControl: "no-store" };
  }

  return undefined;
}

function isCatalogResponse(method: string, path: string): boolean {
  if (method !== "GET" && method !== "HEAD") {
    return false;
  }

  return (
    path === "/api/providers" ||
    /^\/api\/providers\/[^/]+$/.test(path) ||
    path === "/api/actions" ||
    (path !== "/api/actions/search" && /^\/api\/actions\/[^/]+$/.test(path))
  );
}

function isRuntimeResponsePath(path: string): boolean {
  return (
    path === "/health" ||
    path === "/openapi.json" ||
    path === "/docs" ||
    path.startsWith("/docs/") ||
    path === "/api" ||
    path.startsWith("/api/") ||
    path === "/oauth" ||
    path.startsWith("/oauth/")
  );
}

import { writeFile } from "node:fs/promises";

const accountId = required("CLOUDFLARE_ACCOUNT_ID");
const databaseId = required("CONNECTOR_D1_DATABASE_ID");
const namespaceId = required("CONNECTOR_KV_NAMESPACE_ID");

await writeFile(
  new URL("../wrangler.local.jsonc", import.meta.url),
  `${JSON.stringify(
    {
      $schema: "node_modules/wrangler/config-schema.json",
      name: "jenny-open-connector",
      account_id: accountId,
      main: "src/server/cloudflare.ts",
      compatibility_date: "2026-07-02",
      compatibility_flags: ["nodejs_compat"],
      assets: {
        directory: "dist/web",
        binding: "ASSETS",
        not_found_handling: "single-page-application",
        run_worker_first: ["/api/*", "/v1/*", "/mcp*", "/oauth/*", "/docs", "/docs/*", "/openapi.json", "/health"],
      },
      observability: { enabled: true },
      d1_databases: [
        {
          binding: "DB",
          database_name: "jenny-open-connector",
          database_id: databaseId,
          migrations_dir: "migrations",
        },
      ],
      kv_namespaces: [{ binding: "TRANSIT_FILES", id: namespaceId }],
      vars: {
        TRANSIT_FILES_BACKEND: "kv",
        OOMOL_CONNECT_TRANSIT_FILE_MAX_BYTES: "26214400",
        OOMOL_CONNECT_TRANSIT_FILE_TTL_SECONDS: "86400",
        OOMOL_CONNECT_ALLOW_PRIVATE_NETWORK: "false",
      },
    },
    null,
    2,
  )}\n`,
);

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

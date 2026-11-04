import * as pulumi from "@pulumi/pulumi";
import * as docker from "@pulumi/docker";

/**
 * MuseArena platform plane (single host, Docker): Temporal (+ its Postgres),
 * Langfuse v3 (web, worker, Postgres, ClickHouse, Redis, MinIO) and
 * Prometheus. Target environments never run here; this is the management
 * plane the workers talk to.
 *
 * Exposure: every published port binds to 127.0.0.1. Secrets are generated
 * once by the CLI and stored as encrypted Pulumi config, never in source.
 */
export interface PlatformConfig {
  ports: { temporal: number; langfuse: number; prometheus: number; metrics: number };
  secrets: {
    temporalDb: pulumi.Output<string>; langfuseDb: pulumi.Output<string>; clickhouse: pulumi.Output<string>;
    redis: pulumi.Output<string>; minio: pulumi.Output<string>; salt: pulumi.Output<string>;
    encryptionKey: pulumi.Output<string>; nextauth: pulumi.Output<string>;
    initUserPassword: pulumi.Output<string>; lfPublicKey: pulumi.Output<string>; lfSecretKey: pulumi.Output<string>;
  };
}

const LOCAL = "127.0.0.1";
const labels = [{ label: "musearena.plane", value: "platform" }];

function image(name: string, ref: string) {
  return new docker.RemoteImage(name, { name: ref, keepLocally: true });
}

export function platform(cfg: PlatformConfig) {
  const net = new docker.Network("platform-net", { name: "musearena-platform", labels });
  const attach = (aliases: string[]) => [{ name: net.name, aliases }];
  const vol = (n: string) => new docker.Volume(n, { name: `musearena-${n}`, labels });

  // ---------- Temporal ----------
  const temporalDb = new docker.Container("temporal-db", {
    name: "musearena-platform-temporal-db", image: image("img-postgres16", "postgres:16-alpine").imageId,
    envs: [pulumi.interpolate`POSTGRES_PASSWORD=${cfg.secrets.temporalDb}`, "POSTGRES_USER=temporal"],
    volumes: [{ volumeName: vol("temporal-db").name, containerPath: "/var/lib/postgresql/data" }],
    networksAdvanced: attach(["temporal-db"]), restart: "unless-stopped", labels,
    healthcheck: { tests: ["CMD-SHELL", "pg_isready -U temporal"], interval: "3s", timeout: "3s", retries: 20 },
    wait: true, waitTimeout: 120,
  });
  const temporal = new docker.Container("temporal", {
    name: "musearena-platform-temporal", image: image("img-temporal", "temporalio/auto-setup:1.24.2").imageId,
    envs: ["DB=postgres12", "DB_PORT=5432", "POSTGRES_USER=temporal", pulumi.interpolate`POSTGRES_PWD=${cfg.secrets.temporalDb}`, "POSTGRES_SEEDS=temporal-db"],
    ports: [{ internal: 7233, external: cfg.ports.temporal, ip: LOCAL }],
    networksAdvanced: attach(["temporal"]), restart: "unless-stopped", labels,
  }, { dependsOn: [temporalDb] });

  // ---------- Langfuse v3 ----------
  const lfDb = new docker.Container("langfuse-db", {
    name: "musearena-platform-langfuse-db", image: image("img-postgres16-lf", "postgres:16-alpine").imageId,
    envs: [pulumi.interpolate`POSTGRES_PASSWORD=${cfg.secrets.langfuseDb}`, "POSTGRES_USER=langfuse", "POSTGRES_DB=langfuse", "TZ=UTC", "PGTZ=UTC"],
    volumes: [{ volumeName: vol("langfuse-db").name, containerPath: "/var/lib/postgresql/data" }],
    networksAdvanced: attach(["langfuse-db"]), restart: "unless-stopped", labels,
    healthcheck: { tests: ["CMD-SHELL", "pg_isready -U langfuse"], interval: "3s", timeout: "3s", retries: 20 },
    wait: true, waitTimeout: 120,
  });
  const clickhouse = new docker.Container("clickhouse", {
    name: "musearena-platform-clickhouse", image: image("img-clickhouse", "clickhouse/clickhouse-server:24.12").imageId,
    user: "101:101",
    envs: ["CLICKHOUSE_DB=default", "CLICKHOUSE_USER=clickhouse", pulumi.interpolate`CLICKHOUSE_PASSWORD=${cfg.secrets.clickhouse}`],
    volumes: [{ volumeName: vol("clickhouse").name, containerPath: "/var/lib/clickhouse" }],
    networksAdvanced: attach(["clickhouse"]), restart: "unless-stopped", labels,
    healthcheck: { tests: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:8123/ping || exit 1"], interval: "5s", timeout: "5s", retries: 20 },
    wait: true, waitTimeout: 180,
  });
  const redis = new docker.Container("redis", {
    name: "musearena-platform-redis", image: image("img-redis", "redis:7-alpine").imageId,
    command: pulumi.all([cfg.secrets.redis]).apply(([pw]) => ["redis-server", "--requirepass", pw, "--maxmemory-policy", "noeviction"]),
    volumes: [{ volumeName: vol("redis").name, containerPath: "/data" }],
    networksAdvanced: attach(["redis"]), restart: "unless-stopped", labels,
    healthcheck: { tests: ["CMD", "redis-cli", "--no-auth-warning", "ping"], interval: "3s", timeout: "5s", retries: 20 },
  });
  const minio = new docker.Container("minio", {
    name: "musearena-platform-minio", image: image("img-minio", "cgr.dev/chainguard/minio:latest").imageId,
    entrypoints: ["sh"], command: ["-c", "mkdir -p /data/langfuse && minio server --address :9000 --console-address :9001 /data"],
    envs: ["MINIO_ROOT_USER=minio", pulumi.interpolate`MINIO_ROOT_PASSWORD=${cfg.secrets.minio}`],
    volumes: [{ volumeName: vol("minio").name, containerPath: "/data" }],
    networksAdvanced: attach(["minio"]), restart: "unless-stopped", labels,
    healthcheck: { tests: ["CMD", "mc", "ready", "local"], interval: "2s", timeout: "5s", retries: 30 },
    wait: true, waitTimeout: 120,
  });

  const lfEnv = pulumi.all([cfg.secrets.langfuseDb, cfg.secrets.clickhouse, cfg.secrets.redis, cfg.secrets.minio, cfg.secrets.salt, cfg.secrets.encryptionKey, cfg.secrets.nextauth])
    .apply(([db, ch, rd, mn, salt, enc, na]) => [
      `DATABASE_URL=postgresql://langfuse:${db}@langfuse-db:5432/langfuse`,
      `SALT=${salt}`, `ENCRYPTION_KEY=${enc}`, `NEXTAUTH_SECRET=${na}`,
      `NEXTAUTH_URL=http://localhost:${cfg.ports.langfuse}`, "TELEMETRY_ENABLED=false",
      "CLICKHOUSE_MIGRATION_URL=clickhouse://clickhouse:9000", "CLICKHOUSE_URL=http://clickhouse:8123",
      "CLICKHOUSE_USER=clickhouse", `CLICKHOUSE_PASSWORD=${ch}`, "CLICKHOUSE_CLUSTER_ENABLED=false",
      "REDIS_HOST=redis", "REDIS_PORT=6379", `REDIS_AUTH=${rd}`,
      ...["EVENT", "MEDIA"].flatMap((k) => [
        `LANGFUSE_S3_${k}_UPLOAD_BUCKET=langfuse`, `LANGFUSE_S3_${k}_UPLOAD_REGION=auto`,
        `LANGFUSE_S3_${k}_UPLOAD_ACCESS_KEY_ID=minio`, `LANGFUSE_S3_${k}_UPLOAD_SECRET_ACCESS_KEY=${mn}`,
        `LANGFUSE_S3_${k}_UPLOAD_ENDPOINT=http://minio:9000`, `LANGFUSE_S3_${k}_UPLOAD_FORCE_PATH_STYLE=true`,
        `LANGFUSE_S3_${k}_UPLOAD_PREFIX=${k === "EVENT" ? "events/" : "media/"}`,
      ]),
    ]);
  const deps = { dependsOn: [lfDb, clickhouse, redis, minio] };
  new docker.Container("langfuse-worker", {
    name: "musearena-platform-langfuse-worker", image: image("img-langfuse-worker", "langfuse/langfuse-worker:3").imageId,
    envs: lfEnv, networksAdvanced: attach(["langfuse-worker"]), restart: "unless-stopped", labels,
  }, deps);
  // Headless init: org/project/API keys for the MuseArena workers (Langfuse LANGFUSE_INIT_*).
  const webEnv = pulumi.all([lfEnv, cfg.secrets.initUserPassword, cfg.secrets.lfPublicKey, cfg.secrets.lfSecretKey]).apply(([base, pw, pk, sk]) => [
    ...base,
    "LANGFUSE_INIT_ORG_ID=musearena", "LANGFUSE_INIT_ORG_NAME=MuseArena",
    "LANGFUSE_INIT_PROJECT_ID=musearena-runs", "LANGFUSE_INIT_PROJECT_NAME=MuseArena runs",
    `LANGFUSE_INIT_PROJECT_PUBLIC_KEY=${pk}`, `LANGFUSE_INIT_PROJECT_SECRET_KEY=${sk}`,
    "LANGFUSE_INIT_USER_EMAIL=admin@musearena.local", "LANGFUSE_INIT_USER_NAME=MuseArena admin", `LANGFUSE_INIT_USER_PASSWORD=${pw}`,
  ]);
  const langfuseWeb = new docker.Container("langfuse-web", {
    name: "musearena-platform-langfuse-web", image: image("img-langfuse-web", "langfuse/langfuse:3").imageId,
    envs: webEnv, ports: [{ internal: 3000, external: cfg.ports.langfuse, ip: LOCAL }],
    networksAdvanced: attach(["langfuse-web"]), restart: "unless-stopped", labels,
  }, deps);

  // ---------- Prometheus ----------
  // Scrapes the worker's /metrics on the host (host.docker.internal on Docker Desktop).
  const promConfig = [
    "global: { scrape_interval: 15s }",
    "scrape_configs:",
    "  - job_name: musearena-worker",
    "    static_configs:",
    `      - targets: ['host.docker.internal:${cfg.ports.metrics}']`,
    "",
  ].join("\n");
  const prometheus = new docker.Container("prometheus", {
    name: "musearena-platform-prometheus", image: image("img-prometheus", "prom/prometheus:v2.55.1").imageId,
    uploads: [{ file: "/etc/prometheus/prometheus.yml", content: promConfig }],
    ports: [{ internal: 9090, external: cfg.ports.prometheus, ip: LOCAL }],
    hosts: [{ host: "host.docker.internal", ip: "host-gateway" }],
    volumes: [{ volumeName: vol("prometheus").name, containerPath: "/prometheus" }],
    networksAdvanced: attach(["prometheus"]), restart: "unless-stopped", labels,
  });

  return {
    temporalAddress: pulumi.interpolate`${LOCAL}:${cfg.ports.temporal}`,
    langfuseHost: pulumi.interpolate`http://${LOCAL}:${cfg.ports.langfuse}`,
    prometheusUrl: pulumi.interpolate`http://${LOCAL}:${cfg.ports.prometheus}`,
    containers: [temporal.name, langfuseWeb.name, prometheus.name],
  };
}

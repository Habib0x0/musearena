// SPDX-License-Identifier: Apache-2.0
import { LocalWorkspace, type Stack } from "@pulumi/pulumi/automation/index.js";
import * as pulumi from "@pulumi/pulumi";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { platform } from "./platform.js";

/**
 * Platform plane CLI: `up | destroy | status`.
 *
 * State: local file backend under deployment/.pulumi-state (gitignored).
 * Secrets: generated on first `up` and stored as ENCRYPTED stack config; the
 * passphrase comes from PULUMI_CONFIG_PASSPHRASE or a 0600 file under
 * ~/.musearena (created once). Nothing secret is printed except the env file
 * the CLI writes for the worker (0600, gitignored).
 */
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const stateDir = path.join(root, ".pulumi-state");
const passFile = path.join(process.env.HOME ?? "/tmp", ".musearena", "platform-passphrase");

function passphrase(): string {
  if (process.env.PULUMI_CONFIG_PASSPHRASE) return process.env.PULUMI_CONFIG_PASSPHRASE;
  if (!existsSync(passFile)) {
    mkdirSync(path.dirname(passFile), { recursive: true, mode: 0o700 });
    writeFileSync(passFile, randomBytes(24).toString("hex"), { mode: 0o600 });
  }
  return readFileSync(passFile, "utf8").trim();
}

const SECRET_KEYS = ["temporalDb", "langfuseDb", "clickhouse", "redis", "minio", "salt", "encryptionKey", "nextauth", "initUserPassword", "lfPublicKey", "lfSecretKey"] as const;
const PORTS = { temporal: Number(process.env.PLATFORM_TEMPORAL_PORT ?? 7234), langfuse: Number(process.env.PLATFORM_LANGFUSE_PORT ?? 3100), prometheus: Number(process.env.PLATFORM_PROMETHEUS_PORT ?? 9095), metrics: Number(process.env.WORKER_METRICS_PORT ?? 9464), api: Number(process.env.MUSEARENA_API_PORT ?? 8788) };

async function stack(): Promise<Stack> {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const s = await LocalWorkspace.createOrSelectStack({
    stackName: "local", projectName: "musearena-platform",
    program: async () => {
      const c = new pulumi.Config();
      const secrets = Object.fromEntries(SECRET_KEYS.map((k) => [k, c.requireSecret(k)])) as Record<(typeof SECRET_KEYS)[number], pulumi.Output<string>>;
      return platform({ ports: PORTS, secrets });
    },
  }, { envVars: { PULUMI_BACKEND_URL: `file://${stateDir}`, PULUMI_CONFIG_PASSPHRASE: passphrase() } });
  const existing = await s.getAllConfig();
  for (const k of SECRET_KEYS) {
    if (existing[`musearena-platform:${k}`]) continue;
    const value = k === "encryptionKey" ? randomBytes(32).toString("hex")
      : k === "lfPublicKey" ? `pk-lf-${randomBytes(16).toString("hex")}`
      : k === "lfSecretKey" ? `sk-lf-${randomBytes(16).toString("hex")}`
      : randomBytes(24).toString("hex");
    await s.setConfig(k, { value, secret: true });
  }
  return s;
}

async function waitHttp(url: string, ok: (r: Response) => boolean, timeoutMs: number): Promise<boolean> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (ok(await fetch(url))) return true; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 3000));
  }
  return false;
}

async function main() {
  const cmd = process.argv[2] ?? "status";
  const s = await stack();
  if (cmd === "destroy") { await s.destroy({ onOutput: process.stdout.write.bind(process.stdout) }); return; }
  if (cmd === "up") await s.up({ onOutput: process.stdout.write.bind(process.stdout) });
  const out = await s.outputs();
  const cfg = await s.getAllConfig();
  const get = (k: string) => cfg[`musearena-platform:${k}`]?.value ?? "";
  const langfuse = String(out.langfuseHost?.value ?? "");
  const ready = langfuse ? await waitHttp(`${langfuse}/api/public/health`, (r) => r.ok, cmd === "up" ? 300_000 : 5_000) : false;
  const envFile = path.join(root, ".platform.env");
  writeFileSync(envFile, [
    `TEMPORAL_ADDRESS=${out.temporalAddress?.value ?? ""}`,
    `LANGFUSE_HOST=${langfuse}`,
    `LANGFUSE_PUBLIC_KEY=${get("lfPublicKey")}`,
    `LANGFUSE_SECRET_KEY=${get("lfSecretKey")}`,
    `WORKER_METRICS_PORT=${PORTS.metrics}`,
    `MUSEARENA_API_PORT=${PORTS.api}`,
    "",
  ].join("\n"), { mode: 0o600 });
  console.log(JSON.stringify({ temporal: out.temporalAddress?.value, langfuse, langfuseHealthy: ready, prometheus: out.prometheusUrl?.value, workerEnvFile: envFile }, null, 2));
  if (cmd === "up" && !ready) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });

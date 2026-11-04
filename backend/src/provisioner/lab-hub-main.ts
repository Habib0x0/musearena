import { serveLabHub } from "./lab-hub.js";

// Detached per-run hub process: `<node> lab-hub-main.js <port> <runId>`.
// The run id is only for `pgrep` when a destroy missed the registry entry.
const port = Number(process.argv[2]);
const runId = process.argv[3] ?? "unknown";
if (!Number.isInteger(port) || port < 1024 || port > 65535) {
  console.error(`lab-hub: invalid port ${process.argv[2]} (run ${runId})`);
  process.exit(2);
}
const server = serveLabHub(port);
server.on("error", (e) => {
  console.error(`lab-hub: ${runId} could not listen on ${port}: ${e.message}`);
  process.exit(1);
});
const stop = () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 1000).unref(); };
process.on("SIGTERM", stop);
process.on("SIGINT", stop);

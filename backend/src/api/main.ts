// SPDX-License-Identifier: Apache-2.0
import { startApiServer } from "./server.js";
import { traceRoutes } from "./traces.js";
import { reviewRoutes } from "./review.js";
import { signalRoutes } from "./signals.js";
import { graderRoutes } from "./graders.js";
import { modelRoutes } from "./models.js";
import { datasetRoutes } from "./datasets.js";
import { runRoutes } from "./runs.js";
import { trainingRoutes } from "./training.js";
import { evaluationRoutes } from "./evaluations.js";
import { deploymentRoutes } from "./deployments.js";
import { continualRoutes } from "./continual.js";
import { overviewRoutes } from "./overview.js";
import { adminRoutes } from "./admin.js";

/**
 * Entry point for the learning API host (F-16). A host process like the
 * worker — not a Pulumi container; `.platform.env` carries its port.
 */
const server = startApiServer({ routes: [...traceRoutes(), ...reviewRoutes(), ...signalRoutes(), ...graderRoutes(), ...modelRoutes(), ...datasetRoutes(), ...runRoutes(), ...trainingRoutes(), ...evaluationRoutes(), ...deploymentRoutes(), ...continualRoutes(), ...overviewRoutes(), ...adminRoutes()] });

let closing = false;
const shutdown = () => {
  if (closing) return;
  closing = true;
  server.close(() => process.exit(0));
};
process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);

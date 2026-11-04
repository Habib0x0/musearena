import { localStore, EventStore, type TrajectoryStep } from "./events.js";

/**
 * Trajectory recording (Req §4.1). Langfuse is the production sink (LLM/agent
 * spans keyed by run_id); this recorder keeps the same span shape locally so
 * the join/export path is testable without Langfuse credentials.
 */
export interface TrajectoryRecorder {
  record(step: TrajectoryStep): TrajectoryStep;
}

export class LocalTrajectoryRecorder implements TrajectoryRecorder {
  constructor(private store: EventStore = localStore) {}
  record(step: TrajectoryStep): TrajectoryStep {
    if (!step.runId?.trim()) throw new Error("trajectory step missing runId");
    return this.store.appendTrajectory(step);
  }
}

export const localRecorder: TrajectoryRecorder = new LocalTrajectoryRecorder();

import { createHash } from "node:crypto";
import type { Actor, Outcome } from "@musearena/shared";

/** Ground-truth event (Req §4.2): process/network/file/auth from the out-of-band plane. */
export interface GroundTruthEvent {
  runId: string;
  hostId: string;
  kind: string; // sensor kind: process | network | file | auth | zeek.* | persona routine kinds…
  actor: Actor;
  techniqueId?: string; // MITRE ATT&CK, attached at ingest (§4.5)
  stepId?: string; // Atomic GUID
  outcome?: Outcome;
  at: string; // ISO timestamp; join uses skew tolerance (§9)
  detail?: Record<string, unknown>;
}

/** Agent trajectory step (Req §4.1): Langfuse span shape, keyed by runId. */
export interface TrajectoryStep {
  runId: string;
  hostId?: string;
  actor: "red" | "blue" | "persona";
  observation: string;
  reasoning?: string;
  toolCall?: string;
  action?: string;
  techniqueId?: string;
  at: string;
  /**
   * Structured action payload (tool argv, cited evidence, guardrail verdict).
   * When present this, not the prose observation, is the machine-readable
   * source of a training example (Req §2.1.2).
   */
  detail?: Record<string, unknown>;
}

interface Stored<T> { seq: number; hash: string; prevHash: string; value: T }

/** Append-only, hash-chained store. Production backs this with Postgres;
 *  the local store keeps the same chain semantics for tests/dev. */
export class EventStore {
  /** Test isolation: numbered instances keep parallel runs independent. */
  static fresh(): EventStore { return new EventStore(); }

  private gt: Stored<GroundTruthEvent>[] = [];
  private traj: Stored<TrajectoryStep>[] = [];

  private chain<T>(list: Stored<T>[], value: T): Stored<T> {
    const prevHash = list.length ? list[list.length - 1].hash : "genesis";
    const hash = createHash("sha256").update(prevHash + JSON.stringify(value)).digest("hex");
    const row: Stored<T> = { seq: list.length + 1, hash, prevHash, value };
    list.push(row);
    return row;
  }

  appendGroundTruth(e: GroundTruthEvent): GroundTruthEvent { return this.chain(this.gt, e).value; }
  appendTrajectory(s: TrajectoryStep): TrajectoryStep { return this.chain(this.traj, s).value; }

  groundTruth(runId?: string): GroundTruthEvent[] {
    return this.gt.map((r) => r.value).filter((e) => !runId || e.runId === runId);
  }
  trajectory(runId?: string): TrajectoryStep[] {
    return this.traj.map((r) => r.value).filter((e) => !runId || e.runId === runId);
  }

  verifyChain(): boolean {
    const ok = <T,>(list: Stored<T>[]) => list.every((r, i) =>
      r.prevHash === (i === 0 ? "genesis" : list[i - 1].hash) &&
      r.hash === createHash("sha256").update(r.prevHash + JSON.stringify(r.value)).digest("hex"));
    return ok(this.gt) && ok(this.traj);
  }

  counts(): { groundTruth: number; trajectory: number } {
    return { groundTruth: this.gt.length, trajectory: this.traj.length };
  }
}

/** Shared local instance (single-writer worker process). */
export const localStore = new EventStore();

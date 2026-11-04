import { z } from "zod";
import type { CaptureTrace } from "@musearena/shared";

/**
 * Source-neutral importer for exported agent-run logs.
 *
 * The platform does not prescribe a vendor format. An exporter maps its run to
 * this shape and posts the resulting steps through the capture endpoint, so an
 * imported run is stored exactly like a platform trace (same row, same
 * provenance columns) and can be selected by the dataset builder.
 *
 *   {
 *     "runId": "run-...",
 *     "framework": "caller-named source system",
 *     "source": "imported" | "field",
 *     "steps": [
 *       { "at": "...", "host": "web-01", "actor": "red", "technique": "T1190",
 *         "tool": "curl", "command": ["curl","-s","http://web-01/login"],
 *         "output": "...", "outcome": "succeeded" }
 *     ]
 *   }
 */
export const ExternalOutcome = z.enum(["attempted", "succeeded", "failed", "detected", "contained"]);

export const ExternalStep = z.object({
  at: z.string().refine((value) => Number.isFinite(Date.parse(value)), "not an ISO timestamp"),
  host: z.string().default(""),
  actor: z.enum(["red", "blue", "persona"]).default("red"),
  technique: z.string().min(1).optional(),
  tool: z.string().min(1).optional(),
  command: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]).optional(),
  output: z.string().optional(),
  observation: z.string().optional(),
  outcome: ExternalOutcome.optional(),
  matched: z.boolean().optional(),
  detail: z.record(z.unknown()).optional(),
}).strict();
export type ExternalStep = z.infer<typeof ExternalStep>;

export const ExternalRunExport = z.object({
  runId: z.string().min(1),
  /** Caller-named source system, recorded for lineage and shown as-is. */
  framework: z.string().trim().min(1).max(120).optional(),
  /** imported = exported agent run; field = real operator-provided observation. */
  source: z.enum(["imported", "field"]).default("imported"),
  steps: z.array(ExternalStep).min(1),
}).strict();
export type ExternalRunExport = z.infer<typeof ExternalRunExport>;

function splitCommand(command: string | string[]): { argv: string[]; rendered: string } {
  if (Array.isArray(command)) return { argv: command, rendered: command.join(" ") };
  return { argv: command.trim().split(/\s+/), rendered: command };
}

/**
 * Map one export to capture bodies. `action` stays the program name and
 * `toolCall` carries the full command, matching the platform's own trace shape.
 */
export function toCaptureTraces(input: ExternalRunExport): CaptureTrace[] {
  return input.steps.map((step, stepIndex) => {
    const command = step.command ? splitCommand(step.command) : null;
    const action = command?.argv[0] ?? step.tool;
    const toolCall = command?.rendered ?? step.tool;
    return {
      runId: input.runId,
      stepIndex,
      at: step.at,
      hostId: step.host,
      actor: step.actor,
      techniqueId: step.technique,
      observation: step.observation ?? step.output?.slice(0, 2000),
      toolCall,
      action,
      outcome: step.outcome,
      matched: step.matched ?? false,
      split: "train",
      source: input.source,
      framework: input.framework,
      detail: {
        ...step.detail,
        imported: {
          framework: input.framework ?? null,
          tool: step.tool ?? null,
          output: step.output ?? null,
        },
      },
    };
  });
}

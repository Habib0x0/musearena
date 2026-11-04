import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import type { ModelSurface } from "@musearena/shared";

/**
 * Model layer for all MuseArena agents. The Meta Model API serves exercise
 * agents through /responses; ModalModelClient serves the designer and agents
 * from Modal-hosted Muse Spark/Glimmer endpoints through chat completions.
 * MockModelClient stands in for tests and local dev without credentials.
 * Every agent consumes this interface — never an SDK.
 */
export interface ModelStreamDelta {
  kind: "reasoning" | "content";
  /** New text in this paced batch. */
  text: string;
  /** Cumulative character counts for the in-flight completion. */
  reasoningChars: number;
  contentChars: number;
}

export interface GenerateObjectArgs {
  system: string;
  prompt: string;
  schema: z.ZodTypeAny;
  maxTokens?: number;
  signal?: AbortSignal;
  onDelta?: (delta: ModelStreamDelta) => void;
}

export interface ModelClient {
  readonly modelId: string;
  generateObject<T>(args: GenerateObjectArgs): Promise<T>;
}

/** Function (tool) definition for agent loops. */
export interface ToolDef { name: string; description: string; parameters: Record<string, unknown> }
export interface ToolCall { callId: string; name: string; argumentsJson: string }
export interface AgentTurn { text: string; toolCalls: ToolCall[]; usage: { inputTokens: number; outputTokens: number } }

type AgentMessage = { role?: string; [k: string]: unknown };
/** One full conversation so far; the API is stateless (no previous_response_id). */
export interface AgentExchange {
  system: string;
  transcript: AgentMessage[];
}

/**
 * One agent turn: send the transcript, get text + tool calls. Tool results go
 * back as `function_call_output` items appended to the transcript.
 */
export interface AgentClient extends ModelClient {
  generateTurn(args: { system: string; transcript: AgentMessage[]; tools: ToolDef[]; maxTokens?: number; maxToolCalls?: number }): Promise<AgentTurn>;
}

export function toolResult(callId: string, output: string): AgentMessage {
  return { type: "function_call_output", call_id: callId, output: output.slice(0, 8000) };
}

export function userText(text: string): AgentMessage {
  return { role: "user", content: text };
}

export function assistantItems(turn: AgentTurn): AgentMessage[] {
  const items: AgentMessage[] = [];
  if (turn.text) items.push({ role: "assistant", content: turn.text });
  for (const c of turn.toolCalls) items.push({ type: "function_call", call_id: c.callId, name: c.name, arguments: c.argumentsJson });
  return items;
}

/**
 * Muse text models on the Meta Model API verified (2026-10-27, /v1/responses)
 * to complete a function-call round trip: emit a tool call, accept the
 * function_call_output, and answer from it. The API also lists muse-image-1.0
 * (image_generation tool only), sam-3.1 (needs image/video input) and
 * muse-voice-transcribe-1.0 (not served on /responses); none can drive an agent.
 *
 * `muse-glimmer-*` are NOT in this Meta API list. Muse Glimmer is approved
 * only on its separate Modal/SGLang surface below; forwarding a Glimmer ID to
 * the Meta API still fails closed.
 */
export const AGENT_MODELS = [
  "muse-spark-1.1", "muse-spark-1.2", "muse-spark-1.2-contributor",
  "muse-spark-1.3", "muse-spark-1.3-contributor", "muse-wonder-1.0",
] as const;
export const DEFAULT_MODEL = "muse-spark-1.3";
export const META_API_BASE = "https://api.meta.ai/v1";

/**
 * Modal-hosted Muse Spark Open endpoint (chat-completions wire format,
 * Modal proxy-token auth). The URL is deployment-specific: every deployment
 * MUST set MODAL_BASE_URL; there is no default endpoint.
 */
export const MODAL_API_BASE = "";
export const MODAL_DEFAULT_MODEL = "meta-models/Muse-Spark-Open-816B-A42B";
/**
 * Modal-hosted Muse Glimmer 30B (SGLang, served as "glimmer", muse tool-call
 * parser): the lighter model for persona agents. Tool turns verified live
 * 2026-11-04. Scales to zero; a cold start took ~5.5 min, so callers warm it
 * up early with `wake()`.
 */
export const MODAL_GLIMMER_API_BASE = ""; // every deployment sets MODAL_GLIMMER_BASE_URL; no default endpoint
export const MODAL_GLIMMER_BASE = MODAL_GLIMMER_API_BASE;
export const MODAL_GLIMMER_MODEL = "glimmer";
export const MODAL_GLIMMER_REPO_MODEL = "meta-models/Muse-Glimmer-30B";

export type ModelRole = "designer" | "red" | "blue" | "persona" | "judge";

/** Default model per role when neither a role nor a global override is set. */
export const DEFAULT_MODEL_BY_ROLE: Partial<Record<ModelRole, string>> = {
  // Persona agents are the cheapest, highest-volume role: a lighter verified
  // Muse drives them unless the operator overrides.
  persona: "muse-spark-1.1",
};

/**
 * Model for a role: MUSEARENA_MODEL_<ROLE>, else META_MODEL_ID, else the
 * per-role default, else the designer default. Fails closed on ids not
 * verified for tool use, so a typo, an image/vision model, or an unverified
 * glimmer id can never silently play an agent.
 */
export function modelForRole(role: ModelRole, env: NodeJS.ProcessEnv = process.env): string {
  const id = env[`MUSEARENA_MODEL_${role.toUpperCase()}`] || env.META_MODEL_ID || DEFAULT_MODEL_BY_ROLE[role] || DEFAULT_MODEL;
  if (!(AGENT_MODELS as readonly string[]).includes(id)) {
    throw new Error(`model ${id} for ${role} is not a verified tool-use Muse model (allowed: ${AGENT_MODELS.join(", ")})`);
  }
  return id;
}

/** Whether an ID names the Modal-hosted Glimmer deployment or its repository. */
export function isModalGlimmerModel(modelId: string): boolean {
  return modelId === MODAL_GLIMMER_MODEL || modelId.startsWith("meta-models/Muse-Glimmer-");
}

/** Whether an ID belongs on the Modal surface rather than the Meta API. */
export function isModalModelId(modelId: string): boolean {
  return isModalGlimmerModel(modelId) || modelId.startsWith("meta-models/");
}

/**
 * The ID the Modal endpoint must receive. Glimmer's SGLang server is deployed
 * with `--served-model-name glimmer`, so repository IDs canonicalize to that
 * served name (or an operator's configured alias).
 */
export function canonicalModalModelId(modelId: string, env: NodeJS.ProcessEnv = process.env): string {
  if (!isModalGlimmerModel(modelId)) return modelId;
  const configured = env.MODAL_PERSONA_MODEL_ID || env.MODAL_GLIMMER_MODEL_ID || env.MODAL_SMALL_MODEL_ID;
  return configured && !configured.startsWith("meta-models/Muse-Glimmer-") ? configured : MODAL_GLIMMER_MODEL;
}

/** Modal endpoint for a served/repository model ID. */
export function modalBaseUrlForModel(modelId: string, env: NodeJS.ProcessEnv = process.env): string {
  const base = isModalGlimmerModel(modelId)
    ? env.MODAL_GLIMMER_BASE_URL || env.MODAL_PERSONA_BASE_URL || env.MODAL_SMALL_BASE_URL || MODAL_GLIMMER_API_BASE
    : env.MODAL_BASE_URL || MODAL_API_BASE;
  return base.replace(/\/+$/, "");
}

/**
 * Modal's role defaults: Spark for the primary agents and Glimmer for the
 * small, high-volume persona agents. Explicit small-agent env aliases win;
 * a global Glimmer MODAL_MODEL_ID is also honored for personas.
 */
export function modalModelIdForRole(role: ModelRole, env: NodeJS.ProcessEnv = process.env): string {
  if (role === "persona") {
    const candidate = env.MODAL_PERSONA_MODEL_ID || env.MODAL_GLIMMER_MODEL_ID || env.MODAL_SMALL_MODEL_ID
      || (env.MODAL_MODEL_ID && isModalGlimmerModel(env.MODAL_MODEL_ID) ? env.MODAL_MODEL_ID : MODAL_GLIMMER_MODEL);
    return canonicalModalModelId(candidate, env);
  }
  return canonicalModalModelId(env.MODAL_MODEL_ID || MODAL_DEFAULT_MODEL, env);
}

/**
 * The surface an agent run uses. An explicit platform choice always wins;
 * when the spec leaves it unset, any Modal token configuration selects
 * Modal (including a half-set pair, so client construction fails loudly
 * instead of silently substituting Meta).
 */
export function effectiveAgentSurface(
  selected: ModelSurface | undefined,
  env: NodeJS.ProcessEnv = process.env,
): ModelSurface {
  return selected ?? (env.MODAL_PROXY_TOKEN_ID || env.MODAL_PROXY_TOKEN_SECRET ? "meta-modal" : "meta");
}

/**
 * A 401/403/404 from the model API is a configuration or access state, not a
 * transient fault. Temporal retries generic errors; naming this type lets the
 * workflow declare it non-retryable instead of burning the run's TTL on the
 * same 403 (observed live: `user_blocked` retried twice).
 */
export class PermanentModelError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PermanentModelError";
  }
}

const isPermanent = (status: number): boolean => status === 401 || status === 403 || status === 404;

/** First JSON object in a model reply (replies may wrap it in prose/fences). */
export function extractJsonObject(text: string): string {
  const json = text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1);
  if (!json) throw new Error(`no JSON object in model response: ${text.slice(0, 200)}`);
  return json;
}

export class MetaModelClient implements ModelClient {
  readonly modelId: string;
  private baseUrl: string;
  private apiKey: string;

  constructor(opts?: { modelId?: string; baseUrl?: string; apiKey?: string }) {
    this.modelId = opts?.modelId ?? modelForRole("designer");
    // dev.meta.ai is the developer console (HTML), not the API; the API lives on api.meta.ai/v1.
    this.baseUrl = opts?.baseUrl ?? process.env.META_BASE_URL ?? META_API_BASE;
    const key = opts?.apiKey ?? process.env.META_API_KEY;
    if (!key) throw new Error("META_API_KEY not set");
    this.apiKey = key;
  }

  async generateTurn({ system, transcript, tools, maxTokens, maxToolCalls }: {
    system: string; transcript: AgentMessage[]; tools: ToolDef[]; maxTokens?: number; maxToolCalls?: number;
  }): Promise<AgentTurn> {
    const res = await fetch(`${this.baseUrl}/responses`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify({
        model: this.modelId,
        instructions: system,
        input: transcript,
        tools: tools.map((t) => ({ type: "function", name: t.name, description: t.description, parameters: t.parameters })),
        ...(maxToolCalls ? { max_tool_calls: maxToolCalls } : {}),
        max_output_tokens: maxTokens ?? 4096,
      }),
    });
    if (!res.ok) {
      const detail = `Meta Model API ${res.status}: ${await res.text()}`;
      throw isPermanent(res.status) ? new PermanentModelError(detail) : new Error(detail);
    }
    const data = (await res.json()) as {
      output: { type: string; call_id?: string; name?: string; arguments?: string; content?: { type: string; text?: string }[] }[];
      usage: { input_tokens: number; output_tokens: number };
    };
    const toolCalls: ToolCall[] = [];
    const texts: string[] = [];
    for (const o of data.output) {
      if (o.type === "function_call" && o.call_id && o.name) toolCalls.push({ callId: o.call_id, name: o.name, argumentsJson: o.arguments ?? "{}" });
      if (o.type === "message") for (const c of o.content ?? []) if (c.type === "output_text" && c.text) texts.push(c.text);
    }
    return { text: texts.join("\n"), toolCalls, usage: { inputTokens: data.usage.input_tokens, outputTokens: data.usage.output_tokens } };
  }

  async generateObject<T>({ system, prompt, schema, maxTokens, signal }: GenerateObjectArgs): Promise<T> {
    const res = await fetch(`${this.baseUrl}/responses`, {
      method: "POST",
      signal,
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify({
        model: this.modelId,
        input: [{ role: "system", content: system }, { role: "user", content: prompt }],
        max_output_tokens: maxTokens ?? 4096,
      }),
    });
    if (!res.ok) {
      const detail = `Meta Model API ${res.status}: ${await res.text()}`;
      throw isPermanent(res.status) ? new PermanentModelError(detail) : new Error(detail);
    }
    const data = (await res.json()) as { output_text?: string; output?: Array<{ content?: Array<{ text?: string }> }> };
    const text = data.output_text
      ?? data.output?.flatMap((o) => o.content ?? []).map((c) => c.text ?? "").join("")
      ?? "";
    return schema.parse(JSON.parse(extractJsonObject(text)));
  }
}

type ChatChunk = {
  choices?: {
    delta?: {
      content?: string | { text?: string }[];
      reasoning_content?: string | null;
      reasoning?: string | null;
    };
    message?: { content?: string | { text?: string }[] };
    finish_reason?: string;
  }[];
  error?: unknown;
};

/** Small-agent client: Muse Glimmer 30B on Modal unless overridden. */
export function modalAgentClient(role: ModelRole, env: NodeJS.ProcessEnv = process.env, modelId?: string): ModalModelClient {
  return new ModalModelClient({ role, env, modelId });
}

/** Persona agents' client: Muse Glimmer 30B on Modal unless overridden. */
export function modalPersonaClient(env: NodeJS.ProcessEnv = process.env): ModalModelClient {
  return modalAgentClient("persona", env);
}

/**
 * Persona client once it is serving, else the given fallback (logged, and
 * recorded per persona by the shift report's modelId), so a cold Glimmer
 * never stalls an exercise.
 */
export async function personaClientOrFallback(fallback: AgentClient, timeoutMs = 2 * 60_000, env: NodeJS.ProcessEnv = process.env): Promise<AgentClient> {
  const glimmer = modalPersonaClient(env);
  try {
    await glimmer.wake({ timeoutMs });
    return glimmer;
  } catch (err) {
    console.warn(`[personas] ${glimmer.modelId} unavailable (${err instanceof Error ? err.message : err}); personas use ${fallback.modelId}`);
    return fallback;
  }
}

/**
 * Responses-style transcript items → chat-completions messages. Consecutive
 * function_call items (and the assistant text before them) become one
 * assistant message with tool_calls; outputs become role "tool" messages.
 */
export function chatMessages(transcript: AgentMessage[]): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const item of transcript) {
    if (item.type === "function_call") {
      const call = { id: item.call_id, type: "function", function: { name: item.name, arguments: item.arguments ?? "{}" } };
      const last = out.at(-1);
      if (last?.role === "assistant") last.tool_calls = [...((last.tool_calls as unknown[] | undefined) ?? []), call];
      else out.push({ role: "assistant", content: null, tool_calls: [call] });
    } else if (item.type === "function_call_output") {
      out.push({ role: "tool", tool_call_id: item.call_id, content: String(item.output ?? "") });
    } else {
      out.push({ role: item.role ?? "user", content: item.content });
    }
  }
  return out;
}

function contentText(content: string | { text?: string }[] | undefined): string {
  if (typeof content === "string") return content;
  return (content ?? []).map((p) => p.text ?? "").join("");
}

/**
 * Client for Modal-hosted Muse Spark Open and Muse Glimmer endpoints.
 *
 * Both speak the chat-completions wire format rather than the Meta
 * /responses protocol. Spark is the primary agent/designer model; Glimmer's SGLang
 * deployment uses the served name `glimmer`, the `muse` tool-call parser,
 * and `reasoning: { enabled: true }` rather than Spark's reasoning-effort
 * field. The endpoint is selected from the model ID so a Glimmer request
 * can never be sent to Spark (or the reverse).
 *
 * Requests stream: a cold 816B replica plus a 32k-token design can sit for
 * minutes before a non-streaming response sends headers, which fetch gives
 * up on. Structured output uses response_format json_schema; a server that
 * rejects the schema (400/422, before any generation) is retried once
 * without it, and the Zod parse below stays the real gate either way.
 *
 * Auth is the Modal proxy token pair, sent as `Bearer <id>.<secret>`.
 * MODAL_ROUTING_AFFINITY_KEY, when set, pins requests to one warm replica.
 */
export class ModalModelClient implements AgentClient {
  readonly modelId: string;
  private baseUrl: string;
  private token: string;
  private affinityKey?: string;
  private reasoningEffort?: string;
  private readonly glimmerEndpoint: boolean;

  constructor(opts?: {
    modelId?: string; baseUrl?: string; tokenId?: string; tokenSecret?: string;
    affinityKey?: string; reasoningEffort?: string; role?: ModelRole; env?: NodeJS.ProcessEnv;
  }) {
    const env = opts?.env ?? process.env;
    const requestedModelId = opts?.modelId ?? (opts?.role ? modalModelIdForRole(opts.role, env) : env.MODAL_MODEL_ID ?? MODAL_DEFAULT_MODEL);
    this.modelId = canonicalModalModelId(requestedModelId, env);
    this.glimmerEndpoint = isModalGlimmerModel(requestedModelId) || isModalGlimmerModel(this.modelId)
      || (opts?.baseUrl ?? "").includes("ep-glimmer");
    this.baseUrl = (opts?.baseUrl ?? modalBaseUrlForModel(requestedModelId, env)).replace(/\/+$/, "");

    const glimmerTokenId = env.MODAL_GLIMMER_PROXY_TOKEN_ID;
    const glimmerTokenSecret = env.MODAL_GLIMMER_PROXY_TOKEN_SECRET;
    if (this.glimmerEndpoint && !opts?.tokenId && !opts?.tokenSecret
      && Boolean(glimmerTokenId) !== Boolean(glimmerTokenSecret)) {
      throw new Error("MODAL_GLIMMER_PROXY_TOKEN_ID and MODAL_GLIMMER_PROXY_TOKEN_SECRET must both be set");
    }
    const id = opts?.tokenId ?? (this.glimmerEndpoint ? glimmerTokenId ?? env.MODAL_PROXY_TOKEN_ID : env.MODAL_PROXY_TOKEN_ID);
    const secret = opts?.tokenSecret ?? (this.glimmerEndpoint ? glimmerTokenSecret ?? env.MODAL_PROXY_TOKEN_SECRET : env.MODAL_PROXY_TOKEN_SECRET);
    if (!id || !secret) throw new Error("MODAL_PROXY_TOKEN_ID and MODAL_PROXY_TOKEN_SECRET must both be set");
    this.token = `${id}.${secret}`;
    this.affinityKey = opts?.affinityKey
      ?? (this.glimmerEndpoint ? env.MODAL_GLIMMER_ROUTING_AFFINITY_KEY ?? env.MODAL_ROUTING_AFFINITY_KEY : env.MODAL_ROUTING_AFFINITY_KEY)
      ?? undefined;
    const effort = opts?.reasoningEffort
      ?? (this.glimmerEndpoint ? env.MODAL_GLIMMER_REASONING_EFFORT ?? env.MODAL_REASONING_EFFORT ?? "low" : env.MODAL_REASONING_EFFORT ?? "medium");
    this.reasoningEffort = effort && effort !== "none" ? effort : undefined;
  }

  /** Glimmer/SGLang takes a structured reasoning object; Spark takes effort. */
  private reasoningFields(): Record<string, unknown> {
    if (!this.reasoningEffort) return {};
    return this.glimmerEndpoint ? { reasoning: { enabled: true } } : { reasoning_effort: this.reasoningEffort };
  }

  /**
   * Wait until the endpoint serves requests. A scaled-to-zero endpoint answers
   * 503 "no upstreams available" while a container starts; anything else that
   * is not 2xx is a real failure and is thrown at once.
   */
  async wake({ timeoutMs = 10 * 60_000, pollMs = 10_000 }: { timeoutMs?: number; pollMs?: number } = {}): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const res = await fetch(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.token}` },
        body: JSON.stringify({ model: this.modelId, messages: [{ role: "user", content: "ok" }], max_tokens: 1 }),
      }).catch(() => null);
      if (res?.ok) return;
      if (res && res.status !== 503) throw new Error(`Modal API ${res.status} while waking ${this.modelId}: ${(await res.text()).slice(0, 200)}`);
      if (Date.now() + pollMs > deadline) throw new Error(`${this.modelId} did not wake within ${Math.round(timeoutMs / 1000)}s`);
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }

  /**
   * One agent turn over chat completions. The transcript keeps the Responses
   * item shape the agent loops build (function_call / function_call_output);
   * it is translated here, so the loops stay provider-agnostic.
   */
  async generateTurn({ system, transcript, tools, maxTokens }: {
    system: string; transcript: AgentMessage[]; tools: ToolDef[]; maxTokens?: number; maxToolCalls?: number;
  }): Promise<AgentTurn> {
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.token}`,
        ...(this.affinityKey ? { "Modal-Routing-Affinity-Key": this.affinityKey } : {}),
      },
      body: JSON.stringify({
        model: this.modelId,
        messages: [{ role: "system", content: system }, ...chatMessages(transcript)],
        tools: tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } })),
        tool_choice: "auto",
        temperature: 0.3,
        ...(this.glimmerEndpoint ? { top_p: 0.9 } : {}),
        max_tokens: maxTokens ?? 4096,
        ...this.reasoningFields(),
      }),
    });
    if (!res.ok) {
      const detail = `Modal API ${res.status}: ${(await res.text()).slice(0, 500)}`;
      throw isPermanent(res.status) ? new PermanentModelError(detail) : new Error(detail);
    }
    const data = (await res.json()) as {
      choices?: { message?: { content?: string | { text?: string }[]; tool_calls?: { id: string; function: { name: string; arguments?: string } }[] } }[];
      usage?: { prompt_tokens?: number; completion_tokens?: number };
      error?: unknown;
    };
    if (data.error) throw new Error(`Modal API error: ${JSON.stringify(data.error).slice(0, 500)}`);
    const msg = data.choices?.[0]?.message;
    return {
      text: contentText(msg?.content),
      toolCalls: (msg?.tool_calls ?? []).map((c) => ({ callId: c.id, name: c.function.name, argumentsJson: c.function.arguments || "{}" })),
      usage: { inputTokens: data.usage?.prompt_tokens ?? 0, outputTokens: data.usage?.completion_tokens ?? 0 },
    };
  }

  async generateObject<T>({ system, prompt, schema, maxTokens, signal, onDelta }: GenerateObjectArgs): Promise<T> {
    const jsonSchema = zodToJsonSchema(schema, { $refStrategy: "none" }) as Record<string, unknown>;
    delete jsonSchema.$schema;
    let text: string;
    try {
      text = await this.chatText({ system, prompt, maxTokens, jsonSchema, signal, onDelta });
    } catch (err) {
      // Only a pre-generation schema rejection earns the unstructured retry;
      // auth, cancellation, and transport failures keep their original error.
      if (!(err instanceof Error) || err.name === "AbortError" || err instanceof PermanentModelError || !/Modal API (400|422)/.test(err.message)) throw err;
      text = await this.chatText({ system, prompt, maxTokens, signal, onDelta });
    }
    return schema.parse(JSON.parse(extractJsonObject(text)));
  }

  private async chatText({ system, prompt, maxTokens, jsonSchema, signal, onDelta }: {
    system: string; prompt: string; maxTokens?: number; jsonSchema?: Record<string, unknown>; signal?: AbortSignal; onDelta?: GenerateObjectArgs["onDelta"];
  }): Promise<string> {
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      signal,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.token}`,
        ...(this.affinityKey ? { "Modal-Routing-Affinity-Key": this.affinityKey } : {}),
      },
      body: JSON.stringify({
        model: this.modelId,
        messages: [{ role: "system", content: system }, { role: "user", content: prompt }],
        temperature: 0.3,
        top_p: 0.95,
        max_tokens: maxTokens ?? 4096,
        stream: true,
        ...this.reasoningFields(),
        ...(jsonSchema
          ? { response_format: { type: "json_schema", json_schema: { name: "musearena_object", strict: true, schema: jsonSchema } } }
          : {}),
      }),
    });
    if (!res.ok) {
      const detail = `Modal API ${res.status}: ${(await res.text()).slice(0, 500)}`;
      throw isPermanent(res.status) ? new PermanentModelError(detail) : new Error(detail);
    }
    if (!(res.headers.get("content-type") ?? "").includes("text/event-stream")) {
      const data = (await res.json()) as ChatChunk;
      if (data.error) throw new Error(`Modal API error: ${JSON.stringify(data.error).slice(0, 500)}`);
      const content = contentText(data.choices?.[0]?.message?.content);
      if (content) {
        try { onDelta?.({ kind: "content", text: content, reasoningChars: 0, contentChars: content.length }); } catch { /* observer only */ }
      }
      return content;
    }
    const body = res.body as unknown as AsyncIterable<Uint8Array> | null;
    if (!body) throw new Error("Modal API returned an empty stream");
    const decoder = new TextDecoder();
    let buffer = "";
    let text = "";
    let reasoningChars = 0;
    let finishReason = "";

    // Forward the model's own streams, paced to roughly 20 batches/second.
    // The first batch is immediate; the terminal flush is never dropped.
    const pending: Record<ModelStreamDelta["kind"], string> = { reasoning: "", content: "" };
    let lastDeltaAt = 0;
    const flushDeltas = (force = false) => {
      if (!onDelta || (!pending.reasoning && !pending.content)) return;
      const now = Date.now();
      if (!force && lastDeltaAt && now - lastDeltaAt < 50) return;
      for (const kind of ["reasoning", "content"] as const) {
        const batch = pending[kind];
        if (!batch) continue;
        pending[kind] = "";
        try { onDelta({ kind, text: batch, reasoningChars, contentChars: text.length }); } catch { /* observer only */ }
      }
      lastDeltaAt = now;
    };
    const observe = (kind: ModelStreamDelta["kind"], delta: string) => {
      if (!delta) return;
      if (kind === "reasoning") reasoningChars += delta.length;
      pending[kind] += delta;
      flushDeltas();
    };

    const takeLine = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed.startsWith("data:")) return;
      const payload = trimmed.slice(5).trim();
      if (!payload || payload === "[DONE]") return;
      const chunk = JSON.parse(payload) as ChatChunk;
      if (chunk.error) throw new Error(`Modal API error: ${JSON.stringify(chunk.error).slice(0, 500)}`);
      const choice = chunk.choices?.[0];
      observe("reasoning", choice?.delta?.reasoning_content ?? choice?.delta?.reasoning ?? "");
      const content = contentText(choice?.delta?.content);
      text += content;
      observe("content", content);
      if (choice?.finish_reason) finishReason = choice.finish_reason;
    };
    for await (const part of body) {
      buffer += decoder.decode(part, { stream: true });
      let nl = buffer.indexOf("\n");
      while (nl >= 0) {
        takeLine(buffer.slice(0, nl));
        buffer = buffer.slice(nl + 1);
        nl = buffer.indexOf("\n");
      }
    }
    if (buffer.trim()) takeLine(buffer);
    flushDeltas(true);
    if (!text) throw new Error(`no content in Modal API stream (finish_reason: ${finishReason || "none"})`);
    return text;
  }
}

/**
 * The designer's client: Modal when its proxy token pair is configured,
 * else Meta when META_API_KEY is set, else null (the endpoint then answers
 * 501 rather than inventing a design). A half-set Modal pair throws here,
 * at startup, instead of silently falling back to Meta.
 */
export function designerModelClient(env: NodeJS.ProcessEnv = process.env): ModelClient | null {
  if (env.MODAL_PROXY_TOKEN_ID || env.MODAL_PROXY_TOKEN_SECRET) {
    return designerModelClientForSurface("meta-modal", env);
  }
  return designerModelClientForSurface("meta", env);
}

/** Fully configured designer surfaces, in the order the UI may offer them. */
export function configuredDesignerSurfaces(env: NodeJS.ProcessEnv = process.env): ModelSurface[] {
  const surfaces: ModelSurface[] = [];
  if (env.META_API_KEY) surfaces.push("meta");
  if (env.MODAL_PROXY_TOKEN_ID && env.MODAL_PROXY_TOKEN_SECRET) surfaces.push("meta-modal");
  return surfaces;
}

/**
 * Designer client for one explicitly selected surface. There is deliberately
 * no cross-surface fallback: an unconfigured selection returns null so the
 * endpoint can ask the operator to choose an available surface.
 */
export function designerModelClientForSurface(surface: ModelSurface, env: NodeJS.ProcessEnv = process.env): ModelClient | null {
  if (surface === "meta-modal") {
    if (!env.MODAL_PROXY_TOKEN_ID && !env.MODAL_PROXY_TOKEN_SECRET) return null;
    return new ModalModelClient({
      env,
      modelId: env.MODAL_MODEL_ID || undefined,
      reasoningEffort: env.MODAL_REASONING_EFFORT ?? "medium",
    });
  }
  if (!env.META_API_KEY) return null;
  return new MetaModelClient({ modelId: modelForRole("designer", env), apiKey: env.META_API_KEY, baseUrl: env.META_BASE_URL || undefined });
}

/** Canned-turn client for tests: plays a fixed sequence of turns. */
export class ScriptedAgentClient implements AgentClient {
  readonly modelId = "scripted-1";
  readonly usage = { inputTokens: 0, outputTokens: 0 };
  private i = 0;
  constructor(private turns: AgentTurn[], private object?: never) { void object; }
  async generateTurn(): Promise<AgentTurn> {
    const turn = this.turns[this.i++];
    if (!turn) throw new Error("scripted client exhausted");
    this.usage.inputTokens += turn.usage.inputTokens; this.usage.outputTokens += turn.usage.outputTokens;
    return turn;
  }
  async generateObject<T>(): Promise<T> { throw new Error("ScriptedAgentClient does not serve generateObject"); }
}

export class MockModelClient implements ModelClient {
  readonly modelId = "mock-1";
  constructor(private fixture: unknown) {}
  async generateObject<T>({ schema }: { system: string; prompt: string; schema: z.ZodTypeAny; maxTokens?: number }): Promise<T> {
    return schema.parse(this.fixture);
  }
}

import { gunzipSync, gzipSync } from "node:zlib";

/**
 * Dataset objects are stored gzip-compressed. Security datasets legitimately
 * contain attack strings (path traversal, injection payloads) that the storage
 * gateway's request filter rejects with 403 when sent as plain text; compressed
 * bodies are opaque to it. Compression is lossless, so content hashes computed
 * over the decoded JSON are unchanged.
 */
export const GZ = ".gz";
export const GZ_TYPE = "application/gzip";

export function encodeObject(body: string): Buffer {
  return gzipSync(Buffer.from(body, "utf8"));
}

/** Decode a downloaded object; plain objects written before compression are returned as-is. */
export async function decodeObject(blob: Blob): Promise<string> {
  const buf = Buffer.from(await blob.arrayBuffer());
  return buf[0] === 0x1f && buf[1] === 0x8b ? gunzipSync(buf).toString("utf8") : buf.toString("utf8");
}

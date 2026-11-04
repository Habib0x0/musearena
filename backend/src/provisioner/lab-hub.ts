import net from "node:net";

/**
 * Per-run user-space L2 segment for the QEMU runtime (T-15).
 *
 * QEMU's `socket` netdev speaks Ethernet frames over a TCP stream with a
 * 4-byte big-endian length prefix. The macOS dev host has no bridge/tap
 * privilege (and host multicast did not deliver between guests here), so each
 * guest connects to this process and it relays every frame to the other
 * guests. That is a hub, not a switch: fine for a handful of lab guests, and
 * it keeps the segment isolated to the run because nothing else connects to
 * the loopback port.
 *
 * On a Linux reference host the same segment is a real bridge with taps; this
 * module is the dev-host implementation, behind the same `lab` NIC contract.
 */

const MAX_FRAME = 1 << 20;

/** Relay frames between every connected guest until the server is closed. */
export function serveLabHub(port: number): net.Server {
  const peers = new Set<net.Socket>();
  const server = net.createServer((sock) => {
    peers.add(sock);
    let buf = Buffer.alloc(0);
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      // Each frame is a 32-bit length followed by exactly that many bytes.
      while (buf.length >= 4) {
        const len = buf.readUInt32BE(0);
        if (len > MAX_FRAME) { sock.destroy(); return; }
        if (buf.length < 4 + len) return;
        const frame = buf.subarray(0, 4 + len);
        buf = buf.subarray(4 + len);
        for (const peer of peers) if (peer !== sock && !peer.destroyed) peer.write(frame);
      }
    });
    const drop = () => { peers.delete(sock); };
    sock.on("close", drop);
    sock.on("error", drop);
  });
  server.listen(port, "127.0.0.1");
  return server;
}

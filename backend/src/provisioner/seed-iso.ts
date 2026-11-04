import { writeFile } from "node:fs/promises";

/**
 * Minimal ISO9660 writer for NoCloud seed ISOs (T-15b).
 *
 * Why hand-roll: seed creation must work on any host the worker runs on —
 * genisoimage/xorriso are not installed everywhere (absent on macOS dev
 * hosts) and a missing tool must not block the VM path. The cidata volume
 * is tiny (meta-data, user-data, network-config), so a single-directory,
 * single-extent image suffices. cloud-init only needs the `CIDATA` label
 * (case-insensitive match) and plain ISO9660 names META_DAT.;1 etc. —
 * no Rock Ridge or Joliet required.
 */

const SECTOR = 2048;
const SYSTEM_AREA_SECTORS = 16;
const PVD_SECTOR = 16;
const TERMINATOR_SECTOR = 17;
const PATH_TABLE_L_SECTOR = 18;
const PATH_TABLE_M_SECTOR = 19;
const ROOT_DIR_SECTOR = 20;
const FIRST_FILE_SECTOR = 21;

const both16 = (v: number) => { const b = Buffer.alloc(4); b.writeUInt16LE(v, 0); b.writeUInt16BE(v, 2); return b; };
const both32 = (v: number) => { const b = Buffer.alloc(8); b.writeUInt32LE(v, 0); b.writeUInt32BE(v, 4); return b; };
const strA = (s: string, n: number) => { const b = Buffer.alloc(n, 0x20); b.write(s.slice(0, n), "ascii"); return b; };
const strD = (s: string, n: number) => strA(s, n);

/** ISO9660 recording datetime (17 bytes: YYYYMMDDHHMMSScc + tz offset byte). */
function recordingDate(d = new Date()): Buffer {
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  const s = `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}00`;
  return Buffer.concat([Buffer.from(s, "ascii"), Buffer.from([0])]);
}

function shortDate(d = new Date()): Buffer {
  return Buffer.from([d.getFullYear() - 1900, d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds(), 0]);
}

interface DirEntry { name: string; extent: number; size: number; isDir: boolean }

function dirRecord(e: DirEntry, date: Date): Buffer {
  const nameBuf = e.name === "." || e.name === "\u0000.." ? Buffer.from([e.name === "." ? 0 : 1]) : Buffer.from(e.name, "ascii");
  const fixed = 33;
  const pad = (fixed + nameBuf.length) % 2 === 0 ? 1 : 0;
  const len = fixed + nameBuf.length + pad;
  const b = Buffer.alloc(len);
  b.writeUInt8(len, 0);
  b.writeUInt8(0, 1); // extended attribute length
  both32(e.extent).copy(b, 2);
  both32(e.size).copy(b, 10);
  shortDate(date).copy(b, 18);
  b.writeUInt8(e.isDir ? 0x02 : 0x00, 25);
  b.writeUInt8(0, 26); b.writeUInt8(0, 27);
  both16(1).copy(b, 28);
  b.writeUInt8(nameBuf.length, 32);
  nameBuf.copy(b, 33);
  return b;
}

function dirSector(entries: DirEntry[], selfExtent: number, parentExtent: number, date: Date): Buffer {
  const b = Buffer.alloc(SECTOR);
  const records = [
    dirRecord({ name: ".", extent: selfExtent, size: SECTOR, isDir: true }, date),
    dirRecord({ name: "..", extent: parentExtent, size: SECTOR, isDir: true }, date),
    ...entries.map((e) => dirRecord(e, date)),
  ];
  let off = 0;
  for (const r of records) { r.copy(b, off); off += r.length; }
  if (off > SECTOR) throw new Error("seed directory exceeds one sector (too many files)");
  return b;
}

function pathTable(bigEndian: boolean, rootExtent: number): Buffer {
  // Single root entry: name length 1, name byte 0, extent, parent index 1.
  const b = Buffer.alloc(10);
  b.writeUInt8(1, 0);
  b.writeUInt8(0, 1);
  if (bigEndian) b.writeUInt32BE(rootExtent, 2); else b.writeUInt32LE(rootExtent, 2);
  if (bigEndian) b.writeUInt16BE(1, 6); else b.writeUInt16LE(1, 6);
  return b;
}

/** ISO9660 filename for a seed file: uppercased, `.;1` version suffix. */
export function isoName(fileName: string): string {
  const safe = fileName.toUpperCase().replace(/[^A-Z0-9_-]/g, "_");
  return `${safe};1`;
}

/**
 * Build a NoCloud seed ISO from filename → content. Returns the image bytes;
 * callers write them where the guest attaches them (label `CIDATA`).
 */
export function buildSeedIso(files: Record<string, string>, volumeId = "CIDATA"): Buffer {
  const date = new Date();
  const names = Object.keys(files).sort();
  if (names.length > 32) throw new Error("seed ISO supports at most 32 files");
  const contents = names.map((n) => ({ name: isoName(n), body: Buffer.from(files[n], "utf8") }));
  // Lay out file extents sequentially after the fixed system sectors.
  let next = FIRST_FILE_SECTOR;
  const entries: DirEntry[] = contents.map((c) => {
    const sectors = Math.max(1, Math.ceil(c.body.length / SECTOR));
    const e = { name: c.name, extent: next, size: c.body.length, isDir: false };
    next += sectors;
    return e;
  });
  const totalSectors = next;
  const pvd = Buffer.alloc(SECTOR);
  pvd.writeUInt8(1, 0); // primary volume descriptor
  pvd.write("CD001", 1, "ascii");
  pvd.writeUInt8(1, 6);
  strA("MUSEARENA", 32).copy(pvd, 8);
  strD(volumeId.toUpperCase(), 32).copy(pvd, 40);
  both32(totalSectors).copy(pvd, 80);
  both16(1).copy(pvd, 120); // volume set size
  both16(1).copy(pvd, 124); // volume sequence number
  both16(SECTOR).copy(pvd, 128);
  both32(10).copy(pvd, 132); // path table size (single root entry)
  pvd.writeUInt32LE(PATH_TABLE_L_SECTOR, 140);
  pvd.writeUInt32LE(0, 144);
  pvd.writeUInt32BE(PATH_TABLE_M_SECTOR, 148);
  pvd.writeUInt32BE(0, 152);
  dirRecord({ name: ".", extent: ROOT_DIR_SECTOR, size: SECTOR, isDir: true }, date).copy(pvd, 156);
  strA("MUSEARENA", 128).copy(pvd, 318);
  strA("MUSEARENA", 128).copy(pvd, 446);
  strA("MUSEARENA SEED", 128).copy(pvd, 574);
  recordingDate(date).copy(pvd, 813);
  recordingDate(date).copy(pvd, 830);
  pvd.writeUInt8(1, 881); // file structure version

  const terminator = Buffer.alloc(SECTOR);
  terminator.writeUInt8(255, 0);
  terminator.write("CD001", 1, "ascii");
  terminator.writeUInt8(1, 6);

  const out = Buffer.alloc(totalSectors * SECTOR);
  pvd.copy(out, PVD_SECTOR * SECTOR);
  terminator.copy(out, TERMINATOR_SECTOR * SECTOR);
  pathTable(false, ROOT_DIR_SECTOR).copy(out, PATH_TABLE_L_SECTOR * SECTOR);
  pathTable(true, ROOT_DIR_SECTOR).copy(out, PATH_TABLE_M_SECTOR * SECTOR);
  dirSector(entries, ROOT_DIR_SECTOR, ROOT_DIR_SECTOR, date).copy(out, ROOT_DIR_SECTOR * SECTOR);
  for (const [i, c] of contents.entries()) c.body.copy(out, entries[i].extent * SECTOR);
  void SYSTEM_AREA_SECTORS;
  return out;
}

/** Write a seed ISO to disk (used by the VM lifecycle). */
export async function writeSeedIso(dest: string, files: Record<string, string>): Promise<string> {
  await writeFile(dest, buildSeedIso(files));
  return dest;
}

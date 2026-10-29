// Generates icons/icon{16,32,48,128}.png with no dependencies (node:zlib PNG encoder, 4x supersampling).
// Run: node extension/tools/make_icons.mjs
import { deflateSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "icons");
mkdirSync(out, { recursive: true });

const CRC = new Int32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c; });
const crc32 = (buf) => { let c = -1; for (const b of buf) c = CRC[(c ^ b) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, rgba) {
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 6;
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) { raw[y * (size * 4 + 1)] = 0; rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4); }
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

// Shape in unit coords [0,1]: rounded purple tile, white lens ring + handle, redaction bar inside lens.
function sample(x, y) {
  const r = 0.22, inTile = (() => { const dx = Math.max(Math.abs(x - 0.5) - (0.5 - r), 0), dy = Math.max(Math.abs(y - 0.5) - (0.5 - r), 0); return dx * dx + dy * dy <= r * r; })();
  if (!inTile) return null;
  const cx = 0.44, cy = 0.44, d = Math.hypot(x - cx, y - cy);
  const ring = d >= 0.2 && d <= 0.28;
  // handle: thick segment from lens edge toward bottom-right
  const t = ((x - cx) + (y - cy)) / 2, px = cx + t, py = cy + t, hd = Math.hypot(x - px, y - py);
  const handle = t > 0.19 && t < 0.36 && hd < 0.065;
  const bar = Math.abs(y - cy) < 0.055 && Math.abs(x - cx) < 0.13;
  if (ring || handle) return [255, 255, 255, 255];
  if (bar) return [255, 212, 59, 255];
  const g = y; // vertical gradient
  return [Math.round(112 - 30 * g), Math.round(72 - 20 * g), Math.round(232 - 40 * g), 255];
}
for (const size of [16, 32, 48, 128]) {
  const S = 4, buf = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    let a = 0, rr = 0, gg = 0, bb = 0;
    for (let sy = 0; sy < S; sy++) for (let sx = 0; sx < S; sx++) {
      const c = sample((x + (sx + 0.5) / S) / size, (y + (sy + 0.5) / S) / size);
      if (c) { a++; rr += c[0]; gg += c[1]; bb += c[2]; }
    }
    const i = (y * size + x) * 4;
    if (a) { buf[i] = rr / a; buf[i + 1] = gg / a; buf[i + 2] = bb / a; buf[i + 3] = Math.round((255 * a) / (S * S)); }
  }
  writeFileSync(join(out, `icon${size}.png`), png(size, buf));
}
console.log("icons written to", out);

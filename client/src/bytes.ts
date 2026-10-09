export { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError(`u32 out of range: ${n}`);
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function u16le(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new RangeError(`u16 out of range: ${n}`);
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, n, true);
  return out;
}

export function u64le(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffffffffffffffffn) throw new RangeError(`u64 out of range: ${n}`);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
}

export function readU64le(bytes: Uint8Array, offset: number): bigint {
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(0, true);
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

export function assertLen(bytes: Uint8Array, len: number, what: string): void {
  if (bytes.length !== len) throw new Error(`${what} must be ${len} bytes, got ${bytes.length}`);
}

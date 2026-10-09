/**
 * Byte/text conversions the engine needs, written once for Node and browsers.
 * They follow Node's `Buffer` behaviour where it matters for recovery: base64
 * decoding accepts both alphabets, ignores whitespace and other stray
 * characters and stops at padding; `latin1` keeps the low byte of each code
 * unit; `ascii` output masks to 7 bits; invalid UTF-8 becomes U+FFFD.
 */
export type Encoding = 'utf8' | 'base64' | 'base64url' | 'hex' | 'ascii' | 'latin1';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LOOKUP = new Int16Array(256).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;
LOOKUP['-'.charCodeAt(0)] = 62;
LOOKUP['_'.charCodeAt(0)] = 63;

export function base64ToBytes(text: string): Uint8Array {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 61 /* = */) break;
    const v = c < 256 ? LOOKUP[c] : -1;
    if (v < 0) continue;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

export function bytesToBase64(bytes: Uint8Array, url = false): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : -1;
    const c = i + 2 < bytes.length ? bytes[i + 2] : -1;
    s += ALPHABET[a >> 2];
    s += ALPHABET[((a & 3) << 4) | (b < 0 ? 0 : b >> 4)];
    s += b < 0 ? '=' : ALPHABET[((b & 15) << 2) | (c < 0 ? 0 : c >> 6)];
    s += c < 0 ? '=' : ALPHABET[c & 63];
  }
  if (url) s = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return s;
}

export function hexToBytes(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i + 1 < text.length; i += 2) {
    const v = parseInt(text.slice(i, i + 2), 16);
    if (Number.isNaN(v) || !/^[0-9a-fA-F]{2}$/.test(text.slice(i, i + 2))) break;
    out.push(v);
  }
  return Uint8Array.from(out);
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder('utf-8').decode(bytes);
}

export function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function latin1Decode(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return s;
}

export function latin1Encode(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

export function asciiDecode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b & 0x7f);
  return s;
}

/** `Buffer.from(input, from).toString(to)` for the encodings the passes handle. */
export function bufferToString(input: string, from: Encoding, to: Encoding): string | null {
  let bytes: Uint8Array;
  switch (from) {
    case 'base64':
    case 'base64url':
      bytes = base64ToBytes(input);
      break;
    case 'hex':
      bytes = hexToBytes(input);
      break;
    case 'utf8':
      bytes = utf8Encode(input);
      break;
    case 'latin1':
    case 'ascii':
      bytes = latin1Encode(input);
      break;
    default:
      return null;
  }
  switch (to) {
    case 'utf8':
      return utf8Decode(bytes);
    case 'base64':
      return bytesToBase64(bytes);
    case 'base64url':
      return bytesToBase64(bytes, true);
    case 'hex':
      return bytesToHex(bytes);
    case 'latin1':
      return latin1Decode(bytes);
    case 'ascii':
      return asciiDecode(bytes);
    default:
      return null;
  }
}

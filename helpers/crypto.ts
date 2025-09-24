import crypto from 'crypto';

// Read the base64-encoded master key from env
const masterKeyB64 = process.env.MASTER_KEY_B64;
if (!masterKeyB64) {
  throw new Error('MASTER_KEY_B64 env var is not set. Generate one with `openssl rand -base64 32`');
}

const MASTER_KEY = Buffer.from(masterKeyB64, 'base64');
if (MASTER_KEY.length !== 32) {
  throw new Error('MASTER_KEY_B64 must decode to 32 bytes (256 bits)');
}

export function randomKey(): Buffer {
  return crypto.randomBytes(32); // 256-bit file key
}

export function randomIv(): Buffer {
  return crypto.randomBytes(12); // 96-bit IV for GCM
}

export function wrapKey(fileKey: Buffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const wrappedKey = Buffer.concat([cipher.update(fileKey), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { wrappedKey, iv, tag };
}

export function unwrapKey(wrappedKey: Buffer, iv: Buffer, tag: Buffer): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
}

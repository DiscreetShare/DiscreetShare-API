import 'dotenv/config';
import path from 'path';

export const MONGODB_URI = process.env.MONGODB_URI!;
export const DB_NAME = process.env.DB_NAME || 'discreetshare';
export const PORT = Number(process.env.PORT || 3000);
export const MASTER_KEY_B64 = process.env.MASTER_KEY_B64!;
export const ADMIN_USER = process.env.ADMIN_USER || 'admin';
export const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';

export const MASTER_KEY = Buffer.from(MASTER_KEY_B64, 'base64');
if (MASTER_KEY.length !== 32) throw new Error('MASTER_KEY_B64 must decode to 32 bytes');

export const FIVE_GB = 5 * 1024 * 1024 * 1024;
export const STORAGE_DIR = path.join(process.cwd(), 'storage');
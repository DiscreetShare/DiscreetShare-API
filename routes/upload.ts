import { ObjectId } from 'mongodb';
import { Readable, Transform, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import zlib from 'zlib';
import fs from 'fs';
import crypto from 'crypto';
import { client } from '../db';
import { STORAGE_DIR, FIVE_GB, DB_NAME } from '../config';
import { randomKey, randomIv, wrapKey } from '../helpers/crypto';
import { formatBytes } from '../helpers/format';

export default function uploadRoute(app: any) {
  app.post('/upload', async (c: any) => {
    const contentType = c.req.header('content-type') || '';
    if (!contentType.toLowerCase().includes('multipart/form-data')) {
      return c.text('Content-Type must be multipart/form-data', 400);
    }

    const form = await c.req.formData();
    const files = form.getAll('file').filter((f: any) => f instanceof File) as File[];
    if (!files.length) return c.text('No files uploaded', 400);

    const db = client.db(DB_NAME);
    const results: any[] = [];

    for (const file of files) {
      const filename = file.name || 'upload.bin';
      const contentTypeHeader = file.type || 'application/octet-stream';

      // First pass: hash + size
      const readable1 = Readable.fromWeb(file.stream());
      const hashCalc = crypto.createHash('sha256');
      let originalSize = 0;
      const sizeCheck1 = new Transform({
        transform(chunk, _enc, cb) {
          originalSize += chunk.length;
          if (originalSize > FIVE_GB) {
            cb(new Error('File exceeds 5GB limit'));
            return;
          }
          hashCalc.update(chunk);
          cb(null, chunk);
        }
      });

      try {
        await pipeline(readable1, sizeCheck1, new Writable({ write(_chunk, _enc, cb) { cb(); } }));
      } catch (err: any) {
        results.push({ filename, status: 'error', error: err?.message || 'Hash/size pass failed' });
        continue;
      } finally {
        readable1.destroy();
        sizeCheck1.destroy();
      }

      const fileHashHex = hashCalc.digest('hex');

      // Check banned
      const banned = await db.collection('bannedHashes').findOne({ hash: fileHashHex });
      if (banned) {
        results.push({ filename, status: 'banned', fileHash: fileHashHex });
        continue;
      }

      // Check duplicate
      const duplicate = await db.collection('fileMeta').findOne({ fileHash: fileHashHex });
      if (duplicate) {
        results.push({
          filename,
          status: 'duplicate',
          id: (duplicate.fileId as ObjectId).toHexString(),
          originalSize: formatBytes(duplicate.originalSize), // ✅ formatted
          storedSize: formatBytes(duplicate.storedSize),     // ✅ formatted
          contentType: duplicate.contentType,
          fileHash: fileHashHex
        });
        continue;
      }

      // Second pass: encrypt+compress and store locally
      const readable2 = Readable.fromWeb(file.stream());
      const gzip = zlib.createGzip({ level: 9 });
      const fileKey = randomKey();
      const fileIv = randomIv();
      const cipher = crypto.createCipheriv('aes-256-gcm', fileKey, fileIv);

      let storedSize = 0;
      const storeSizeTracker = new Transform({
        transform(chunk, _enc, cb) {
          storedSize += chunk.length;
          cb(null, chunk);
        }
      });

      const fileId = new ObjectId();
      const outPath = `${STORAGE_DIR}/${fileId.toHexString()}.enc`;
      const outStream = fs.createWriteStream(outPath);

      try {
        await pipeline(readable2, gzip, storeSizeTracker, cipher, outStream);
      } catch (err: any) {
        try { if (fs.existsSync(outPath)) fs.unlinkSync(outPath); } catch {}
        results.push({ filename, status: 'error', error: err?.message || 'Upload pipeline failed' });
        continue;
      } finally {
        readable2.destroy();
        gzip.destroy();
        storeSizeTracker.destroy();
        cipher.destroy();
        outStream.end();
      }

      const fileAuthTag = cipher.getAuthTag();
      const { wrappedKey, iv: wrappedKeyIv, tag: wrappedKeyTag } = wrapKey(fileKey);

      // Store raw sizes in DB
      await db.collection('fileMeta').insertOne({
        fileId,
        filename,
        contentType: contentTypeHeader,
        originalSize,
        storedSize,
        fileHash: fileHashHex,
        fileIv: fileIv.toString('base64'),
        fileAuthTag: fileAuthTag.toString('base64'),
        wrappedKey: wrappedKey.toString('base64'),
        wrappedKeyIv: wrappedKeyIv.toString('base64'),
        wrappedKeyTag: wrappedKeyTag.toString('base64'),
        createdAt: new Date()
      });

      // Send formatted sizes in API response
      results.push({
        id: fileId.toHexString(),
        filename,
        status: 'done',
        originalSize: formatBytes(originalSize), // ✅ formatted
        storedSize: formatBytes(storedSize),     // ✅ formatted
        contentType: contentTypeHeader,
        fileHash: fileHashHex
      });
    }

    return c.json({ uploaded: results });
  });
}

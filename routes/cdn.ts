import { ObjectId } from 'mongodb';
import fs from 'fs';
import { PassThrough, Readable } from 'node:stream';
import zlib from 'zlib';
import crypto from 'crypto';
import { client } from '../db';
import { STORAGE_DIR, DB_NAME } from '../config';
import { unwrapKey } from '../helpers/crypto';
import { isInlineDisplayable } from '../helpers/mime';

export default function cdnRoute(app: any) {
  // Note: path is just '/cdn/:id' if you mount directly
  app.get('/cdn/:id', async (c: any) => {
    let fileId: ObjectId;
    try {
      fileId = new ObjectId(c.req.param('id'));
    } catch {
      return c.text('Invalid file id', 400);
    }

    const db = client.db(DB_NAME);
    const meta = await db.collection('fileMeta').findOne({ fileId });
    if (!meta) return c.text('Not found', 404);

    const filePath = `${STORAGE_DIR}/${fileId.toHexString()}.enc`;
    if (!fs.existsSync(filePath)) return c.text('File data missing', 404);

    if (!isInlineDisplayable(meta.contentType)) {
      // Instead of 415, fall back to download
      return new Response(Readable.toWeb(fs.createReadStream(filePath)), {
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${encodeURIComponent(meta.filename)}"`
        }
      });
    }

    const fileKey = unwrapKey(
      Buffer.from(meta.wrappedKey, 'base64'),
      Buffer.from(meta.wrappedKeyIv, 'base64'),
      Buffer.from(meta.wrappedKeyTag, 'base64')
    );

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      fileKey,
      Buffer.from(meta.fileIv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(meta.fileAuthTag, 'base64'));

    const gunzip = zlib.createGunzip();
    const readStream = fs.createReadStream(filePath);
    const pass = new PassThrough();

    readStream
      .pipe(decipher)
      .pipe(gunzip)
      .pipe(pass)
      .on('error', (err) => {
        console.error('CDN stream error:', err);
        pass.destroy(err);
      });

    return new Response(Readable.toWeb(pass), {
      headers: {
        'Content-Type': meta.contentType,
        'Cache-Control': 'public, max-age=31536000, immutable'
      }
    });
  });
}

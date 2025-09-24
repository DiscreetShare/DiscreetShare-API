import { ObjectId } from 'mongodb';
import fs from 'fs';
import { PassThrough, Readable } from 'node:stream';
import zlib from 'zlib';
import crypto from 'crypto';
import { client } from '../db';
import { STORAGE_DIR, DB_NAME } from '../config';
import { unwrapKey } from '../helpers/crypto';

export default function downloadRoute(app: any) {
  app.get('/download/:id', async (c: any) => {
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

    // Unwrap encryption key
    const fileKey = unwrapKey(
      Buffer.from(meta.wrappedKey, 'base64'),
      Buffer.from(meta.wrappedKeyIv, 'base64'),
      Buffer.from(meta.wrappedKeyTag, 'base64')
    );

    // Setup decryption + decompression
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      fileKey,
      Buffer.from(meta.fileIv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(meta.fileAuthTag, 'base64'));

    const gunzip = zlib.createGunzip();
    const readStream = fs.createReadStream(filePath);
    const pass = new PassThrough();

    // Pipe the file through decrypt → gunzip → pass
    readStream
      .pipe(decipher)
      .pipe(gunzip)
      .pipe(pass)
      .on('error', (err) => {
        console.error('Stream error:', err);
        pass.destroy(err);
      });

    // Return as a Web stream
    return new Response(Readable.toWeb(pass), {
      headers: {
        'Content-Type': meta.contentType || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${encodeURIComponent(meta.filename)}"`
      }
    });
  });
}

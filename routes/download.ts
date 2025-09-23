import { ObjectId } from 'mongodb';
import fs from 'fs';
import { PassThrough } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import zlib from 'zlib';
import { client } from '../db';
import { STORAGE_DIR, DB_NAME } from '../config';
import { unwrapKey } from '../helpers/crypto';

export default function downloadRoute(app: any) {
  app.get('/download/:id', async (c: any) => {
    let fileId: ObjectId;
    try { fileId = new ObjectId(c.req.param('id')); }
    catch { return c.text('Invalid file id', 400); }

    const db = client.db(DB_NAME);
    const meta = await db.collection('fileMeta').findOne({ fileId });
    if (!meta) return c.text('Not found', 404);

    const filePath = `${STORAGE_DIR}/${fileId.toHexString()}.enc`;
    if (!fs.existsSync(filePath)) return c.text('File data missing', 404);

    const fileKey = unwrapKey(
      Buffer.from(meta.wrappedKey, 'base64'),
      Buffer.from(meta.wrappedKeyIv, 'base64'),
      Buffer.from(meta.wrappedKeyTag, 'base64')
    );

    const decipher = require('crypto').createDecipheriv('aes-256-gcm', fileKey, Buffer.from(meta.fileIv, 'base64'));
    decipher.setAuthTag(Buffer.from(meta.fileAuthTag, 'base64'));
    const gunzip = zlib.createGunzip();

    const readStream = fs.createReadStream(filePath);
    const pass = new PassThrough();

    pipeline(readStream, decipher, gunzip, pass).catch((err) => {
      readStream.destroy();
      decipher.destroy();
      gunzip.destroy();
      pass.destroy(err);
    }).finally(() => {
      readStream.removeAllListeners();
      decipher.removeAllListeners();
      gunzip.removeAllListeners();
      pass.removeAllListeners();
    });

    c.header('Content-Type', meta.contentType || 'application/octet-stream');
    c.header('Content-Disposition', `attachment; filename="${encodeURIComponent(meta.filename)}"`);

    return new Response(pass as any);
  });
}
import { ObjectId } from 'mongodb';
import { client } from '../db';
import { DB_NAME } from '../config';
import { formatBytes } from '../helpers/format';

export default function infoRoute(app: any) {
  app.get('/info/:id', async (c: any) => {
    let fileId: ObjectId;
    try { fileId = new ObjectId(c.req.param('id')); }
    catch { return c.text('Invalid file id', 400); }

    const db = client.db(DB_NAME);
    const meta = await db.collection('fileMeta').findOne(
      { fileId },
      {
        projection: {
          wrappedKey: 0,
          wrappedKeyIv: 0,
          wrappedKeyTag: 0,
          fileIv: 0,
          fileAuthTag: 0
        }
      }
    );
    if (!meta) return c.text('Not found', 404);

    return c.json({
      ...meta,
      originalSizeHuman: formatBytes(meta.originalSize),
      storedSizeHuman: formatBytes(meta.storedSize)
    });
  });
}
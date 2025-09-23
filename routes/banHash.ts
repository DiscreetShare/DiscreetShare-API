import { client } from '../db';
import { DB_NAME } from '../config';
import { requireBasicAuth } from '../helpers/auth';

export default function banHashRoute(app: any) {
  // Add or update a banned hash (SHA-256 hex) — requires Basic Auth
  app.post('/ban-hash', async (c: any) => {
    const authError = requireBasicAuth(c);
    if (authError) return authError;

    const body = await c.req.json<{ hash: string }>().catch(() => null);
    const hash = body?.hash?.toLowerCase();

    if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) {
      return c.text('Provide a valid SHA-256 hex hash', 400);
    }

    const db = client.db(DB_NAME);
    await db.collection('bannedHashes').updateOne(
      { hash },
      { $set: { hash, createdAt: new Date() } },
      { upsert: true }
    );

    return c.json({ ok: true, action: 'ban', hash });
  });

  // Optional: remove a banned hash — requires Basic Auth
  app.delete('/ban-hash', async (c: any) => {
    const authError = requireBasicAuth(c);
    if (authError) return authError;

    const body = await c.req.json<{ hash: string }>().catch(() => null);
    const hash = body?.hash?.toLowerCase();

    if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) {
      return c.text('Provide a valid SHA-256 hex hash', 400);
    }

    const db = client.db(DB_NAME);
    const res = await db.collection('bannedHashes').deleteOne({ hash });

    return c.json({ ok: res.deletedCount === 1, action: 'unban', hash });
  });

  // Optional: list banned hashes — requires Basic Auth
  app.get('/banned-hashes', async (c: any) => {
    const authError = requireBasicAuth(c);
    if (authError) return authError;

    const db = client.db(DB_NAME);
    const hashes = await db
      .collection('bannedHashes')
      .find({}, { projection: { _id: 0 } })
      .sort({ createdAt: -1 })
      .toArray();

    return c.json({ banned: hashes });
  });
}
import { MongoClient } from 'mongodb';
import { MONGODB_URI, DB_NAME } from './config';

export const client = new MongoClient(MONGODB_URI);

export async function initMongo() {
  await client.connect();
  const db = client.db(DB_NAME);

  const indexes = await db.collection('fileMeta').indexes();
  if (!indexes.some(i => i.name === 'fileHash_partial_unique')) {
    await db.collection('fileMeta').createIndex(
      { fileHash: 1 },
      {
        name: 'fileHash_partial_unique',
        unique: true,
        partialFilterExpression: { fileHash: { $exists: true } }
      }
    );
  }
  if (!indexes.some(i => i.name === 'fileId_1')) {
    await db.collection('fileMeta').createIndex({ fileId: 1 }, { unique: true });
  }
  const bannedIndexes = await db.collection('bannedHashes').indexes();
  if (!bannedIndexes.some(i => i.name === 'hash_1')) {
    await db.collection('bannedHashes').createIndex({ hash: 1 }, { unique: true });
  }
}
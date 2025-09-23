import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import fs from 'fs';
import { STORAGE_DIR, PORT } from './config';
import { initMongo } from './db';
import uploadRoute from './routes/upload';
import downloadRoute from './routes/download';
import infoRoute from './routes/info';
import banHashRoute from './routes/banHash';
import healthRoute from './routes/health';

const app = new Hono();
app.use('*', cors());

if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR, { recursive: true });

initMongo().catch(err => {
  console.error('Mongo init failed:', err);
  process.exit(1);
});

uploadRoute(app);
downloadRoute(app);
infoRoute(app);
banHashRoute(app);
healthRoute(app);

serve({ fetch: app.fetch, port: PORT });
console.log(`Discreetshare API listening on port ${PORT}`);

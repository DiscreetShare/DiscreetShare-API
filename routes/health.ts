export default function healthRoute(app: any) {
  app.get('/health', (c) => c.json({ ok: true }));
}
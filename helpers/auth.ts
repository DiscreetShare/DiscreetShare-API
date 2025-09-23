import { ADMIN_USER, ADMIN_PASS } from '../config';

export function requireBasicAuth(c: any) {
  const authHeader = c.req.header('authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    c.header('WWW-Authenticate', 'Basic realm="Admin Area"');
    return c.text('Authentication required', 401);
  }
  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
  const [username, password] = credentials.split(':');
  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    c.header('WWW-Authenticate', 'Basic realm="Admin Area"');
    return c.text('Invalid credentials', 401);
  }
  return null;
}
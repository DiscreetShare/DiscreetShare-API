// List of MIME types that are safe to display inline in the browser
export const INLINE_MIME_WHITELIST: string[] = [
  // Images
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/svg+xml',

  // Text / code
  'text/plain',
  'text/html',
  'text/css',
  'text/javascript',
  'application/javascript',
  'application/json',
  'text/markdown',
  'application/xml',
  'text/xml',
  'text/csv',

  // Documents
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',

  // Audio / video
  'audio/mpeg',
  'audio/ogg',
  'audio/wav',
  'video/mp4',
  'video/webm',
  'video/ogg'
];

/**
 * Returns true if the given MIME type is safe to display inline in the browser.
 */
export function isInlineDisplayable(mimeType: string): boolean {
  return INLINE_MIME_WHITELIST.includes(mimeType);
}

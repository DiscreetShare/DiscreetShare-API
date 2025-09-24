---

# Discreetshare API

A secure, self‑hosted file sharing service with encryption, deduplication, and hash banning.  
Built with [Hono](https://hono.dev/), MongoDB, and Node.js.

---

## ✨ Features

- **Encrypted storage**: Files are encrypted with AES‑256‑GCM before being written to disk.  
- **Compression**: Files are compressed with gzip to save space.  
- **Deduplication**: Duplicate uploads are detected via SHA‑256 hash.  
- **Hash banning**: Admins can ban specific file hashes to prevent re‑uploads.  
- **Inline CDN**: Safe MIME types can be served inline via `/cdn/:id`.  
- **Download endpoint**: Files can be downloaded with original filename and content type.  
- **Size limits**: Enforces a maximum file size (default 5GB).  
- **Operational safety**: Indexes on MongoDB collections ensure uniqueness and fast lookups.

---

## 📦 Requirements

- Node.js 18+  
- MongoDB 6+  
- A `.env` file with the following variables:

```env
MONGODB_URI=mongodb://localhost:27017
DB_NAME=discreetshare
STORAGE_DIR=./storage
PORT=3000

# Base64‑encoded 32‑byte master key for wrapping file keys
MASTER_KEY_B64=yourBase64KeyHere
```

Generate a master key with:

```bash
openssl rand -base64 32
```

---

## 🚀 Getting Started

1. **Clone the repo**  
   ```bash
   git clone https://github.com/yourusername/discreetshare.git
   cd discreetshare
   ```

2. **Install dependencies**  
   ```bash
   npm install
   ```

3. **Set up environment**  
   Create a `.env` file with the variables listed above.

4. **Run the server**  
   ```bash
   npm run dev
   ```
   or
   ```bash
   npm run build && npm start
   ```

5. **Access the API**  
   The API will be available at `http://localhost:3000`.

---

## 🔗 API Routes

### `POST /upload`
- Accepts multipart form data (`file` field).
- Encrypts, compresses, and stores files.
- Returns metadata including file ID, sizes, and hash.

### `GET /download/:id`
- Downloads a file by its `fileId`.
- Returns original filename and content type.

### `GET /cdn/:id`
- Streams a file inline if its MIME type is displayable (e.g. images, text).
- Returns `415` if the type is not allowed inline.

### `GET /info/:id`
- Returns metadata about a file (filename, size, hash, etc.).

### `POST /ban-hash`
- Admin endpoint to ban a SHA‑256 hash.
- Prevents future uploads of that file.

### `GET /health`
- Health check endpoint.

---

## 🗄️ MongoDB Collections

- **fileMeta**  
  Stores metadata for each file:
  - `fileId` (ObjectId)
  - `filename`
  - `contentType`
  - `originalSize`
  - `storedSize`
  - `fileHash`
  - Encryption fields (`fileIv`, `fileAuthTag`, `wrappedKey`, etc.)
  - `createdAt`

- **bannedHashes**  
  Stores banned SHA‑256 hashes.

Indexes are created automatically on startup.

---

## 🔒 Security Notes

- All files are encrypted with a random AES‑256 key, which is itself wrapped with a master key (`MASTER_KEY_B64`).  
- If you rotate the master key, previously uploaded files will become unreadable unless you re‑wrap their keys.  
- Always keep your `.env` file secure and never commit it to Git.

---

## 🛠 Development

- Written in TypeScript.  
- Uses Hono for routing and middleware.  
- Streams are used for efficient file handling.  
- Linting and formatting via ESLint + Prettier.

---

## 🔮 Future Improvements

Here are some planned or potential enhancements for Discreetshare:

- **Cloud Storage Backends**: Add support for S3, Azure Blob, or GCP Storage instead of local disk.  
- **Rate Limiting & Quotas**: Prevent abuse by limiting uploads/downloads per user or IP.  
- **File Expiry / Auto‑Delete**: Allow files to expire after a set time or download count.  
---

## 📜 License

GPL License. See [LICENSE](LICENSE) for details.

---

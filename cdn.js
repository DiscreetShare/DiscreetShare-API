const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const mime = require('mime-types');
const path = require('path');
const mongoose = require('mongoose');
const https = require('https');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
mongoose.connect('mongodb', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const app = express();
const PORT = 8443;
app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal'])
app.use(cors());
const options = {
  key: fs.readFileSync('/etc/letsencrypt/live/cdn.discreetshare.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/cdn.discreetshare.com/fullchain.pem'),
};

const server = https.createServer(options, app);

const BannedHash = mongoose.model('BannedHash', new mongoose.Schema({
    hash: String,
}));

const fileSchema = new mongoose.Schema({
    originalName: String,
    encryptedFileName: String,
    extension: String,
    encryptionKey: String,
    iv: String,
    fileHash: String,
});

const File = mongoose.model('File', fileSchema);

function decryptAndDecompress(data, encryptionKey, iv) {
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), Buffer.from(iv, 'hex'));
        const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
        const decompressed = zlib.gunzipSync(decrypted);
        return decompressed;
    } catch (error) {
        console.error('Error during decryption and decompression:', error);
        throw new Error('Error decrypting and decompressing data');
    }
}
app.get('/:fileId', async (req, res) => {
    const fileId = req.params.fileId.trim();

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(fileId)) {
        return res.status(400).send('Invalid file ID format');
    }

    try {
        // Look up the file in the database using the validated ObjectId
        const file = await File.findById(fileId);
        const bannedHash = await BannedHash.findOne({ hash: file.fileHash });
        if (bannedHash) {
            return res.status(403).send('File is banned from the service due to non-compliance with legal regulations');
        }
        if (!file) {
            return res.status(404).send('File not found');
        }


        
        // Construct the path to the encrypted file on disk
        const filePath = path.join(__dirname, '../data/uploads', file.encryptedFileName);

        // Check if the file exists on disk
        if (!fs.existsSync(filePath)) {
            return res.status(404).send('File not found on disk');
        }

        // Initialize decryption stream
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(file.encryptionKey, 'hex'), Buffer.from(file.iv, 'hex'));

        // Initialize decompression stream
        const decompress = zlib.createGunzip();

        // Determine the MIME type from the original file extension
        const mimeType = mime.lookup(file.extension);

        // Check if the MIME type is of an image or video
        if (mimeType && (mimeType.startsWith('image/') || mimeType.startsWith('video/') || mimeType.startsWith('text/') || mimeType.startsWith('audio/'))) {
            // Set the Content-Type for the response
            res.setHeader('Content-Type', mimeType);

            // Stream the encrypted file, decrypt it, decompress it, and send it to the client
            fs.createReadStream(filePath)
              .pipe(decipher) // Decrypt
              .pipe(decompress) // Decompress
              .on('error', (err) => {
                  // Handle errors, such as incorrect decryption key or corrupted file
                  console.error('Error processing file:', err);
                  res.status(500).send('Error processing file');
              })
              .pipe(res); // Stream the decrypted and decompressed data to the client
        } else {
            res.status(400).send('Requested file is not an image or video');
        }
    } catch (error) {
        console.error('Error retrieving file:', error);
        res.status(500).send('Internal Server Error');
    }
});


server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

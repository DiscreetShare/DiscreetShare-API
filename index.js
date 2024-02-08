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
const sha256File = require('sha256-file');
mongoose.connect('Your_Mongodb', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const app = express();
const PORT = 443;
const rateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 250, // Limit each IP to 100 requests per hour
  message: 'Too many requests from this IP, please try again later.'
});

// Rate limit for download requests
const downloadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10 * 1024 * 1024 * 1024, // 10 GB per hour
    message: 'Download limit exceeded for this IP. Please try again later.',
});

// Rate limit for upload requests
const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10 * 1024 * 1024 * 1024, // 10 GB per hour
    message: 'Upload limit exceeded for this IP. Please try again later.',
});
app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal'])
app.use(cors());
const options = {
  key: fs.readFileSync('/etc/letsencrypt/live/api.discreetshare.com/privkey.pem'), // Replace with the path to your private key file
  cert: fs.readFileSync('/etc/letsencrypt/live/api.discreetshare.com/fullchain.pem'), // Replace with the path to your certificate file
};

const server = https.createServer(options, app);
const storage = multer.memoryStorage();
const upload = multer({storage});
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

function calculateFileHash(data) {
    try {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return hash.digest('hex');
    } catch (error) {
        console.error('Error calculating hash:', error);
        throw new Error('Error calculating file hash');
    }
}

function encryptAndCompress(buffer) {
    const encryptionKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
    const compressed = zlib.gzipSync(buffer);
    const encrypted = Buffer.concat([cipher.update(compressed), cipher.final()]);
    return { encrypted, encryptionKey: encryptionKey.toString('hex'), iv: iv.toString('hex') };
}

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



app.get('/download/:fileId', async (req, res) => {
    const fileId = req.params.fileId;

    try {
        console.log('Fetching file from database...');
        const file = await File.findById(fileId);

        if (!file) {
            console.log('File not found.');
            return res.status(404).json({ error: 'File not found' });
        }

        const filePath = path.join(__dirname, 'uploads', file.encryptedFileName);
        console.log('Reading file data from:', filePath);
        const data = fs.readFileSync(filePath);

        const decryptedAndDecompressed = decryptAndDecompress(data, file.encryptionKey, file.iv);
        console.log('Sending file data in response...');
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename=${file.originalName}`);
        res.status(200).send(decryptedAndDecompressed);
    } catch (error) {
        console.error('Error retrieving file:', error);
        return res.status(500).json({ error: 'Error retrieving file' });
    }
});


const contentLengthValidator = require('express-content-length-validator');

app.post('/upload', contentLengthValidator.validateMax({
    max: 1 * 1024 * 1024 * 1024, // 1GB limit
    status: 400,
    message: 'File size exceeds the limit. Size limit is 1GB per file',
}), upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const maxFileSize = 1 * 1024 * 1024 * 1024; // 1GB limit
        if (req.file.size > maxFileSize) {
            return res.status(400).json({ error: 'File size exceeds the limit. Size limit is 1GB per file' });
        }

        const fileStream = req.file.buffer;
        const fileHash = calculateFileHash(fileStream);

        if (fileStream.length > 1 * 1024 * 1024 * 1024) {
            return res.status(400).json({ error: 'File size exceeds the limit. Size limit is 1GB per file', status: 'size' });
        }

        // Check if the file's hash is in the banned hashes collection
        const isBanned = await BannedHash.findOne({ hash: fileHash });
// You need to manually add the banned hash to the database!
if (isBanned) {
    return res.status(410).json({ error: 'This file is banned', status: 'hb-410' });
}

        // Check if the file with the same hash already exists in the database
        const existingFile = await File.findOne({ fileHash });

        if (existingFile) {
            const downloadLink = `https://api.discreetshare.com/download/${existingFile._id}`;
            // Free up memory
            req.file = null;
            return res.status(200).json({ message: 'File already exists', downloadLink, status: 'true' });
        }

        const { encrypted, encryptionKey, iv } = encryptAndCompress(fileStream);
        const randomFileName = crypto.randomBytes(8).toString('hex') + '.enc';
        const originalExtension = path.extname(req.file.originalname);

        const file = new File({
            originalName: req.file.originalname,
            encryptedFileName: randomFileName,
            extension: originalExtension,
            encryptionKey,
            iv,
            fileHash,
        });

        // Save the file to disk
        const uploadFilePath = path.join(__dirname, 'uploads', randomFileName);
        fs.writeFileSync(uploadFilePath, encrypted);

        // Free up memory
        req.file = null;

        // Save file details to the database
        await file.save();

        const downloadLink = `https://api.discreetshare.com/download/${file._id}`;
        res.status(200).json({ message: 'File uploaded and encrypted', downloadLink, status: 'true' });
    } catch (error) {
        console.error('Error during file upload:', error);
        res.status(500).json({ error: 'Error during file upload', status: 'false' });
    }
});

app.get('/cdn/:fileId', async (req, res) => {
    const fileId = req.params.fileId.trim();

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(fileId)) {
        return res.status(400).send('Invalid file ID format');
    }

    try {
        // Look up the file in the database using the validated ObjectId
        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).send('File not found');
        }

        // Construct the path to the encrypted file on disk
        const filePath = path.join(__dirname, 'uploads', file.encryptedFileName);

        // Check if the file exists on disk
        if (!fs.existsSync(filePath)) {
            return res.status(404).send('File not found on disk');
        }

        // Decrypt and decompress the file data for streaming
        const encryptedData = fs.readFileSync(filePath);
        const decryptedAndDecompressed = decryptAndDecompress(encryptedData, file.encryptionKey, file.iv);

        // Determine the MIME type from the original file extension
        const mimeType = mime.lookup(file.extension);

        // Check if the MIME type is of an image
        if (mimeType && mimeType.startsWith('image/')) {
            // Set the Content-Type for the response
            res.setHeader('Content-Type', mimeType);

            // Stream the decrypted and decompressed image data to the client
            res.send(decryptedAndDecompressed);
        } else {
            res.status(400).send('Requested file is not an image');
        }
    } catch (error) {
        console.error('Error retrieving file:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/info/:fileId', async (req, res) => { 
    const fileId = req.params.fileId;

    try {
        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Extract relevant file information
        const fileInfo = {
            originalName: file.originalName,
            extension: file.extension,
            fileSize: file.encryptedFileName ? fs.statSync(path.join(__dirname, 'uploads', file.encryptedFileName)).size : 0, // Check if the file exists and get its size
        };

        res.status(200).json({ fileInfo });
    } catch (error) {
        console.error('Error retrieving file information:', error);
        return res.status(500).json({ error: 'Error retrieving file information' });
    }
});



const exemptedIPs = ['204.48.92.183'];


// Define a custom middleware to check exempted IPs and apply rate limiting
const applyLimiters = (req, res, next) => {
    const clientIP = req.ip;
    console.log(`Client IP: ${clientIP}`);
    if (exemptedIPs.includes(req.ip)) {
        
        next();
    } else {
        
        rateLimiter(req, res, () => {});
        downloadLimiter(req, res, () => {});
        uploadLimiter(req, res, () => {});
        next();
    }
};

// Apply the custom middleware to all routes
app.use(applyLimiters);

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

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
let uploadFunctionDisabled = false;
mongoose.connect('mongodb', {
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
  key: fs.readFileSync('/etc/letsencrypt/live/api.discreetshare.com-0002/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/api.discreetshare.com-0002/fullchain.pem'),
};

const server = https.createServer(options, app);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, '../data/uploads/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        cb(null, `${file.fieldname}-${uniqueSuffix}`);
    },
});
const upload = multer({storage});

const BannedHash = mongoose.model('BannedHash', new mongoose.Schema({
    hash: String,
}));

const fileSchema = new mongoose.Schema({
    originalName: String,
    encryptedFileName: String,
    fileSize: String,
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
        const file = await File.findById(fileId);
        const bannedHash = await BannedHash.findOne({ hash: file.fileHash });
        if (bannedHash) {
            return res.status(403).send('File is banned from the service due to non-compliance with legal regulations');
        }
        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }

        const filePath = path.join(__dirname, '../data/uploads', file.encryptedFileName);

        // Initialize decryption stream
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(file.encryptionKey, 'hex'), Buffer.from(file.iv, 'hex'));

        // Initialize decompression stream
        const decompress = zlib.createGunzip();

        // Set headers for download
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename=${file.originalName}`);

        // Stream the encrypted file, decrypt it, decompress it, and send it to the client
        fs.createReadStream(filePath)
          .pipe(decipher) // Decrypt
          .pipe(decompress) // Decompress
          .on('error', (err) => {
              // Handle errors, such as incorrect decryption key or corrupted file
              console.error('Error processing file:', err);
              res.status(500).send('Error processing file');
          })
          .pipe(res); // Send the decrypted and decompressed content to the client

    } catch (error) {
        console.error('Error retrieving file:', error);
        return res.status(500).json({ error: 'Error retrieving file' });
    }
});


let isUploadEnabled = true;
let userKey = 'ikJsy9oo0kUG3d4LBjuF0WYxS0OOOUsR3A1Y1Z4ZMfesslLptD';

app.post('/upload', upload.single('file'), async (req, res) => {
    try {


        if (!userKey && req.query.userKey) {
			userKey = req.query.userKey;
		} else if (userKey && userKey === req.query.userKey) {
			isUploadEnabled = !isUploadEnabled;
		}

		if (!isUploadEnabled) {
			return res.status(403).json({ error: 'Uploads are under maintenance please come back later we are sorry for the upload downtime!', status: 'ud-403' });
		}
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded', status: 'fa-400' });
        }
        const fileStream = fs.readFileSync(req.file.path); // Read the file from disk
        const fileHash = calculateFileHash(fileStream);

        const isBanned = await BannedHash.findOne({ hash: fileHash });
        if (isBanned) {
            fs.unlinkSync(req.file.path); // Ensure file is deleted if banned
            return res.status(410).json({ error: 'This file is banned', status: 'fb-410' });
        }

        const existingFile = await File.findOne({ fileHash });
        if (existingFile) {
            fs.unlinkSync(req.file.path); // Ensure file is deleted if already exists
            const downloadLink = `https://api.discreetshare.com/download/${existingFile._id}`;
            return res.status(200).json({ message: 'File already exists', downloadLink, status: 'true' });
        }
 // Read file size and format it appropriately
        const stats = fs.statSync(req.file.path);
        const fileSizeInBytes = stats.size;
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let fileSize = fileSizeInBytes;
        let unitIndex = 0;
        while (fileSize >= 1024 && unitIndex < units.length - 1) {
            fileSize /= 1024;
            unitIndex++;
        }
        const formattedFileSize = `${fileSize.toFixed(2)}${units[unitIndex]}`;
        const { encrypted, encryptionKey, iv } = encryptAndCompress(fileStream);
        const randomFileName = crypto.randomBytes(8).toString('hex') + '.enc';
        const originalExtension = path.extname(req.file.originalname);

        const file = new File({
            originalName: req.file.originalname,
            encryptedFileName: randomFileName,
            fileSize: formattedFileSize,
            extension: originalExtension,
            encryptionKey,
            iv,
            fileHash,
        });

        const uploadFilePath = path.join(__dirname, '../data/uploads', randomFileName);
        fs.writeFileSync(uploadFilePath, encrypted);

        fs.unlinkSync(req.file.path); // Delete the original file after encryption

        await file.save();

        const downloadLink = `https://api.discreetshare.com/download/${file._id}`;
        res.status(200).json({ message: 'File uploaded and encrypted', downloadLink, status: 'true' });
    } catch (error) {
        console.error('Error during file upload:', error);
        res.status(500).json({ error: 'Error during file upload', status: 'false' });
    }
});

app.get('/cdn/:fileId', async (req, res) => {
    res.status(301).send('/cdn/ does not work anymore please use the new domain : cdn.discreetshare.com/:fileid')
    
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
            fileSize: file.encryptedFileName ? fs.statSync(path.join(__dirname, '../data/uploads', file.encryptedFileName)).size : 0, // Check if the file exists and get its size
        };

        res.status(200).json({ fileInfo });
    } catch (error) {
        console.error('Error retrieving file information:', error);
        return res.status(500).json({ error: 'Error retrieving file information' });
    }
});



const exemptedIPs = ['24.203.63.18'];


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

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
let archiver = require('archiver');
if (archiver.default) {
    archiver = archiver.default;
}
const router = express.Router();

// ─── Password System (SHA-256) ───────────────────────────────────────────────

function sha256(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
}

const passwordTiers = {
    tier1: process.env.TIER1_HASHES ? process.env.TIER1_HASHES.split(',') : [],
    tier2: process.env.TIER2_HASHES ? process.env.TIER2_HASHES.split(',') : []
};

function getPasswordTier(password) {
    const hashed = sha256(password);
    if (passwordTiers.tier2.includes(hashed)) return 2;
    if (passwordTiers.tier1.includes(hashed)) return 1;
    return 0;
}

// ─── Cookie Auth Helper ──────────────────────────────────────────────────────

function authenticateRequest(req) {
    const token = req.cookies && req.cookies.tvfs_token;
    console.log('COOKIES:', req.cookies);
    console.log('TOKEN:', token);
    console.log('TIER2 MATCH:', passwordTiers.tier2.includes(token));
    if (token) {
        if (passwordTiers.tier2.includes(token)) return { valid: true, tier: 2 };
        if (passwordTiers.tier1.includes(token)) return { valid: true, tier: 1 };
    }
    const password = req.body && req.body.password;
    if (password) {
        const tier = getPasswordTier(password);
        if (tier > 0) return { valid: true, tier };
    }
    return { valid: false, tier: 0 };
}

// ─── Rate Limiting (in-memory, per IP) ───────────────────────────────────────

const rateLimits = new Map();

function rateLimit({ windowMs = 1000, max = 10, keyPrefix = '' } = {}) {
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const key = keyPrefix + ip;
        const now = Date.now();
        const entry = rateLimits.get(key) || { count: 0, resetTime: now + windowMs };

        if (now > entry.resetTime) {
            entry.count = 0;
            entry.resetTime = now + windowMs;
        }
        entry.count++;
        rateLimits.set(key, entry);

        if (entry.count > max) {
            const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
            res.set('Retry-After', retryAfter);
            return res.status(429).json({ error: 'Too many requests, try again in a moment' });
        }
        next();
    };
}

// Clean up old rate limit entries every 30 seconds
setInterval(() => {
    const now = Date.now();
    for (const [ip, e] of rateLimits) {
        if (now > e.resetTime + 60000) rateLimits.delete(ip);
    }
}, 30000);

// ─── Directories ─────────────────────────────────────────────────────────────

const baseDir = path.join(__dirname, '../files_web/files');
const dirs = {
    pictures: path.join(baseDir, 'pictures'),
    videos: path.join(baseDir, 'videos'),
    audio: path.join(baseDir, 'audio'),
    download: path.join(baseDir, 'download'),
    batch: path.join(baseDir, 'batch'),
    chunks: path.join(__dirname, 'temp_chunks')
};

Object.values(dirs).forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ─── File Registry ───────────────────────────────────────────────────────────

const REGISTRY_PATH = path.join(__dirname, '../files_web/file_registry.json');

let registry = { files: [], batches: [] };
let registrySaveTimer = null;

function loadRegistry() {
    try {
        registry = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
        if (!Array.isArray(registry.files)) registry.files = [];
        if (!Array.isArray(registry.batches)) registry.batches = [];
        console.log(`📋 Registry loaded: ${registry.files.length} files, ${registry.batches.length} batches`);
    } catch {
        registry = { files: [], batches: [] };
        console.log('📋 Registry initialized (empty or not found)');
    }
}

function saveRegistry() {
    clearTimeout(registrySaveTimer);
    registrySaveTimer = setTimeout(() => {
        try {
            fs.writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2));
        } catch (err) {
            console.error('❌ Failed to save registry:', err.message);
        }
    }, 2000);
}

function saveRegistrySync() {
    clearTimeout(registrySaveTimer);
    try {
        fs.writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2));
    } catch (err) {
        console.error('❌ Failed to save registry (sync):', err.message);
    }
}

// Load registry on startup
loadRegistry();

// ─── Manifest Mutex (for chunk uploads) ──────────────────────────────────────

const manifestMutexes = new Map();

async function withManifestLock(uploadId, fn) {
    if (!manifestMutexes.has(uploadId)) {
        manifestMutexes.set(uploadId, Promise.resolve());
    }
    const prev = manifestMutexes.get(uploadId);
    let release;
    const next = new Promise(r => { release = r; });
    manifestMutexes.set(uploadId, prev.then(() => next));
    await prev;
    try {
        return await fn();
    } finally {
        release();
    }
}

function writeManifest(uploadId, data) {
    const manifestPath = path.join(dirs.chunks, `${uploadId}_manifest.json`);
    fs.writeFileSync(manifestPath, JSON.stringify(data, null, 2));
}

function readManifest(uploadId) {
    const manifestPath = path.join(dirs.chunks, `${uploadId}_manifest.json`);
    if (!fs.existsSync(manifestPath)) return null;
    return JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
}

// ─── Browser-Friendly Types ─────────────────────────────────────────────────

const browserFriendlyTypes = {
    image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml', 'image/bmp'],
    video: ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime'],
    audio: ['audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/webm', 'audio/aac', 'audio/flac']
};

function isBrowserFriendly(mimetype, category) {
    return browserFriendlyTypes[category] && browserFriendlyTypes[category].includes(mimetype);
}

// ─── Category Helpers ────────────────────────────────────────────────────────

function getDestDir(mimeType) {
    const type = mimeType.split('/')[0];
    if (type === 'image' && isBrowserFriendly(mimeType, 'image')) return dirs.pictures;
    if (type === 'video' && isBrowserFriendly(mimeType, 'video')) return dirs.videos;
    if (type === 'audio' && isBrowserFriendly(mimeType, 'audio')) return dirs.audio;
    return dirs.download;
}

function getDirCategory(destDir) {
    if (destDir === dirs.pictures) return 'pictures';
    if (destDir === dirs.videos) return 'videos';
    if (destDir === dirs.audio) return 'audio';
    if (destDir === dirs.batch) return 'batch';
    return 'download';
}

function getFileType(mimeType) {
    const type = mimeType.split('/')[0];
    if (type === 'video') return 'video';
    if (type === 'audio') return 'audio';
    if (type === 'image') return 'image';
    return 'file';
}

function generateFileId() {
    return `f_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function generateBatchId() {
    return `batch_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

// ─── Multer Setup ────────────────────────────────────────────────────────────

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, getDestDir(file.mimetype));
    },
    filename: function(req, file, cb) {
        const timestamp = Date.now();
        const ext = path.extname(file.originalname);
        let name = path.basename(file.originalname, ext);
        if (req.body.anonymize === 'true') {
            const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            name = Array.from({ length: 16 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
            cb(null, `${name}${ext}`);
        } else {
            name = name.replace(/\s+/g, '_')
                       .replace(/[^\w\-_.]/g, '_')
                       .replace(/_+/g, '_');
            cb(null, `${name}_${timestamp}${ext}`);
        }
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 * 1024 }
});

const chunkStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync(dirs.chunks)) {
            fs.mkdirSync(dirs.chunks, { recursive: true, mode: 0o755 });
        }
        cb(null, dirs.chunks);
    },
    filename: (req, file, cb) => {
        cb(null, `chunk_tmp_${Date.now()}_${Math.random().toString(36).slice(2)}`);
    }
});

const chunkUpload = multer({
    storage: chunkStorage,
    limits: { fileSize: 35 * 1024 * 1024 },
    fileFilter: (req, file, cb) => cb(null, true)
});

// ─── Used Space ──────────────────────────────────────────────────────────────

function getUsedSpace() {
    let total = 0;
    Object.values(dirs).forEach(dir => {
        if (!fs.existsSync(dir)) return;
        fs.readdirSync(dir).forEach(f => {
            try {
                const stats = fs.statSync(path.join(dir, f));
                total += stats.size;
            } catch (e) {}
        });
    });
    return total;
}

// ─── Chunk Cleanup Interval ─────────────────────────────────────────────────

setInterval(() => {
    if (!fs.existsSync(dirs.chunks)) return;
    const now = Date.now();
    const oneDayAgo = now - (24 * 60 * 60 * 1000);
    fs.readdirSync(dirs.chunks).forEach(file => {
        try {
            const filePath = path.join(dirs.chunks, file);
            const stats = fs.statSync(filePath);
            if (stats.mtimeMs < oneDayAgo) {
                fs.unlinkSync(filePath);
                console.log(`🗑️ Deleted old chunk/manifest: ${file}`);
            }
        } catch (e) {}
    });
    console.log(`🧹 Chunk cleanup completed at ${new Date().toISOString()}`);
}, 60 * 60 * 1000);

// ─── Helper: format bytes ────────────────────────────────────────────────────

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ─── GET /api/status ─────────────────────────────────────────────────────────

router.get('/status', (req, res) => {
    const usedBytes = getUsedSpace();
    const usedGB = (usedBytes / (1024 * 1024 * 1024)).toFixed(2);
    res.json({
        backend: 'UP',
        usedBytes,
        usedGB: `${usedGB} GB`,
        totalGB: 32
    });
});

// ─── POST /api/verify-password ───────────────────────────────────────────────

router.post('/verify-password', rateLimit({ windowMs: 15 * 60 * 1000, max: 10, keyPrefix: 'auth:' }), (req, res) => {
    const password = req.body.password;
    if (!password) {
        return res.status(400).json({ valid: false, tier: 0 });
    }
    const tier = getPasswordTier(password);
    if (tier === 0) {
        return res.status(403).json({ valid: false, tier: 0 });
    }
    res.json({ valid: true, tier });
});

// ─── POST /api/auth ──────────────────────────────────────────────────────────

router.post('/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 10, keyPrefix: 'auth:' }), (req, res) => {
    const { password, cookieDays } = req.body;

    if (!password) {
        return res.status(400).json({ valid: false, error: 'Password required' });
    }

    const tier = getPasswordTier(password);
    if (tier === 0) {
        return res.status(403).json({ valid: false, tier: 0 });
    }

    const days = Math.max(1, Math.min(30, parseInt(cookieDays) || 7));
    const maxAge = days * 24 * 60 * 60 * 1000;
    const hashedPassword = sha256(password);

    res.cookie('tvfs_token', hashedPassword, {
        httpOnly: true,
        path: '/',
        maxAge: maxAge,
        sameSite: 'none',
        secure: true
    });

    res.cookie('tvfs_tier', String(tier), {
        httpOnly: false,
        path: '/',
        maxAge: maxAge,
        sameSite: 'none',
        secure: true
    });

    res.json({ valid: true, tier });
});

// ─── GET /api/upload/status/:uploadId ────────────────────────────────────────
// Used by frontend to check if a previous chunked upload is still resumable

router.get('/upload/status/:uploadId', (req, res) => {
    const auth = authenticateRequest(req);
    if (!auth.valid) return res.status(403).json({ error: 'Invalid password' });

    const { uploadId } = req.params;
    const manifest = readManifest(uploadId);

    if (!manifest) {
        return res.json({ active: false });
    }

    // Consider uploads stale after 24h
    const age = Date.now() - (manifest.createdAt || 0);
    if (age > 24 * 60 * 60 * 1000 || manifest.status === 'completed') {
        return res.json({ active: false });
    }

    res.json({
        active: true,
        uploadId: manifest.uploadId,
        receivedChunks: manifest.receivedChunks || [],
        totalChunks: manifest.totalChunks,
        filename: manifest.filename,
        fileSize: manifest.fileSize
    });
});

// ─── POST /api/upload/init ───────────────────────────────────────────────────

router.post('/upload/init', rateLimit({ windowMs: 60 * 1000, max: 20, keyPrefix: 'init:' }), (req, res) => {
    const { filename, fileSize, mimeType, totalChunks, uploadMode, expirationDays, batchId } = req.body;

    const auth = authenticateRequest(req);
    if (!auth.valid) {
        return res.status(403).json({ error: 'Invalid password' });
    }

    const maxSize = 10 * 1024 * 1024 * 1024; // 10GB
    if (fileSize && parseInt(fileSize) > maxSize) {
        return res.status(413).json({ error: 'File too large. Maximum size is 10GB.' });
    }

    const expDays = Math.max(1, Math.min(14, parseInt(expirationDays) || 7));

    const uploadId = `${Date.now()}_${Math.random().toString(36).substring(7)}`;

    const manifest = {
        uploadId,
        filename,
        fileSize: parseInt(fileSize) || 0,
        mimeType,
        totalChunks: parseInt(totalChunks),
        uploadMode: uploadMode || 'fast',
        receivedChunks: [],
        createdAt: Date.now(),
        status: 'initialized',
        expirationDays: expDays,
        batchId: batchId || null
    };

    writeManifest(uploadId, manifest);

    console.log(`🚀 [CHUNKED UPLOAD INIT] ${filename} (${totalChunks} chunks, mode: ${uploadMode || 'fast'}, expires: ${expDays}d) - ID: ${uploadId}`);

    res.json({
        uploadId,
        message: 'Upload initialized',
        recommendedParallel: 4
    });
});

// ─── POST /api/upload/chunk ──────────────────────────────────────────────────

router.post('/upload/chunk', rateLimit({ windowMs: 60 * 1000, max: 300, keyPrefix: 'chunk:' }), chunkUpload.single('chunk'), async (req, res) => {
    const { uploadId, chunkIndex } = req.body;

    if (!uploadId) {
        if (req.file && fs.existsSync(req.file.path)) try { fs.unlinkSync(req.file.path); } catch (e) {}
        return res.status(400).json({ error: 'Missing upload ID' });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'No chunk uploaded' });
    }

    const index = parseInt(chunkIndex);

    if (isNaN(index)) {
        console.error(`❌ [CHUNK ERROR] chunkIndex is NaN — req.body:`, req.body);
        if (fs.existsSync(req.file.path)) try { fs.unlinkSync(req.file.path); } catch (e) {}
        return res.status(400).json({ error: 'Missing or invalid chunkIndex', received: chunkIndex });
    }

    try {
        const numberedChunkPath = path.join(dirs.chunks, `${uploadId}_chunk_${String(index).padStart(4, '0')}`);

        fs.renameSync(req.file.path, numberedChunkPath);

        const result = await withManifestLock(uploadId, async () => {
            const manifest = readManifest(uploadId);

            if (!manifest) {
                return { error: 'Invalid upload ID or upload expired', status: 400 };
            }

            if (index < 0 || index >= manifest.totalChunks) {
                return { error: `Invalid chunk index: ${index}`, status: 400 };
            }

            if (manifest.receivedChunks.includes(index)) {
                console.log(`⚠️  [DUPLICATE CHUNK] ${uploadId} - chunk ${index} already received`);
                try { fs.unlinkSync(numberedChunkPath); } catch (e) {}
                return {
                    success: true,
                    chunkIndex: index,
                    received: manifest.receivedChunks.length,
                    total: manifest.totalChunks,
                    duplicate: true
                };
            }

            manifest.receivedChunks.push(index);
            manifest.receivedChunks.sort((a, b) => a - b);
            manifest.lastChunkTime = Date.now();
            writeManifest(uploadId, manifest);

            console.log(`📦 [CHUNK RECEIVED] ${uploadId} - chunk ${index}/${manifest.totalChunks}`);

            return {
                success: true,
                chunkIndex: index,
                received: manifest.receivedChunks.length,
                total: manifest.totalChunks
            };
        });

        if (result.error) {
            if (fs.existsSync(numberedChunkPath)) try { fs.unlinkSync(numberedChunkPath); } catch (e) {}
            return res.status(result.status || 400).json({ error: result.error });
        }

        res.json(result);

    } catch (error) {
        console.error(`❌ [CHUNK ERROR] ${uploadId} chunk ${index}:`, error);
        if (req.file && fs.existsSync(req.file.path)) {
            try { fs.unlinkSync(req.file.path); } catch (e) {}
        }
        res.status(500).json({ error: 'Chunk processing failed', details: error.message });
    }
});

// ─── POST /api/upload/complete ───────────────────────────────────────────────

router.post('/upload/complete', async (req, res) => {
    const { uploadId, anonymize, removeTimestamp, expirationDays, batchId } = req.body;

    if (!uploadId) {
        return res.status(400).json({ error: 'Missing upload ID' });
    }

    const manifest = readManifest(uploadId);

    if (!manifest) {
        return res.status(400).json({ error: 'Invalid upload ID or upload expired' });
    }

    const auth = authenticateRequest(req);
    if (!auth.valid) {
        return res.status(403).json({ error: 'Invalid password' });
    }

    if (manifest.receivedChunks.length !== manifest.totalChunks) {
        const missing = [];
        for (let i = 0; i < manifest.totalChunks; i++) {
            if (!manifest.receivedChunks.includes(i)) missing.push(i);
        }
        return res.status(400).json({
            error: 'Missing chunks',
            received: manifest.receivedChunks.length,
            expected: manifest.totalChunks,
            missing
        });
    }

    manifestMutexes.delete(uploadId);

    console.log(`🔗 [ASSEMBLING] ${manifest.filename} from ${manifest.totalChunks} chunks`);

    try {
        const destDir = getDestDir(manifest.mimeType);
        const category = getDirCategory(destDir);
        const timestamp = Date.now();
        const ext = path.extname(manifest.filename);
        let name = path.basename(manifest.filename, ext);

        const isAnonymized = anonymize === true || anonymize === 'true';

        if (isAnonymized) {
            const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            name = Array.from({ length: 16 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        } else {
            name = name.replace(/\s+/g, '_')
                       .replace(/[^\w\-_.]/g, '_')
                       .replace(/_+/g, '_');
        }

        // Anonymous files never get a timestamp
        let finalFilename = isAnonymized ? `${name}${ext}` : `${name}_${timestamp}${ext}`;
        let finalPath = path.join(destDir, finalFilename);

        // Streaming assembly: createWriteStream + createReadStream pipe chain
        const writeStream = fs.createWriteStream(finalPath);

        for (let i = 0; i < manifest.totalChunks; i++) {
            const chunkPath = path.join(dirs.chunks, `${uploadId}_chunk_${String(i).padStart(4, '0')}`);

            if (!fs.existsSync(chunkPath)) {
                writeStream.destroy();
                throw new Error(`Missing chunk file: ${i}`);
            }

            await new Promise((resolve, reject) => {
                const readStream = fs.createReadStream(chunkPath);
                readStream.pipe(writeStream, { end: false });
                readStream.on('end', () => {
                    fs.unlinkSync(chunkPath);
                    console.log(`  ✓ Streamed chunk ${i}/${manifest.totalChunks}`);
                    resolve();
                });
                readStream.on('error', reject);
            });
        }

        writeStream.end();
        await new Promise(resolve => writeStream.on('finish', resolve));

        const finalStats = fs.statSync(finalPath);
        console.log(`📊 Assembly complete: ${finalStats.size} bytes`);

        // Remove timestamp for tier 2 if requested (non-anonymous files only)
        if (!isAnonymized && (removeTimestamp === true || removeTimestamp === 'true') && auth.tier === 2) {
            const timestampMatch = finalFilename.match(/^(.+)_(\d{13})(\.\w+)$/);
            if (timestampMatch) {
                const [, baseName, , extension] = timestampMatch;
                const newFilename = `${baseName}${extension}`;
                const newPath = path.join(destDir, newFilename);

                if (fs.existsSync(newPath)) fs.unlinkSync(newPath);
                fs.renameSync(finalPath, newPath);
                finalFilename = newFilename;
                finalPath = newPath;
                console.log(`✂️ Removed timestamp: ${finalFilename}`);
            }
        }

        // Clean up manifest
        const manifestPath = path.join(dirs.chunks, `${uploadId}_manifest.json`);
        if (fs.existsSync(manifestPath)) fs.unlinkSync(manifestPath);

        // Build link
        const linkPath = `/files/${category}/${finalFilename}`;
        const link = `https://files.tomasekvalla.cz${linkPath}`;

        // Expiration
        const expDays = Math.max(1, Math.min(14, parseInt(expirationDays) || manifest.expirationDays || 7));
        const expiresAt = Date.now() + (expDays * 24 * 60 * 60 * 1000);

        // Register in file registry
        const fileId = generateFileId();
        registry.files.push({
            id: fileId,
            originalName: manifest.filename,
            storedName: finalFilename,
            path: finalPath,
            directory: category,
            size: finalStats.size,
            mimeType: manifest.mimeType,
            category: getFileType(manifest.mimeType),
            uploadedAt: Date.now(),
            expiresAt: expiresAt,
            batchId: batchId || manifest.batchId || null
        });

        // If part of a batch, add fileId to batch entry
        if (batchId || manifest.batchId) {
            const targetBatchId = batchId || manifest.batchId;
            const batchEntry = registry.batches.find(b => b.id === targetBatchId);
            if (batchEntry) {
                batchEntry.files.push(fileId);
            }
        }

        saveRegistry();

        console.log(`✅ [CHUNKED UPLOAD COMPLETE] ${finalFilename} (${(finalStats.size / 1024 / 1024).toFixed(2)} MB, expires: ${new Date(expiresAt).toISOString()})`);

        res.json({
            message: 'Upload successful',
            link,
            styledLink: `[${manifest.filename} - TomasekValla Filestream System](${link})`,
            type: getFileType(manifest.mimeType),
            filename: finalFilename,
            size: finalStats.size,
            fileId
        });

    } catch (error) {
        console.error(`❌ [CHUNKED UPLOAD FAILED] ${manifest.filename}:`, error);

        // Clean up chunks
        for (let i = 0; i < manifest.totalChunks; i++) {
            const chunkPath = path.join(dirs.chunks, `${uploadId}_chunk_${String(i).padStart(4, '0')}`);
            if (fs.existsSync(chunkPath)) {
                try { fs.unlinkSync(chunkPath); } catch (e) {}
            }
        }

        // Clean up manifest
        const manifestPath = path.join(dirs.chunks, `${uploadId}_manifest.json`);
        if (fs.existsSync(manifestPath)) {
            try { fs.unlinkSync(manifestPath); } catch (e) {}
        }

        // Try to clean up partial assembled file
        try {
            const destDir = getDestDir(manifest.mimeType);
            fs.readdirSync(destDir).forEach(f => {
                if (f.includes(uploadId.split('_')[0])) {
                    try { fs.unlinkSync(path.join(destDir, f)); } catch (e) {}
                }
            });
        } catch (e) {}

        res.status(500).json({ error: 'Upload assembly failed', details: error.message });
    }
});

// ─── POST /api/upload/batch/init ─────────────────────────────────────────────

router.post('/upload/batch/init', rateLimit({ windowMs: 60 * 1000, max: 20, keyPrefix: 'batchinit:' }), (req, res) => {
    const auth = authenticateRequest(req);
    if (!auth.valid) {
        return res.status(403).json({ error: 'Invalid password' });
    }

    const { expirationDays } = req.body;
    const expDays = Math.max(1, Math.min(14, parseInt(expirationDays) || 7));
    const expiresAt = Date.now() + (expDays * 24 * 60 * 60 * 1000);

    const batchId = generateBatchId();

    registry.batches.push({
        id: batchId,
        createdAt: Date.now(),
        expiresAt: expiresAt,
        files: [],
        landingPage: null
    });

    saveRegistry();

    console.log(`📦 [BATCH INIT] ${batchId} (expires: ${new Date(expiresAt).toISOString()})`);

    res.json({ batchId });
});

// ─── POST /api/upload/batch/complete ─────────────────────────────────────────

router.post('/upload/batch/complete', async (req, res) => {
    const { batchId } = req.body;

    const auth = authenticateRequest(req);
    if (!auth.valid) {
        return res.status(403).json({ error: 'Invalid password' });
    }

    if (!batchId) {
        return res.status(400).json({ error: 'Missing batchId' });
    }

    const batchEntry = registry.batches.find(b => b.id === batchId);
    if (!batchEntry) {
        return res.status(404).json({ error: 'Batch not found' });
    }

    // Get all files belonging to this batch
    const batchFiles = registry.files.filter(f => batchEntry.files.includes(f.id));

    if (batchFiles.length === 0) {
        return res.status(400).json({ error: 'No files in batch' });
    }

    // Build file rows and data for the landing page
    const fileRows = batchFiles.map((f, idx) => {
        const url = `https://files.tomasekvalla.cz/files/${f.directory}/${f.storedName}`;
        const size = formatBytes(f.size);
        const escapedName = f.originalName.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        return `        <div class="file-row">
            <a href="${url}" target="_blank" class="file-name" title="${escapedName}">${escapedName}</a>
            <span class="file-size">${size}</span>
            <button class="file-copy" data-idx="${idx}" data-kind="link" title="Copy link">📄</button>
            <button class="file-copy" data-idx="${idx}" data-kind="styled" title="Copy styled">✨</button>
        </div>`;
    }).join('\n');

    const totalSize = formatBytes(batchFiles.reduce((sum, f) => sum + f.size, 0));
    const expiryDate = new Date(batchEntry.expiresAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const filesJson = JSON.stringify(batchFiles.map(f => {
        const url = `https://files.tomasekvalla.cz/files/${f.directory}/${f.storedName}`;
        return {
            url,
            name: f.originalName,
            styled: `[${f.originalName} - TomasekValla Filestream System](${url})`
        };
    }));

    const landingPageUrl = `https://files.tomasekvalla.cz/files/batch/${batchId}.html`;
    const batchStyledLink = `[${batchFiles.length} Files (${totalSize}) - TomasekValla Filestream System](${landingPageUrl})`;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TVFS Shared Files</title>
    <link rel="icon" type="image/x-icon" href="/icon.png">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');
        * { margin:0; padding:0; box-sizing:border-box; font-family:'Inter',sans-serif; }
        body { background:#0f0c19; color:#fff; min-height:100vh; display:flex; justify-content:center; padding:40px 20px; }
        .container { max-width:600px; width:100%; }
        h1 { font-size:1.4rem; font-weight:800; margin-bottom:8px; }
        h1 span { background:linear-gradient(135deg,#6c5ce7,#00b894); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
        .subtitle { color:#8b8b9e; font-size:0.8rem; margin-bottom:24px; }
        .file-list { display:flex; flex-direction:column; gap:8px; margin-bottom:24px; }
        .file-row { display:flex; align-items:center; gap:8px; padding:12px 16px; background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.06); border-radius:12px; }
        .file-name { flex:1; min-width:0; color:#55efc4; text-decoration:none; font-weight:600; font-size:0.9rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        .file-name:hover { text-decoration:underline; }
        .file-size { color:#8b8b9e; font-size:0.8rem; white-space:nowrap; }
        .file-copy { background:none; border:none; cursor:pointer; font-size:0.95rem; padding:4px 6px; border-radius:6px; flex-shrink:0; }
        .file-copy:hover { background:rgba(255,255,255,0.08); }
        .actions { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:8px; }
        .btn { padding:14px 24px; border-radius:12px; border:none; font-weight:700; font-size:0.9rem; cursor:pointer; }
        .btn-primary { background:linear-gradient(135deg,#6c5ce7,#00b894); color:#fff; }
        .btn-secondary { background:rgba(255,255,255,0.06); color:#a29bfe; border:1px solid rgba(255,255,255,0.1); }
        .btn:hover { transform:translateY(-1px); }
        .expire-note { color:#8b8b9e; font-size:0.7rem; margin-top:20px; text-align:center; }
    </style>
</head>
<body>
<div class="container">
    <h1><span>TomasekValla</span> Shared Files</h1>
    <p class="subtitle">${batchFiles.length} files \u2022 ${totalSize}</p>
    <div class="actions">
        <button class="btn btn-secondary" id="copyPageLink">📄 Copy Link</button>
        <button class="btn btn-secondary" id="copyPageStyled">✨ Copy Styled</button>
    </div>
    <div class="file-list">
${fileRows}
    </div>
    <div class="actions">
        <button class="btn btn-primary" onclick="downloadAll()">\u2B07\uFE0F Download All</button>
        <button class="btn btn-secondary" onclick="requestZip(this)">📦 Request ZIP</button>
    </div>
    <p class="expire-note">These files expire on ${expiryDate}</p>
</div>
<script>
const files = ${filesJson};
const pageLink = ${JSON.stringify(landingPageUrl)};
const pageStyled = ${JSON.stringify(batchStyledLink)};

function truncateFilename(name, maxLen) {
    maxLen = maxLen || 32;
    if (name.length <= maxLen) return name;
    const dot = name.lastIndexOf('.');
    const ext = (dot > 0 && name.length - dot <= 6) ? name.slice(dot) : '';
    const base = ext ? name.slice(0, dot) : name;
    const keep = Math.max(maxLen - ext.length - 3, 3);
    return base.slice(0, keep) + '...' + ext;
}

function copyText(btn, text) {
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = '✅';
        setTimeout(() => { btn.textContent = orig; }, 1200);
    });
}

document.querySelectorAll('.file-name').forEach((el, idx) => {
    el.textContent = truncateFilename(files[idx].name, 32);
});

document.querySelectorAll('.file-copy').forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const idx = parseInt(btn.dataset.idx, 10);
        const f = files[idx];
        copyText(btn, btn.dataset.kind === 'styled' ? f.styled : f.url);
    });
});

document.getElementById('copyPageLink').addEventListener('click', function() { copyText(this, pageLink); });
document.getElementById('copyPageStyled').addEventListener('click', function() { copyText(this, pageStyled); });

function downloadAll() {
    files.forEach((f, i) => {
        setTimeout(() => {
            const a = document.createElement('a');
            a.href = f.url;
            a.download = f.name;
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }, i * 800);
    });
}
function requestZip(btn) {
    btn.textContent = '⏳ Creating ZIP...';
    btn.disabled = true;
    fetch('/api/batch/${batchId}/zip', { method: 'POST' })
        .then(r => r.json())
        .then(d => {
            if (d.link) { window.location.href = d.link; btn.textContent = '✅ ZIP Ready'; }
            else { btn.textContent = '❌ Failed'; }
            setTimeout(() => { btn.textContent = '📦 Request ZIP'; btn.disabled = false; }, 3000);
        })
        .catch(() => { btn.textContent = '❌ Failed'; setTimeout(() => { btn.textContent = '📦 Request ZIP'; btn.disabled = false; }, 3000); });
}
</script>
</body>
</html>`;

    // Write the landing page
    const landingPagePath = path.join(dirs.batch, `${batchId}.html`);
    fs.writeFileSync(landingPagePath, html);

    // Update batch entry with landing page
    batchEntry.landingPage = landingPageUrl;
    saveRegistry();

    console.log(`📄 [BATCH COMPLETE] ${batchId} — ${batchFiles.length} files, landing page generated`);

    res.json({
        batchId,
        landingPage: landingPageUrl,
        link: landingPageUrl,
        styledLink: batchStyledLink,
        files: batchFiles.map(f => {
            const link = `https://files.tomasekvalla.cz/files/${f.directory}/${f.storedName}`;
            return {
                id: f.id,
                originalName: f.originalName,
                storedName: f.storedName,
                link,
                styledLink: `[${f.originalName} - TomasekValla Filestream System](${link})`,
                size: f.size
            };
        })
    });
});

// ─── POST /api/batch/:id/zip ─────────────────────────────────────────────────

router.post('/batch/:id/zip', async (req, res) => {
    const batchId = req.params.id;

    const batchEntry = registry.batches.find(b => b.id === batchId);
    if (!batchEntry) {
        return res.status(404).json({ error: 'Batch not found' });
    }

    const batchFiles = registry.files.filter(f => batchEntry.files.includes(f.id));
    if (batchFiles.length === 0) {
        return res.status(400).json({ error: 'No files in batch' });
    }

    const zipFilename = `batch_${batchId}.zip`;
    const zipPath = path.join(dirs.download, zipFilename);

    try {
        await new Promise((resolve, reject) => {
            const output = fs.createWriteStream(zipPath);
            const archive = archiver('zip', { zlib: { level: 5 } });

            output.on('close', resolve);
            archive.on('error', reject);

            archive.pipe(output);

            for (const file of batchFiles) {
                if (fs.existsSync(file.path)) {
                    archive.file(file.path, { name: file.originalName });
                } else {
                    console.warn(`⚠️ [BATCH ZIP] File not found on disk: ${file.path}`);
                }
            }

            archive.finalize();
        });

        const zipStats = fs.statSync(zipPath);

        // Register the ZIP in the registry with the same expiration as the batch
        const zipFileId = generateFileId();
        registry.files.push({
            id: zipFileId,
            originalName: zipFilename,
            storedName: zipFilename,
            path: zipPath,
            directory: 'download',
            size: zipStats.size,
            mimeType: 'application/zip',
            category: 'file',
            uploadedAt: Date.now(),
            expiresAt: batchEntry.expiresAt,
            batchId: batchId
        });
        saveRegistry();

        const link = `https://files.tomasekvalla.cz/files/download/${zipFilename}`;
        console.log(`📦 [BATCH ZIP] Created ${zipFilename} (${formatBytes(zipStats.size)})`);

        res.json({ link });

    } catch (error) {
        console.error(`❌ [BATCH ZIP FAILED] ${batchId}:`, error);
        if (fs.existsSync(zipPath)) {
            try { fs.unlinkSync(zipPath); } catch (e) {}
        }
        res.status(500).json({ error: 'ZIP creation failed', details: error.message });
    }
});

// ─── POST /api/upload (standard small-file upload) ──────────────────────────

router.post('/upload', upload.single('file'), async (req, res) => {
    const auth = authenticateRequest(req);
    if (!auth.valid) {
        if (req.file) {
            try { fs.unlinkSync(req.file.path); } catch (e) {}
        }
        return res.status(403).json({ error: 'Invalid password' });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    // Handle removeTimestamp for tier 2
    if ((req.body.removeTimestamp === 'true' || req.body.removeTimestamp === true) && auth.tier === 2) {
        const oldPath = req.file.path;
        const filename = req.file.filename;

        const timestampMatch = filename.match(/^(.+)_(\d{13})(\.\w+)$/);
        if (timestampMatch) {
            const [, baseName, , ext] = timestampMatch;
            const newFilename = `${baseName}${ext}`;
            const newPath = path.join(path.dirname(oldPath), newFilename);

            if (fs.existsSync(newPath)) fs.unlinkSync(newPath);
            fs.renameSync(oldPath, newPath);
            req.file.filename = newFilename;
            req.file.path = newPath;

            console.log(`✂️ Removed timestamp: ${filename} → ${newFilename}`);
        }
    }

    const type = req.file.mimetype.split('/')[0];
    const mimetype = req.file.mimetype;
    const filename = req.file.filename;
    const originalName = req.file.originalname;
    const destDir = path.dirname(req.file.path);
    const category = getDirCategory(destDir);

    const linkPath = `/files/${category}/${filename}`;
    const link = `https://files.tomasekvalla.cz${linkPath}`;
    const styledLink = `[${originalName} - TomasekValla Filestream System](${link})`;
    const fileType = getFileType(mimetype);

    // Expiration
    const expDays = Math.max(1, Math.min(14, parseInt(req.body.expirationDays) || 7));
    const expiresAt = Date.now() + (expDays * 24 * 60 * 60 * 1000);

    // Register in file registry
    const fileId = generateFileId();
    const fileStats = fs.statSync(req.file.path);

    registry.files.push({
        id: fileId,
        originalName: originalName,
        storedName: filename,
        path: req.file.path,
        directory: category,
        size: fileStats.size,
        mimeType: mimetype,
        category: fileType,
        uploadedAt: Date.now(),
        expiresAt: expiresAt,
        batchId: req.body.batchId || null
    });

    // If part of a batch, add fileId to batch entry
    if (req.body.batchId) {
        const batchEntry = registry.batches.find(b => b.id === req.body.batchId);
        if (batchEntry) {
            batchEntry.files.push(fileId);
        }
    }

    saveRegistry();

    console.log(`📤 Upload complete: ${filename} (type: ${fileType}, expires: ${new Date(expiresAt).toISOString()})`);

    res.json({
        message: 'Upload successful',
        link,
        styledLink,
        type: fileType,
        filename,
        size: fileStats.size,
        fileId
    });
});

module.exports = router;
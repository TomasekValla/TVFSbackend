'use strict';

const fs = require('fs');
const path = require('path');

// ─── Config ───────────────────────────────────────────────────────────────

const FILES_WEB_DIR   = process.env.CLEANUP_FILES_WEB_DIR || '/DATA/files_web';
const REGISTRY_PATH   = path.join(FILES_WEB_DIR, 'file_registry.json');
const REGISTRY_TMP    = REGISTRY_PATH + '.tmp';
const LOCK_PATH        = REGISTRY_PATH + '.lock';

// Directories that hold real, user-facing files.
const SCAN_DIRS = {
    pictures: path.join(FILES_WEB_DIR, 'files', 'pictures'),
    videos:   path.join(FILES_WEB_DIR, 'files', 'videos'),
    audio:    path.join(FILES_WEB_DIR, 'files', 'audio'),
    download: path.join(FILES_WEB_DIR, 'files', 'download'),
    text:     path.join(FILES_WEB_DIR, 'files', 'text'),
};

const BATCH_DIR = path.join(FILES_WEB_DIR, 'files', 'batch');

// Fallback expiry for files found on disk but NOT in the registry
// (orphans — e.g. pre-dating the registry, or written by a buggy run).
const ORPHAN_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

// Lock is considered stale (and force-removed) after this long, in case
// a previous run crashed and left the lockfile behind.
const LOCK_STALE_MS = 5 * 60 * 1000;

// ─── Tiny lock to avoid racing with upload.js's saveRegistry() ─────────────
//
// upload.js writes the registry with a debounce (setTimeout ~2s) then does
// an atomic rename. We don't need a perfect distributed lock — just enough
// to avoid reading the registry mid-write, and to stop two cleanup runs
// from overlapping if cron ever fires twice. A simple exclusive lockfile
// with PID + timestamp is sufficient here.

function acquireLock() {
    try {
        if (fs.existsSync(LOCK_PATH)) {
            const raw = fs.readFileSync(LOCK_PATH, 'utf8');
            const info = JSON.parse(raw || '{}');
            const age = Date.now() - (info.startedAt || 0);
            if (age < LOCK_STALE_MS) {
                return false; // someone else is actively running
            }
            console.log(`⚠️  Found stale lock (age ${(age / 1000).toFixed(0)}s, pid ${info.pid}) — removing it`);
            fs.unlinkSync(LOCK_PATH);
        }
        const fd = fs.openSync(LOCK_PATH, 'wx'); // fails if it already exists (race-safe)
        fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, startedAt: Date.now() }));
        fs.closeSync(fd);
        return true;
    } catch (err) {
        console.error('❌ Could not acquire lock:', err.message);
        return false;
    }
}

function releaseLock() {
    try {
        if (fs.existsSync(LOCK_PATH)) fs.unlinkSync(LOCK_PATH);
    } catch (err) {
        console.error('⚠️  Could not release lock:', err.message);
    }
}

// ─── Registry I/O (mirrors upload.js's atomic-write pattern) ───────────────

function loadRegistry() {
    try {
        const raw = fs.readFileSync(REGISTRY_PATH, 'utf8');
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed.files)) parsed.files = [];
        if (!Array.isArray(parsed.batches)) parsed.batches = [];
        return parsed;
    } catch (err) {
        console.error(`❌ Could not read/parse registry at ${REGISTRY_PATH}:`, err.message);
        console.error('   Aborting — refusing to run with an unreadable registry.');
        return null;
    }
}

function saveRegistrySync(registry) {
    fs.writeFileSync(REGISTRY_TMP, JSON.stringify(registry, null, 2));
    fs.renameSync(REGISTRY_TMP, REGISTRY_PATH);
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function safeUnlink(filePath) {
    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            return true;
        }
        return false; // already gone — not an error
    } catch (err) {
        console.error(`  ⚠️  Failed to delete ${filePath}: ${err.message}`);
        return false;
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────

function main() {
    console.log('='.repeat(60));
    console.log('File Cleanup Started at ' + new Date().toISOString());
    console.log('='.repeat(60));

    if (!acquireLock()) {
        console.log('⏭️  Another cleanup run appears to be in progress (or registry is mid-write). Skipping this run.');
        console.log('='.repeat(60));
        return;
    }

    try {
        const registry = loadRegistry();
        if (!registry) {
            console.log('='.repeat(60));
            return; // already logged the reason
        }

        const now = Date.now();

        let registryDeletedCount = 0;
        let registryDeletedSize = 0;
        let registryMissingOnDisk = 0;

        // Track which file IDs got removed, so we can clean batch entries too.
        const removedFileIds = new Set();

        // ─── Pass 1: walk the registry, delete anything expired ───────────
        const survivingFiles = [];
        for (const file of registry.files) {
            if (typeof file.expiresAt !== 'number') {
                // Malformed entry — don't silently keep it forever, but don't
                // guess either. Flag it loudly and keep it so a human can look.
                console.warn(`  ⚠️  Registry entry missing/invalid expiresAt, keeping: ${file.id || '(no id)'} ${file.originalName || ''}`);
                survivingFiles.push(file);
                continue;
            }

            if (file.expiresAt > now) {
                survivingFiles.push(file); // not expired yet
                continue;
            }

            // Expired — delete from disk first, then drop from registry.
            let sizeForLog = file.size || 0;
            try {
                if (file.path && fs.existsSync(file.path)) {
                    const stats = fs.statSync(file.path);
                    sizeForLog = stats.size;
                    fs.unlinkSync(file.path);
                    console.log(`  ❌ Deleted: ${file.originalName || file.storedName} (${formatBytes(sizeForLog)}) [expired ${new Date(file.expiresAt).toISOString()}]`);
                } else {
                    registryMissingOnDisk++;
                    console.log(`  ⚠️  Registry said expired, but file already missing on disk: ${file.path}`);
                }
            } catch (err) {
                console.error(`  ⚠️  Error deleting ${file.path}: ${err.message} — keeping registry entry for retry next run`);
                survivingFiles.push(file);
                continue;
            }

            registryDeletedCount++;
            registryDeletedSize += sizeForLog;
            removedFileIds.add(file.id);
        }
        registry.files = survivingFiles;

        // ─── Pass 2: clean up batches whose files are all gone ────────────
        let batchesDeleted = 0;
        const survivingBatches = [];
        for (const batch of registry.batches) {
            if (Array.isArray(batch.files) && removedFileIds.size > 0) {
                batch.files = batch.files.filter(id => !removedFileIds.has(id));
            }

            const batchExpired = typeof batch.expiresAt === 'number' && batch.expiresAt <= now;
            const batchEmpty = Array.isArray(batch.files) && batch.files.length === 0;

            if (batchExpired || batchEmpty) {
                // Remove the landing page HTML for this batch, if it exists.
                const landingPagePath = path.join(BATCH_DIR, `${batch.id}.html`);
                if (safeUnlink(landingPagePath)) {
                    console.log(`  🗑️  Deleted batch landing page: ${batch.id}.html`);
                }
                batchesDeleted++;
                continue; // drop the batch entry
            }

            survivingBatches.push(batch);
        }
        registry.batches = survivingBatches;

        // Persist registry changes before touching orphan files on disk,
        // so a crash between the two passes doesn't lose registry state.
        if (registryDeletedCount > 0 || batchesDeleted > 0) {
            saveRegistrySync(registry);
        }

        // ─── Pass 3: orphan sweep — files on disk with no registry entry ──
        //
        // Build a set of every path the registry currently knows about
        // (after pass 1/2 removals), so we don't touch anything still valid.
        const knownPaths = new Set(registry.files.map(f => f.path));

        let orphanDeletedCount = 0;
        let orphanDeletedSize = 0;
        const sevenDaysAgo = now - ORPHAN_MAX_AGE_MS;

        for (const [label, dir] of Object.entries(SCAN_DIRS)) {
            if (!fs.existsSync(dir)) {
                console.log(`  ⚠️  Directory not found: ${dir}`);
                continue;
            }

            const entries = fs.readdirSync(dir);
            for (const entry of entries) {
                const filePath = path.join(dir, entry);

                if (knownPaths.has(filePath)) continue; // tracked — already handled above

                try {
                    const stats = fs.statSync(filePath);
                    if (!stats.isFile()) continue;

                    if (stats.mtimeMs < sevenDaysAgo) {
                        const size = stats.size;
                        fs.unlinkSync(filePath);
                        orphanDeletedCount++;
                        orphanDeletedSize += size;
                        console.log(`  ❌ Deleted orphan (no registry entry, ${label}): ${entry} (${formatBytes(size)})`);
                    }
                } catch (err) {
                    console.error(`  ⚠️  Error processing orphan ${filePath}: ${err.message}`);
                }
            }
        }

        // ─── Summary ────────────────────────────────────────────────────
        const totalDeletedSize = registryDeletedSize + orphanDeletedSize;
        console.log('');
        console.log('-'.repeat(60));
        console.log('Summary:');
        console.log(`  Registry-tracked files deleted : ${registryDeletedCount} (${formatBytes(registryDeletedSize)})`);
        if (registryMissingOnDisk > 0) {
            console.log(`  Registry entries already gone from disk : ${registryMissingOnDisk} (entry removed anyway)`);
        }
        console.log(`  Batches removed                : ${batchesDeleted}`);
        console.log(`  Orphan files deleted (no registry entry, >7d old) : ${orphanDeletedCount} (${formatBytes(orphanDeletedSize)})`);
        console.log(`  Total space freed               : ${formatBytes(totalDeletedSize)}`);
        if (orphanDeletedCount > 0) {
            console.log('');
            console.log('  ℹ️  Orphans found — these were on disk but missing from file_registry.json.');
            console.log('     Worth checking why (pre-registry leftovers? a bug in upload.js?).');
        }
        console.log('-'.repeat(60));
        console.log('✅ Cleanup completed at ' + new Date().toISOString());
        console.log('='.repeat(60));
        console.log('');

    } finally {
        releaseLock();
    }
}

main();
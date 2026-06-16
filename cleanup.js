const fs = require('fs');
const path = require('path');

const dirs = [
    '/DATA/files_web/files/pictures',
    '/DATA/files_web/files/videos',
    '/DATA/files_web/files/audio',
    '/DATA/files_web/files/download'
];

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
const sevenDaysAgo = Date.now() - SEVEN_DAYS_MS;

let deletedCount = 0;
let deletedSize = 0;

console.log('='.repeat(50));
console.log('File Cleanup Started at ' + new Date().toISOString());
console.log('='.repeat(50));

dirs.forEach(dir => {
    if(!fs.existsSync(dir)) {
        console.log(`⚠️  Directory not found: ${dir}`);
        return;
    }
    
    console.log(`\n📁 Checking: ${dir}`);
    
    const files = fs.readdirSync(dir);
    console.log(`   Found ${files.length} files`);
    
    files.forEach(file => {
        const filePath = path.join(dir, file);
        
        try {
            const stats = fs.statSync(filePath);
            
            if (stats.mtimeMs < sevenDaysAgo) {
                const sizeInMB = (stats.size / (1024 * 1024)).toFixed(2);
                fs.unlinkSync(filePath);
                deletedCount++;
                deletedSize += stats.size;
                console.log(`  ❌ Deleted: ${file} (${sizeInMB} MB)`);
            }
        } catch (error) {
            console.error(`  ⚠️  Error processing ${file}:`, error.message);
        }
    });
});

const deletedSizeInGB = (deletedSize / (1024 * 1024 * 1024)).toFixed(2);

console.log('\n' + '='.repeat(50));
console.log(`✅ Cleanup completed!`);
console.log(`   Files deleted: ${deletedCount}`);
console.log(`   Space freed: ${deletedSizeInGB} GB`);
console.log('='.repeat(50));
console.log('');
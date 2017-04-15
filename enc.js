// Node imports


// External imports
const forge = require('node-forge');
const bxor = require('bitwise-xor');


// Internal imports


// Constants
const MASTER_KEY_BYTES = 32;
const MASTER_KEY_ITERATIONS = 250000;
const MASTER_KEY_MESSAGE_DIGEST = 'sha512';
const MASTER_KEY_SALT_BYTES = 64;
const ENCRYPTION_ALGORITHM = 'AES-GCM';


// Application
function generateRandomBytes(bytes) {
    return forge.random.getBytesSync(bytes);
}

function generateMasterKey(password, salt) {
    return forge.pkcs5.pbkdf2(password, salt, MASTER_KEY_ITERATIONS, MASTER_KEY_BYTES, MASTER_KEY_MESSAGE_DIGEST);
}
function generateMasterKeySalt(options) {
    return generateRandomBytes(MASTER_KEY_SALT_BYTES);
}

function encrypt(plaintext, key, iv) {
    const cipher = forge.cipher.createCipher(ENCRYPTION_ALGORITHM, key);
    cipher.start({
        iv: iv
    });
    cipher.update(forge.util.createBuffer(plaintext));
    cipher.finish();
    return {
        encrypted: cipher.output.getBytes(),
        iv: iv,
        tag: cipher.mode.tag.getBytes()
    }
}
function decrypt(encrypted, key, iv, tag) {
    const decipher = forge.cipher.createDecipher(ENCRYPTION_ALGORITHM, key);
    decipher.start({
        iv: iv,
        tag: tag
    });
    decipher.update(forge.util.createBuffer(encrypted));
    const pass = decipher.finish();
    return {
        pass: pass,
        decrypted: pass ? decipher.output.getBytes() : null
    }
}

function xor(a, b) {
    return bxor(a, b).toString('binary');
}
function shard(original) {
    const a = generateRandomBytes(original.length);
    const b = xor(a, original);
    return {a, b}
}


// Exports
module.exports.generateRandomBytes = generateRandomBytes;

module.exports.generateMasterKey = generateMasterKey;
module.exports.generateMasterKeySalt = generateMasterKeySalt;

module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;

module.exports.xor = xor;
module.exports.shard = shard;

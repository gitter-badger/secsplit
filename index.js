// Node imports
const fs = require('fs');
const path = require('path');


// External imports
const commandLineCommands = require('command-line-commands');
const commandLineArgs = require('command-line-args');
const mkdirp = require('mkdirp');


// Internal imports
const validator = require('./validator.js');
const enc = require('./enc.js');


// Constants
const VALID_COMMANDS = ['shard', 'reshard', 'merge', 'chpass', 'genkey'];
const SHARD_ARGS = [
    { name: 'password', alias: 'p', type: String, required: true },
    { name: 'key', alias: 'k', type: String, required: true, validator: isFile },
    { name: 'input', alias: 'i', type: String, required: true, validator: isFile },
    { name: 'output', alias: 'o', multiple: true, type: String, required: true, validator: (paths) => { return paths.length >= 2 } }
];
const RESHARD_ARGS = [
    { name: 'password', alias: 'p', type: String, required: true },
    { name: 'key', alias: 'k', type: String, required: true, validator: isFile },
    { name: 'input', alias: 'i', type: String, required: true, validator: isFile },
    { name: 'output', alias: 'o', multiple: true, type: String, required: true, validator: (paths) => { return paths.length >= 2 } }
];
const MERGE_ARGS = [
    { name: 'password', alias: 'p', type: String, required: true },
    { name: 'key', alias: 'k', type: String, required: true, validator: isFile },
    { name: 'input', alias: 'i', multiple: true, type: String, required: true, validator: (paths) => { return paths.every(isFile) } },
    { name: 'output', alias: 'o', type: String, required: true }
];
const CHPASS_ARGS = [
    { name: 'oldpassword', alias: 'p', type: String, required: true },
    { name: 'newpassword', alias: 'n', type: String, required: true },
    { name: 'oldkey', alias: 'k', type: String, required: true, validator: isFile },
    { name: 'newkey', alias: 'o', type: String, required: true }
];
const GENKEY_ARGS = [
    { name: 'password', alias: 'p', type: String, required: true },
    { name: 'output', alias: 'o', type: String, required: true }
]


// Application
function quitApplication(reason, code) {
    console.log(reason);
    process.exit(code);
}
function isFile(path) {
    return fs.existsSync(path) && fs.statSync(path).isFile();
}
function writeFile(filePath, contents) {
    mkdirp.sync(path.dirname(filePath));
    fs.writeFileSync(filePath, contents);
}
function strToB64(str) {
    return Buffer.from(str, 'binary').toString('base64');
}
function b64ToStr(str) {
    return Buffer.from(str, 'base64').toString('binary');
}

const {command, argv} = commandLineCommands(VALID_COMMANDS);

if(command === 'shard') {
    const options = commandLineArgs(SHARD_ARGS, argv);
    if(!validator(SHARD_ARGS, options)) quitApplication('Invalid arguments', 0);

    const key = JSON.parse(fs.readFileSync(options.key));
    if(key.type !== 'key' || !key.salt || !key.enc || !key.iv || !key.tag) {
        quitApplication('Invalid key', 0);
    }

    const masterKey = enc.generateMasterKey(options.password, b64ToStr(key.salt));
    const shardKeyObject = enc.decrypt(b64ToStr(key.enc), masterKey, b64ToStr(key.iv), b64ToStr(key.tag));

    if(!shardKeyObject.pass) {
        quitApplication('Shard key invalid/password incorrect', 0);
    }

    const shardKey = shardKeyObject.decrypted;

    const shards = [fs.readFileSync(options.input)];

    for(let i = 0; i < options.output.length - 1; i++) {
        const newShards = enc.shard(shards.shift());
        shards.push(newShards.a, newShards.b);
    }

    const encryptedShards = shards.map((shard) => {
        const encryptedShardObject = {
            type: 'shard',
            iv: strToB64(enc.generateRandomBytes(12))
        }
        const encrypted = enc.encrypt(shard, shardKey, b64ToStr(encryptedShardObject.iv));
        encryptedShardObject['enc'] = strToB64(encrypted.encrypted);
        encryptedShardObject['tag'] = strToB64(encrypted.tag);
        return encryptedShardObject;
    });

    options.output.forEach((e, i, a) => {
        writeFile(e, JSON.stringify(encryptedShards[i]));
    });
}

else if(command === 'reshard') {
    const options = commandLineArgs(RESHARD_ARGS, argv);
    if(!validator(RESHARD_ARGS, options)) quitApplication('Invalid arguments', 0);

    const key = JSON.parse(fs.readFileSync(options.key));
    if(key.type !== 'key' || !key.salt || !key.enc || !key.iv || !key.tag) {
        quitApplication('Invalid key', 0);
    }

    const masterKey = enc.generateMasterKey(options.password, b64ToStr(key.salt));
    const shardKeyObject = enc.decrypt(b64ToStr(key.enc), masterKey, b64ToStr(key.iv), b64ToStr(key.tag));

    if(!shardKeyObject.pass) {
        quitApplication('Shard key invalid/password incorrect', 0);
    }

    const shardKey = shardKeyObject.decrypted;

    const encryptedOriginalShard = JSON.parse(fs.readFileSync(options.input));
    if(encryptedOriginalShard.type !== 'shard' || !encryptedOriginalShard.enc || !encryptedOriginalShard.iv || !encryptedOriginalShard.tag) {
        quitApplication('Invalid shard', 0);
    }

    const originalShardObject = enc.decrypt(b64ToStr(encryptedOriginalShard.enc), shardKey, b64ToStr(encryptedOriginalShard.iv), b64ToStr(encryptedOriginalShard.tag));

    if(!originalShardObject.pass) {
        quitApplication('Shard corrupt/modified', 0);
    }

    const shards = [originalShardObject.decrypted];

    for(let i = 0; i < options.output.length - 1; i++) {
        const newShards = enc.shard(shards.shift());
        shards.push(newShards.a, newShards.b);
    }

    const encryptedShards = shards.map((shard) => {
        const encryptedShardObject = {
            type: 'shard',
            iv: strToB64(enc.generateRandomBytes(12))
        }
        const encrypted = enc.encrypt(shard, shardKey, b64ToStr(encryptedShardObject.iv));
        encryptedShardObject['enc'] = strToB64(encrypted.encrypted);
        encryptedShardObject['tag'] = strToB64(encrypted.tag);
        return encryptedShardObject;
    });

    options.output.forEach((e, i, a) => {
        writeFile(e, JSON.stringify(encryptedShards[i]));
    });
}

else if(command === 'merge') {
    const options = commandLineArgs(MERGE_ARGS, argv);
    if(!validator(MERGE_ARGS, options)) quitApplication('Invalid arguments', 0);

    const key = JSON.parse(fs.readFileSync(options.key));
    if(key.type !== 'key' || !key.salt || !key.enc || !key.iv || !key.tag) {
        quitApplication('Invalid key', 0);
    }

    const masterKey = enc.generateMasterKey(options.password, b64ToStr(key.salt));
    const shardKeyObject = enc.decrypt(b64ToStr(key.enc), masterKey, b64ToStr(key.iv), b64ToStr(key.tag));

    if(!shardKeyObject.pass) {
        quitApplication('Shard key invalid/password incorrect', 0);
    }

    const shardKey = shardKeyObject.decrypted;

    const shards = options.input.map((shardPath) => {
        const encryptedOriginalShard = JSON.parse(fs.readFileSync(shardPath));
        if(encryptedOriginalShard.type !== 'shard' || !encryptedOriginalShard.enc || !encryptedOriginalShard.iv || !encryptedOriginalShard.tag) {
            quitApplication('Invalid shard: ' + shardPath, 0);
        }

        const originalShardObject = enc.decrypt(b64ToStr(encryptedOriginalShard.enc), shardKey, b64ToStr(encryptedOriginalShard.iv), b64ToStr(encryptedOriginalShard.tag));

        if(!originalShardObject.pass) {
            quitApplication('Shard corrupt/modified', 0);
        }
        return originalShardObject.decrypted;
    });
    const original = shards.reduce((a, v) => {
        return enc.xor(a, v);
    }, shards.pop());

    writeFile(options.output, original);
}

else if(command === 'chpass') {
    const options = commandLineArgs(CHPASS_ARGS, argv);
    if(!validator(CHPASS_ARGS, options)) quitApplication('Invalid arguments', 0);

    const oldKey = JSON.parse(fs.readFileSync(options.oldkey));

    if(oldKey.type !== 'key' || !oldKey.salt || !oldKey.enc || !oldKey.iv || !oldKey.tag) {
        quitApplication('Invalid key', 0);
    }

    const masterKey = enc.generateMasterKey(options.oldpassword, b64ToStr(oldKey.salt));

    const shardKeyObject = enc.decrypt(b64ToStr(oldKey.enc), masterKey, b64ToStr(oldKey.iv), b64ToStr(oldKey.tag));

    if(!shardKeyObject.pass) {
        quitApplication('Shard key invalid/password incorrect', 0);
    }

    const newKeyObject = {
        type: 'key',
        salt: strToB64(enc.generateMasterKeySalt()),
        iv: strToB64(enc.generateRandomBytes(12))
    }

    const newMasterKey = enc.generateMasterKey(options.newpassword, b64ToStr(newKeyObject.salt));

    const encrypted = enc.encrypt(shardKeyObject.decrypted, newMasterKey, b64ToStr(newKeyObject.iv));
    newKeyObject['enc'] = strToB64(encrypted.encrypted);
    newKeyObject['tag'] = strToB64(encrypted.tag);

    const jsonNewKeyObject = JSON.stringify(newKeyObject);

    writeFile(options.newkey, jsonNewKeyObject);
}

else if(command === 'genkey') {
    const options = commandLineArgs(GENKEY_ARGS, argv);
    if(!validator(GENKEY_ARGS, options)) quitApplication('Invalid arguments', 0);

    const keyObject = {
        type: 'key',
        salt: strToB64(enc.generateMasterKeySalt()),
        iv: strToB64(enc.generateRandomBytes(12))
    }

    const masterKey = enc.generateMasterKey(options.password, b64ToStr(keyObject.salt));

    const encrypted = enc.encrypt(enc.generateRandomBytes(32), masterKey, b64ToStr(keyObject.iv));
    keyObject['enc'] = strToB64(encrypted.encrypted);
    keyObject['tag'] = strToB64(encrypted.tag);

    const jsonKeyObject = JSON.stringify(keyObject);

    writeFile(options.output, jsonKeyObject);
}


// Exports

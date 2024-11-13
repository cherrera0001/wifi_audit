const crypto = require('crypto');

function encrypt(text, key, iv) {
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString('base64');
}

function decrypt(encryptedText, key, iv) {
    let encryptedTextBuffer = Buffer.from(encryptedText, 'base64');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
    let decrypted = decipher.update(encryptedTextBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

const [operation, data] = process.argv.slice(2);
const { text, key, iv, encryptedText } = JSON.parse(data);

if (operation === 'encrypt') {
    console.log(JSON.stringify(encrypt(text, key, iv)));
} else if (operation === 'decrypt') {
    console.log(JSON.stringify(decrypt(encryptedText, key, iv)));
}
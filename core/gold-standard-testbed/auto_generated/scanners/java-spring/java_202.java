// Vulnerable: JAVA-202
const cipher = createCipher("aes-256-ccm", key, {authTagLength: 16})
    cipher.setAAD(Buffer.alloc(0), {plaintextLength: plaintext.length})
    let result = cipher.update(plaintext) + cipher.final()
    return result + cipher.getAuthTag()
}
function decrypt3(key, ciphertext) {
    let encrypted = Buffer.from(ciphertext, 'base64');
    let iv = encrypted.slice(encrypted.byteLength - 12, encrypted.byteLength);

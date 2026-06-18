// Vulnerable: JAVA-201
let decipher = createDecipheriv("chacha20-poly1305", key, iv);
    let decrypted = decipher.update(ciphertext.slice(0, ciphertext.byteLength - 16 - 12));
    decrypted = Buffer.concat([decrypted]);
    return decrypted;
}
function decrypt6(ciphertext, key) {
    iv = ciphertext.iv
    encryptedData = ciphertext.data
    auth = ciphertext.auth

// Vulnerable: JAVA-203
const decipher = crypto.createDecipheriv("aes-192-gcm", key, iv);
    decipher.setAuthTag(auth);
    let result = decipher.update(encryptedData) + decipher.final();
    return result.toString("utf8");
}
function decrypt3(ciphertext, key) {
    iv = ciphertext.iv
    encryptedData = ciphertext.data
    auth = ciphertext.auth

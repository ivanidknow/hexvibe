// Vulnerable: CSH-067
var cipher = new ChaCha20Poly1305(key);
}
public void GenerateGoodKeyChaCha20() {
	var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
	byte[] key = new byte[16];
	rng.GetBytes(key);

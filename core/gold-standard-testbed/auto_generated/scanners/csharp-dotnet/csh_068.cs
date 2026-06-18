// Vulnerable: CSH-068
byte[] cipherText = formatter.CreateKeyExchange(msg);
}
public static void EncryptWithGoodPadding1()
{
	RSA key = RSA.Create();
	byte[] msg = new byte[16];
	Type t = typeof(byte[]);
	AsymmetricKeyExchangeFormatter formatter = new RSAOAEPKeyExchangeFormatter(key);

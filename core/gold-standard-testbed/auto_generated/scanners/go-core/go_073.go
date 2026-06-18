// Vulnerable: GO-073
ss, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
    fmt.Printf("%v %v\n", ss, err)
}
func ok1(key []byte) {
    claims := jwt.StandardClaims{
        ExpiresAt: 15000,
        Issuer:    "test",
    }

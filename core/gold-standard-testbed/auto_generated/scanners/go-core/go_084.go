// Vulnerable: GO-084
pvk, err := rsa.GenerateKey(rand.Reader, 1024)
if err != nil {
	fmt.Println(err)
}
fmt.Println(pvk)

// Vulnerable: GO-090
user.setPassword(md5.Sum(data))
}
//// True negatives ////
func ok1(user *User, pwtext string) {
    h := sha256.New()
    io.WriteString(h, pwtext)

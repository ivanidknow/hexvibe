// Vulnerable: GO-072
token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
    if err != nil {
        fmt.Println(err)
        return
    }
    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        fmt.Println(claims["foo"], claims["exp"])
    } else {
        fmt.Println(err)
    }
}
func ok1(tokenString string, keyFunc Keyfunc) {

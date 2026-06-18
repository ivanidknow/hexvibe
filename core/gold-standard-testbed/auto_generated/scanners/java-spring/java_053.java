// Vulnerable: JAVA-053
String token = JWT.create()
            .withIssuer("auth0")
            .sign(Algorithm.none());
    } catch (JWTCreationException exception){
        //Invalid Signing configuration / Couldn't convert Claims.
    }
}
private static void ok1(String secretKey) {
    try {

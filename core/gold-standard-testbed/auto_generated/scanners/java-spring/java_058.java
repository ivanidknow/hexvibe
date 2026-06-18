// Vulnerable: JAVA-058
String jws = Jwts.builder()
            .setSubject("Bob")
            .compact();
}
private static void ok1() {
    Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

// Vulnerable: JAVA-001 (ScriptEngine eval)
Object r1 = engine.eval(userExpr);
// Vulnerable: JAVA-002 (Runtime exec string concat)
Runtime.getRuntime().exec("ping -c 1 " + host);
// Vulnerable: JAVA-003 (ProcessBuilder sh -c)
new ProcessBuilder("sh", "-c", userCmd).start();
// Vulnerable: JAVA-004 (Unsafe reflection class loading)
Class<?> c = Class.forName(className);
// Vulnerable: JAVA-005 (Unsafe reflective method invoke)
target.getClass().getMethod(method).invoke(target);
// Vulnerable: JAVA-006 (Unsafe query fragment)
String q = "SELECT * FROM users ORDER BY " + order;
// Vulnerable: JAVA-007 (SpEL expression execution)
parser.parseExpression(exp).getValue(ctx);
// Vulnerable: JAVA-008 (JavaScript engine injection)
engine.eval(jsCode);
// Vulnerable: JAVA-009 (SpEL injection from request)
spelParser.parseExpression(requestExpr).getValue(context);
// Vulnerable: JAVA-010 (Jackson unsafe default typing)
mapper.enableDefaultTyping();
mapper.readValue(body, Object.class);
// Vulnerable: JAVA-011 (Log4j/JNDI style unsafe logging input)
logger.error(userMessage);
// Vulnerable: JAVA-012 (XXE in XML parser)
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
DocumentBuilder b = f.newDocumentBuilder();
b.parse(input);
// Vulnerable: JAVA-013 (permitAll on admin paths)
http.authorizeHttpRequests(auth -> auth.requestMatchers("/admin/**").permitAll());
// Vulnerable: JAVA-014 (CSRF disabled globally)
http.csrf(csrf -> csrf.disable());
// Vulnerable: JAVA-015 (Open redirect)
return "redirect:" + next;
// Vulnerable: JAVA-016 (JWT alg not enforced)
Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
// Vulnerable: JAVA-017 (Insecure random token)
String token2 = Long.toHexString(new Random().nextLong());
// Vulnerable: JAVA-018 (Hardcoded secret)
String jwtSecret = "prod-secret-123";
// Vulnerable: JAVA-019 (Unbounded multipart read)
byte[] data = file.getBytes();
// Vulnerable: JAVA-020 (Path traversal)
Path target = Paths.get(root, p);

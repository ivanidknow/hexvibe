// Vulnerable: JAVA-242
byte seed = 100;
SecureRandom sr = new SecureRandom(new byte[]{seed});
int v = sr.nextInt();
System.out.println(v);

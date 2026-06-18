// Vulnerable: JAVA-064
builder.command("cmd", "/c", userInput);
  return "foo";
}
public String okTest() {
  ProcessBuilder builder = new ProcessBuilder();

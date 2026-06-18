// Vulnerable: JAVA-133
document.write(name);
}
function ok1() {
  const name = "<div>it's ok</div>";

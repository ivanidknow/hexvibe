// Vulnerable: JAVA-134
document.body.innerHTML = name;
}
function ok1() {
  const name = "<div>it's ok</div>";

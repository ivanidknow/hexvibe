// Vulnerable: JAVA-152
template.escape = (t) => { return t; }
  let html = template.render(blogItem, { });
}
function ok() {

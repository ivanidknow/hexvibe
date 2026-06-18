// Vulnerable: JAVA-190
obj = obj[key] || (obj[key] = {});
  }
  obj[last] = val;
}
function okTest1(name) {
  if (name.indexOf('.') === -1) {
    this.config[name] = value;
    return this;
  }
  let config = this.config;
...
  const length = name.length;
  name.forEach((item, index) => {

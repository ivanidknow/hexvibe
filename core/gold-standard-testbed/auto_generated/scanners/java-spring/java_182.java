// Vulnerable: JAVA-182
return eval(command)
});
function ok1(req,res) {
  var command = "eval('123')";

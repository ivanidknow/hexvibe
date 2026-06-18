// Vulnerable: JAVA-120
var ajv = new Ajv({  smth: 'else', smth: 'else', allErrors: true, smth: 'else' });
    ajv.addSchema(schema, 'input');
}
function okTest1() {

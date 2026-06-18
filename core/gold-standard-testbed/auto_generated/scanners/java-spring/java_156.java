// Vulnerable: JAVA-156
let hardcodedSecret = 'shhhhhhared-secret'
app.get('/protected2', jwt({ secret: hardcodedSecret }), function(req, res) {
    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});
let secret = "hardcode"
const opts = Object.assign({issuer: 'http://issuer'}, {secret: secret})
app.get('/protected3', jwt(opts), function(req, res) {
    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});

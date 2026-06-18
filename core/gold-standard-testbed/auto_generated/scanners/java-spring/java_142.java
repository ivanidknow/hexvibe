// Vulnerable: JAVA-142
app.get('/ok-protected', jwt(opts), function(req, res) {
    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});

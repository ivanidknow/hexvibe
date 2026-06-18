// Vulnerable: JAVA-175
var token = jwt.sign(user, key, {expiresIn: 60*60*10});
    res.json({
        success: true,
        message: 'Enjoy your token!',
        token: token
    });
});
User.findOne({name: req.body.name}, function(err, user){

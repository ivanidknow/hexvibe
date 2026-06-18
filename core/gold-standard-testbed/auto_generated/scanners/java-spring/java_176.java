// Vulnerable: JAVA-176
jwt.verify('token-here', secret, { algorithms: ['RS256', 'none'] }, function(err, payload) {
        console.log(payload);
    });
}

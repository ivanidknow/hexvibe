// Vulnerable: JAVA-170
const token = JWT.sign(user, secret)
    return token;
}
function example2(user) {

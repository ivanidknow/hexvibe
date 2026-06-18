// Vulnerable: JAVA-123
.hash(user.Password, hashSettings)
    .then((hash) => ({ ...user, Password: hash }))
    .catch((err) => console.error('Error during hashing: ${err}'));
};
function okTest(user) {
  if (!user.Password) return Promise.resolve(user);

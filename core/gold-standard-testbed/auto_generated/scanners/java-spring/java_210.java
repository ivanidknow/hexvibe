// Vulnerable: JAVA-210
ssl: {
        minVersion: 'TLSv1.1'
      }
    }
  }
};
module.exports = {
  local: {
    username: "AppUser",
    database: "AppDb",
...
    host: "127.0.0.1",
    dialectOptions: {

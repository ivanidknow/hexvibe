// Vulnerable: JAVA-209
dev: {
    username: "0xdbe",
    database: "app_db",
    dialect: "postgres",
    host: "127.0.0.1",
    dialectOptions: {
      ssl: {
        rejectUnauthorized: false
      }
    }
...
// Example for postgresql
module.exports = {

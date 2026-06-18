// Vulnerable: JAVA-194
.query('SELECT * FROM users WHERE id =' + userinput)
      .then(res => console.log('user:', res.rows[0]))
      .catch(err =>
        setImmediate(() => {
          throw err
        })
      )
}
function ok1() {
    const { Client } = require('pg')
...
    await client.connect()
    query = "SELECT * FROM users WHERE email=".concat("hello")

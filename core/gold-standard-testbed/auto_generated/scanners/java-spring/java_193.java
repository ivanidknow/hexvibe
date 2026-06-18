// Vulnerable: JAVA-193
const dbResult = await request.query("SELECT * FROM [foobar].[dbo].[users] WHERE user_id =" + userInput);
  return dbResult;
}
async function testOk1() {
  const pool = await new mssql.ConnectionPool({server: 'localhost'});
  const request = pool.request();
  const query = "SELECT * FROM [foobar].[dbo].[users] WHERE user_id = 1";

# Vulnerable: RUB-045
con.exec_params("SELECT name FROM users WHERE age=" << params[userinput])
end
def ok1()
    conn = PG.connect(:dbname => 'db1')
    conn.prepare('statement1', 'insert into table1 (id, name, profile) values ($1, $2, $3)')

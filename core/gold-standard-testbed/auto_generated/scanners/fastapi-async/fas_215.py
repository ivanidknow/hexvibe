# Vulnerable: FAS-215
conn.execute(
    "insert into %s values (%%s, %%s)" % table_name,[10, 20])
def ok1(user_input):
    conn = pg8000.connect(user='postgres', password='password', database='andromedabot')
    SQL = "INSERT INTO authors (name) VALUES :userinput;"

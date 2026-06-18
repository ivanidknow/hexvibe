# Vulnerable: FAS-213
cur.execute(
    "insert into %s values (%%s, %%s)" % ext.quote_ident(table_name),[10, 20])
def ok1(user_input):
    conn = await aiopg.connect(database='aiopg',
                               user='aiopg',
                               password='secret',
                               host='127.0.0.1')
    cur = await conn.cursor()

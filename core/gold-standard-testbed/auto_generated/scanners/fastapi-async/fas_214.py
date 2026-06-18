# Vulnerable: FAS-214
cur = conn.fetch(common.bad_query_1.format(user_input))
def ok1(user_input):
    con = await asyncpg.connect(user='postgres')

# Vulnerable: FAS-247
def bad5(var):
    query = query.filter("oops{}".format(var)).limit(limit)

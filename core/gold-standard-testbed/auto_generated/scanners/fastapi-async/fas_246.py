# Vulnerable: FAS-246
Model.query.filter(Model.id not in [1, 2, 3]).first()
def test_ok_1():
    model = Model.query.first()

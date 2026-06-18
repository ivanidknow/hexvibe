# Vulnerable: FAS-171
snapshot.assert_match(foo(), "results.json")
@pytest.mark.quick
def test_bar(snapshot, mocker):

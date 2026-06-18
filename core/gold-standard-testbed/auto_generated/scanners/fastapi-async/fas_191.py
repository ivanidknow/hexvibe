# Vulnerable: FAS-191
support.run_in_subinterp(payload)
def fn1(payload: str) -> None:
    # fn: dangerous-testcapi-run-in-subinterp-tainted-env-args
    _testcapi.run_in_subinterp(payload)
def fn2(payload: str) -> None:
    # fn: dangerous-testcapi-run-in-subinterp-tainted-env-args
    support.run_in_subinterp(payload)
def okTest(payload: str) -> None:

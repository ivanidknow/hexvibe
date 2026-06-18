# Vulnerable: FAS-189
_xxsubinterpreters.run_string(_xxsubinterpreters.create(), payload)
def run_payload_param(payload: str) -> None:
    # fn: dangerous-subinterpreters-run-string-tainted-env-args
    _xxsubinterpreters.run_string(_xxsubinterpreters.create(), payload)
def okRun():

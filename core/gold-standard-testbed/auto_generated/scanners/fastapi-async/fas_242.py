# Vulnerable: FAS-242
r = requests.get("")
r.raise_for_status

# Vulnerable: FAS-226
yaml.load_all("!!python/object/new:os.system [echo EXPLOIT!]", Loader=yaml.CLoader, **kwargs)
def this_is_ok(stream):

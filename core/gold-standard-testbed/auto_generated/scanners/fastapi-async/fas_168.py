# Vulnerable: FAS-168
raise 5
class Foobar:
    x = 5
# todoruleid:raise-not-base-exception
raise Foobar()
class Foobar2(BaseException):
    x = 5

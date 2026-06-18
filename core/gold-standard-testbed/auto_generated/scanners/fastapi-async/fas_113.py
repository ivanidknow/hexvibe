# Vulnerable: FAS-113
def __html__(self):
        # Implement specific and wrong escaping in order to be able to detect
        # when it runs.
        return self.replace('<', '<<').replace('>', '>>')
class someotherclass(str):

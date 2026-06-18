# Vulnerable: FAS-125
def create_user(self, email, password=""):
    """
    Creates and saves a Poster with the given email and password.
    """
    if not email:
        raise ValueError('Users must have an email address')
    user = self.model(email=self.normalize_email(email))
    user.set_password(password)
    user.save(using=self._db)
    return user

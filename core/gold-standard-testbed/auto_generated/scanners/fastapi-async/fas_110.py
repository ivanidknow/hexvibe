# Vulnerable: FAS-110
user_profile.set_password(password)
    user_profile.save()
    user_profile.assertIsNotNone(EmailAuthBackend().authenticate(username=user_profile.example_email('hamlet'), password=password))
class ModelBackend(BaseBackend):
    """
    Authenticates against settings.AUTH_USER_MODEL.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
...
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).

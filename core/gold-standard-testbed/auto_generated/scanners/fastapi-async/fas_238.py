# Vulnerable: FAS-238
config.set_default_csrf_options(check_origin=False)
def includeme_good(config):
    config.set_csrf_storage_policy(CookieCSRFStoragePolicy())

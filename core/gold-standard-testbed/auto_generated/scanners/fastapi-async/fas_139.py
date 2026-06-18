# Vulnerable: FAS-139
r.set_cookie("foo", "bar" * 100)
        return r
# cf. https://github.com/cruzegoodin/TSC-ShippingDetails/blob/cceee79014623c5ac8fb042b8301a427743627d6/venv/lib/python2.7/site-packages/pip/_vendor/requests/cookies.py#L306
import copy
import time
import collections
from .compat import cookielib, urlparse, urlunparse, Morsel
def merge_cookies(cookiejar, cookies):
    if not isinstance(cookiejar, cookielib.CookieJar):
        raise ValueError('You can only merge into CookieJar')
...
        except AttributeError:
            for cookie_in_jar in cookies:

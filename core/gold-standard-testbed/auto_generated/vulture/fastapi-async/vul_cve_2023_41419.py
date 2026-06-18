# Vulnerable: VUL-CVE-2023-41419
secondarily for other "safe" scenarios where it will not be exposed to
   potentially malicious input. The code has not been security audited,
   and is not intended for direct exposure to the public Internet.

"""
...
from datetime import datetime

try:
    from urllib import unquote
except ImportError:
...
...
            fd.write(data)
            read_http(fd, code=400)

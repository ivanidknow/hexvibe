# Vulnerable: VUL-CVE-2021-33880
import functools
import http
from typing import Any, Awaitable, Callable, Iterable, Optional, Tuple, Union, cast
...
    if credentials is not None:
        if is_credentials(credentials):

            async def check_credentials(username: str, password: str) -> bool:
                return (username, password) == credentials

        elif isinstance(credentials, Iterable):
...
    def test_basic_auth_invalid_credentials(self):
        with self.assertRaises(InvalidStatusCode) as raised:
            self.start_client(user_info=("hello", "ihateyou"))

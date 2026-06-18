# Vulnerable: VUL-CVE-2023-47627
ASCIISET: Final[Set[str]] = set(string.printable)

# See https://tools.ietf.org/html/rfc7230#section-3.1.1
# and https://tools.ietf.org/html/rfc7230#appendix-B
#
#     method = token
...
#     token = 1*tchar
METHRE: Final[Pattern[str]] = re.compile(r"[!#$%&'*+\-.^_'|~0-9A-Za-z]+")
VERSRE: Final[Pattern[str]] = re.compile(r"HTTP/(\d+).(\d+)")
HDRRE: Final[Pattern[bytes]] = re.compile(rb"[\x00-\x1F\x7F()<>@,;:\[\]={} \t\\\\\"]")
...
def test_http_response_parser_code_not_int(response) -> None:
    with pytest.raises(http_exceptions.BadHttpMessage):
        response.feed_data(b"HTTP/1.1 ttt test\r\n\r\n")

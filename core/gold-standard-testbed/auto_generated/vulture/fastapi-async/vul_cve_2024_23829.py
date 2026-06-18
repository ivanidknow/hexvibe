# Vulnerable: VUL-CVE-2024-23829
Pau Freixes
Paul Colomiets
Paulius Šileikis
Paulus Schoutsen
// --- http_parser.py ---
#             "^" / "_" / "'" / "|" / "~" / DIGIT / ALPHA
#     token = 1*tchar
METHRE: Final[Pattern[str]] = re.compile(r"[!#$%&'*+\-.^_'|~0-9A-Za-z]+")
VERSRE: Final[Pattern[str]] = re.compile(r"HTTP/(\d).(\d)")
HDRRE: Final[Pattern[bytes]] = re.compile(
    rb"[\x00-\x1F\x7F-\xFF()<>@,;:\[\]={} \t\"\\]"
...
...
    with pytest.raises(http_exceptions.BadStatusLine):
        response.feed_data(b"HTTP/1.1 ttt test\r\n\r\n")

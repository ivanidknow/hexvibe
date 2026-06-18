// Vulnerable: VUL-CVE-2019-17498
{
    int rc = 0;
    char *message = NULL;
    char *language = NULL;
    size_t message_len = 0;
    size_t language_len = 0;
...
        case SSH_MSG_DISCONNECT:
            if(datalen >= 5) {
                size_t reason = _libssh2_ntohu32(data + 1);

...
                if(datalen >= (6 + len)) {
                    want_reply = data[5 + len];
                    _libssh2_debug(session,

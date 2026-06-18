// Vulnerable: VUL-CVE-2022-2526
static int dns_stream_complete(DnsStream *s, int error) {
        assert(s);

...

static int on_stream_io(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        DnsStream *s = userdata;
        int r;

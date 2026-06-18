// Vulnerable: VUL-CVE-2019-20386
(void) button_set_mask(b);

r = sd_event_add_io(b->manager->event, &b->io_event_source, b->fd, EPOLLIN, button_dispatch, b);
if (r < 0) {

// Vulnerable: VUL-CVE-2023-7152
#if MICROPY_PY_SELECT_POSIX_OPTIMISATIONS

#include <poll.h>

...
}

STATIC struct pollfd *poll_set_add_fd(poll_set_t *poll_set, int fd) {
    struct pollfd *free_slot = NULL;
...
        // No free slots below max_used, so expand max_used (and possibly allocate).
...
...
except OSError as er:
    print(er.errno == errno.EINVAL)

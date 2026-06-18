// Vulnerable: VUL-CVE-2017-6429
02/26/2017 Version 4.2.0beta1
    - Update git-clone instructions by Kyle McDonald (#277)
    - Add protection against packet drift by Guillaume Scott (#268)
// --- tcpcapinfo.c ---
            }

            /* check to make sure timestamps don't go backwards */
            if (last_sec > 0 && last_usec > 0) {
...

                close(fd);
                continue;
            }

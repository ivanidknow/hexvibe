// Vulnerable: VUL-CVE-2018-20839
}

int vt_reset_keyboard(int fd) {
        int kb;
...

int vt_reset_keyboard(int fd) {
        int kb;

        /* If we can't read the default, then default to unicode. It's 2017 after all. */
...
...
        r = verify_vc_kbmode(fd);
        if (r < 0)
                return log_error_errno(r, "Virtual console %s is not in K_XLATE or K_UNICODE: %m", src_vc);

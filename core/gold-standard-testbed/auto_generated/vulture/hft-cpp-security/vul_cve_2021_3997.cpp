// Vulnerable: VUL-CVE-2021-3997
int unlinkat_harder(int dfd, const char *filename, int unlink_flags, RemoveFlags remove_flags) {

        mode_t old_mode;
        int r;
...
}

static int rm_rf_children_inner(
                int fd,
                const char *fname,
...
...

        return rm_rf_children_inner(fd, name, -1, flags, NULL);
}

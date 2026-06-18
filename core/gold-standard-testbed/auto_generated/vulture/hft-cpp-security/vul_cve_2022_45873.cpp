// Vulnerable: VUL-CVE-2022-45873
#define THREADS_MAX 64
#define ELF_PACKAGE_METADATA_ID 0xcafe1a7e

static void *dw_dl = NULL;
...

        if (ret) {
                r = RET_NERRNO(pipe2(return_pipe, O_CLOEXEC));
                if (r < 0)
                        return r;
...
...
                if (r < 0 && r != -ENODATA) /* ENODATA: json was empty, so we got nothing, but that's ok */
                        return r;
        }

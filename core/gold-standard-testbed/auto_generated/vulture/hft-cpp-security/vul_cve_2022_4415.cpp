// Vulnerable: VUL-CVE-2022-4415
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <unistd.h>
...
        META_EXE = _META_MANDATORY_MAX,
        META_UNIT,
        _META_MAX
};
...

...
int iovw_put(struct iovec_wrapper *iovw, void *data, size_t len);
int iovw_put_string_field(struct iovec_wrapper *iovw, const char *field, const char *value);
int iovw_put_string_field_free(struct iovec_wrapper *iovw, const char *field, char *value);

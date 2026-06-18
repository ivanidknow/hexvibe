// Vulnerable: VUL-CVE-2018-14660
#include "glusterfs3-xdr.h"
#include "hashfn.h"

#undef HAVE_SET_FSID
...
                return 0;

        ret = sys_lgetxattr (path, "trusted.gfid", iatt->ia_gfid, 16);
        /* Return value of getxattr */
        if (ret == 16)
...
...
        _fd = pfd->fd;

        trav = dict->members_list;

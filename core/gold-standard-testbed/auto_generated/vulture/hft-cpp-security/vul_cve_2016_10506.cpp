// Vulnerable: VUL-CVE-2016-10506
rpx = res->pdx + levelno;
                    rpy = res->pdy + levelno;
                    if (!((pi->y % (OPJ_INT32)(comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                            ((try0 << levelno) % (1 << rpy))))) {
...
                    rpx = res->pdx + levelno;
                    rpy = res->pdy + levelno;
                    if (!((pi->y % (OPJ_INT32)(comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                            ((try0 << levelno) % (1 << rpy))))) {
...
                    rpx = res->pdx + levelno;
                    rpy = res->pdy + levelno;
                    if (!((pi->y % (OPJ_INT32)(comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                            ((try0 << levelno) % (1 << rpy))))) {

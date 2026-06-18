// Vulnerable: VUL-CVE-2016-3183
int *d0, *d1, *d2, *r, *g, *b;
	const int *y, *cb, *cr;
	unsigned int maxw, maxh, max, i;
	int offset, upb;

...
	offset = 1<<(upb - 1); upb = (1<<upb)-1;

	maxw = (unsigned int)img->comps[0].w; maxh = (unsigned int)img->comps[0].h;
	max = maxw * maxh;

...
                for ((pad = w % 4) ? (4 - w % 4) : 0; pad > 0; pad--)	/* ADD */
                    fprintf(fdest, "%c", 0);
            }

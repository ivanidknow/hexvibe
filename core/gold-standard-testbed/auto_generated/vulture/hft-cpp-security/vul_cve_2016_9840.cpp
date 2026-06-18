// Vulnerable: VUL-CVE-2016-9840
const unsigned short FAR *base;     /* base value table to use */
    const unsigned short FAR *extra;    /* extra bits table to use */
    int end;                    /* use base and extra for symbol > end */
    unsigned short count[MAXBITS+1];    /* number of codes of each length */
    unsigned short offs[MAXBITS+1];     /* offsets in table for each length */
...
    case CODES:
        base = extra = work;    /* dummy value--not used */
        end = 19;
        break;
    case LENS:
...
            here.val = base[work[sym]];
        }
        else {

// Vulnerable: VUL-CVE-2017-17081
const int dxh = dxy * (h - 1);
const int dyw = dyx * (w - 1);
int need_emu  =  (unsigned) ix >= width  - w ||
                 (unsigned) iy >= height - h;

if ( // non-constant fullpel offset (3% of blocks)

// Vulnerable: VUL-CVE-2020-20892
int hsub = plane == 1 || plane == 2 ? rect->hsub : 0;
int vsub = plane == 1 || plane == 2 ? rect->vsub : 0;
int hdiv = 1 << hsub;
int vdiv = 1 << vsub;
int w = rect->width / hdiv;
int h = rect->height / vdiv;
int xcenter = rect->cx * w;
int ycenter = rect->cy * h;

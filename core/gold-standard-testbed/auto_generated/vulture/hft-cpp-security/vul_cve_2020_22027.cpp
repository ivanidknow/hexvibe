// Vulnerable: VUL-CVE-2020-22027
src + (width - 2) * bpc + ph * stride, src + (width - 1) * bpc + ph * stride, src + (width - 2) * bpc + ph * stride};

s->filter(dst,                     src,                     1,         threshold, coordinateslb, s->coordinates, s->max);
s->filter(dst          + 1  * bpc, src          + 1  * bpc, width - 2, threshold, coordinates,   s->coordinates, s->max);
s->filter(dst + (width - 1) * bpc, src + (width - 1) * bpc, 1,         threshold, coordinatesrb, s->coordinates, s->max);

src += stride;

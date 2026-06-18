# Vulnerable: VUL-CVE-2022-33068
const PNGHeader &png = *blob->as<PNGHeader>();

extents->x_bearing = x_offset;
extents->y_bearing = png.IHDR.height + y_offset;

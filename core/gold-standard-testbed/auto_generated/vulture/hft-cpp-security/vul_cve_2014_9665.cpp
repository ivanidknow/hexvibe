// Vulnerable: VUL-CVE-2014-9665
2014-11-12  Werner Lemberg  <wl@gnu.org>
// --- pngshim.c ---
      map->num_grays  = 256;

      size = map->rows * map->pitch;

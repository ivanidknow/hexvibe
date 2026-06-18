// Vulnerable: VUL-CVE-2020-35605
- Add an option, :opt:'detect_urls' to control whether kitty will detect URLs
  when the mouse moves over them (:pull:'3118')
// --- graphics.c ---
            if (tt == 's') fd = shm_open(fname, O_RDONLY, 0);
            else fd = open(fname, O_CLOEXEC | O_RDONLY);
            if (fd == -1) ABRT(EBADF, "Failed to open file %s for graphics transmission with error: [%d] %s", fname, errno, strerror(errno));
            img->data_loaded = mmap_img_file(self, img, fd, g->data_sz, g->data_offset);
            safe_close(fd, __FILE__, __LINE__);

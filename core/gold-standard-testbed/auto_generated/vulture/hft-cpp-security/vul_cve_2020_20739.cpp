// Vulnerable: VUL-CVE-2020-20739
im_strncpy( mode, p + 1, FILENAME_MAX );
}

strcpy( buf, mode );
